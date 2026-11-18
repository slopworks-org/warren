package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

type memoryTun struct {
	read, written chan []byte
	done          chan struct{}
}

func memory() *memoryTun {
	return &memoryTun{make(chan []byte, 8), make(chan []byte, 8), make(chan struct{})}
}

func (*memoryTun) File() *os.File           { return nil }
func (*memoryTun) MTU() (int, error)        { return mtu, nil }
func (*memoryTun) Name() (string, error)    { return "test", nil }
func (*memoryTun) BatchSize() int           { return 1 }
func (*memoryTun) Events() <-chan tun.Event { return nil }
func (m *memoryTun) Close() error {
	close(m.done)
	return nil
}

func (m *memoryTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-m.read:
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-m.done:
		return 0, net.ErrClosed
	}
}

func (m *memoryTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		select {
		case m.written <- append([]byte(nil), buf[offset:]...):
		case <-m.done:
			return i, net.ErrClosed
		}
	}
	return len(bufs), nil
}

func keys(t *testing.T) (secret, public string) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", k.Bytes()), fmt.Sprintf("%x", k.PublicKey().Bytes())
}

func listen(t *testing.T, dev *device.Device) string {
	t.Helper()
	conf, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(conf, "\n") {
		if port, ok := strings.CutPrefix(line, "listen_port="); ok && port != "0" {
			return "127.0.0.1:" + port
		}
	}
	t.Fatal("missing listen port")
	return ""
}

func uapi(secret, public, endpoint, address string) string {
	return fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nendpoint=%s\nallowed_ip=%s\n",
		secret, public, endpoint, address)
}

func requireOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func ipPacket(src, dst uint32, marker byte) []byte {
	packet := make([]byte, 21)
	packet[0], packet[3], packet[8], packet[9] = 0x45, 21, 64, 253
	binary.BigEndian.PutUint32(packet[12:], src)
	binary.BigEndian.PutUint32(packet[16:], dst)
	packet[20] = marker
	return packet
}

func expectPacket(t *testing.T, input <-chan []byte, marker byte) {
	t.Helper()
	select {
	case packet := <-input:
		if len(packet) != 21 || packet[20] != marker {
			t.Fatal("received the wrong packet")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("packet never reached its destination")
	}
}

func await(t *testing.T, max time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(max)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatal("path did not change before deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

type lanRelay struct {
	endpoint string
	blocked  atomic.Uint32
	dropped  [2]atomic.Uint64
}

func relayLAN(t *testing.T, a, b string) *lanRelay {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	requireOK(t, err)
	relay := &lanRelay{endpoint: socket.LocalAddr().String()}
	peers := [2]netip.AddrPort{netip.MustParseAddrPort(a), netip.MustParseAddrPort(b)}
	done := make(chan struct{})
	t.Cleanup(func() {
		requireOK(t, socket.Close())
		<-done
	})
	go func() {
		defer close(done)
		var buf [2048]byte
		for {
			n, src, err := socket.ReadFromUDPAddrPort(buf[:])
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
				return
			}
			for from, peer := range peers {
				if src != peer {
					continue
				}
				if relay.blocked.Load()&(1<<from) != 0 {
					relay.dropped[from].Add(1)
				} else if _, err := socket.WriteToUDPAddrPort(buf[:n], peers[1-from]); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
			}
		}
	}()
	return relay
}

type labPeer struct {
	engine *engine
	tun    *memoryTun
	ip     uint32
	ipText string
	config string
}

type nativeLab struct {
	elapsed atomic.Int64
	peers   [2]labPeer
	relay   *lanRelay
	hubTun  *memoryTun
	hubPort *packetPort
}

const testAuthorizationTTL = 12 * time.Second

func newNativeLab(t *testing.T) *nativeLab {
	t.Helper()
	lab := &nativeLab{
		peers:  [2]labPeer{{ip: 0x0a4d0002, ipText: "10.77.0.2"}, {ip: 0x0a4d0003, ipText: "10.77.0.3"}},
		hubTun: memory(),
	}
	lab.elapsed.Store(int64(time.Second))
	lab.hubPort = newPort(lab.hubTun)
	lab.hubPort.fromPeer = func([]byte) bool { return true }
	hub := device.NewDevice(lab.hubPort, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
	t.Cleanup(hub.Close)
	requireOK(t, hub.Up())
	hubSecret, hubPublic := keys(t)
	hubConfig := fmt.Sprintf("private_key=%s\n", hubSecret)
	var secrets, publics [2]string
	for i := range lab.peers {
		p := &lab.peers[i]
		p.tun = memory()
		var err error
		p.engine, err = newEngine(p.tun, p.ip, 0x0a4d0001, 7180, func() time.Duration { return time.Duration(lab.elapsed.Load()) })
		requireOK(t, err)
		p.engine.setForwarding(true)
		t.Cleanup(p.engine.close)
		secrets[i], publics[i] = keys(t)
		requireOK(t, p.engine.hub.IpcSet(uapi(secrets[i], hubPublic, listen(t, hub), "10.77.0.0/16")))
		hubConfig += fmt.Sprintf("public_key=%s\nendpoint=%s\nallowed_ip=%s/32\n", publics[i], listen(t, p.engine.hub), p.ipText)
	}
	requireOK(t, hub.IpcSet(hubConfig))
	lab.relay = relayLAN(t, listen(t, lab.peers[0].engine.lan), listen(t, lab.peers[1].engine.lan))
	for i := range lab.peers {
		remote := lab.peers[1-i]
		lab.peers[i].config = uapi(secrets[i], publics[1-i], lab.relay.endpoint, remote.ipText+"/32") +
			fmt.Sprintf("allowed_ip=fd77:6172:7265:6e00::%x:%x/128\n", remote.ip>>16, remote.ip&0xffff)
	}
	return lab
}

func (lab *nativeLab) renewLAN(t *testing.T) {
	t.Helper()
	deadline := time.Duration(lab.elapsed.Load()) + testAuthorizationTTL
	for i, peer := range lab.peers {
		requireOK(t, peer.engine.configureLAN(peer.config, lab.peers[1-i].ipText, deadline))
	}
}

func (lab *nativeLab) proveLAN(t *testing.T) {
	t.Helper()
	for i := range lab.peers {
		lab.proveFrom(t, i)
	}
}

func (lab *nativeLab) proveFrom(t *testing.T, from int) {
	t.Helper()
	peer, remote := lab.peers[from], lab.peers[1-from]
	proofExpires := time.Duration(lab.elapsed.Load()) + probeTTL
	peer.engine.sendProbes()
	await(t, 10*time.Second, func() bool {
		peer.engine.mu.Lock()
		defer peer.engine.mu.Unlock()
		return peer.engine.peers[remote.ip].probe.provedUntil == proofExpires
	})
}

func (lab *nativeLab) send(t *testing.T, from int, marker byte, toHub bool) {
	t.Helper()
	src, dst := lab.peers[from], lab.peers[1-from]
	src.tun.read <- ipPacket(src.ip, dst.ip, marker)
	written := dst.tun.written
	if toHub {
		written = lab.hubTun.written
	}
	expectPacket(t, written, marker)
}

func (lab *nativeLab) rejectLAN(t *testing.T, to int) {
	t.Helper()
	src, dst := lab.peers[1-to], lab.peers[to]
	_, err := dst.engine.lanPort.Write([][]byte{ipPacket(src.ip, dst.ip, 255)}, 0)
	requireOK(t, err)
	select {
	case <-dst.tun.written:
		t.Fatal("ineligible LAN packet reached the TUN")
	default:
	}
}

func TestEncryptedLANAndHubRemainIndependent(t *testing.T) {
	lab := newNativeLab(t)
	lab.send(t, 0, 1, true)
	lab.send(t, 1, 2, true)

	lab.renewLAN(t)
	lab.proveLAN(t)
	for from, peer := range lab.peers {
		lab.send(t, from, 3, false)
		lab.hubPort.enqueue(ipPacket(lab.peers[1-from].ip, peer.ip, 4))
		expectPacket(t, peer.tun.written, 4)
	}

	// Each orientation keeps a working one-way UDP path but cannot produce
	// a round trip. In both cases control continues to renew the same lease.
	for from, peer := range lab.peers {
		lab.relay.blocked.Store(1 << from)
		dropped := lab.relay.dropped[from].Load()
		peer.engine.sendProbes()
		await(t, 5*time.Second, func() bool { return lab.relay.dropped[from].Load() > dropped })
		lab.send(t, 1-from, 5, false)
		for range 4 {
			lab.elapsed.Add(int64(3 * time.Second))
			lab.renewLAN(t)
		}
		for i, peer := range lab.peers {
			if peer.engine.paths() != "" {
				t.Fatal("one-way LAN remained selected with a renewed control lease")
			}
			lab.send(t, i, 6, true)
		}
		lab.relay.blocked.Store(0)
		lab.proveLAN(t)
		lab.send(t, 0, 7, false)
		lab.send(t, 1, 8, false)
	}
}

func TestEncryptedLANIngressWithStaggeredOutboundProofs(t *testing.T) {
	lab := newNativeLab(t)
	lab.renewLAN(t)
	lab.proveFrom(t, 1)
	lab.elapsed.Add(int64(probeTTL / 2))
	lab.proveFrom(t, 0)
	lab.relay.blocked.Store(1 << 1)
	lab.elapsed.Add(int64(probeTTL / 2))
	a, b := lab.peers[0], lab.peers[1]
	for _, peer := range lab.peers {
		peer.engine.mu.Lock()
		live := peer.engine.authorized(peer.engine.elapsed())
		peer.engine.mu.Unlock()
		if !live {
			t.Fatal("both control leases must be live")
		}
	}
	if a.engine.paths() != b.ipText || b.engine.paths() != "" {
		t.Fatal("expected fresh outbound proof only on A")
	}
	dropped := lab.relay.dropped[1].Load()
	b.engine.sendProbes()
	await(t, 5*time.Second, func() bool { return lab.relay.dropped[1].Load() > dropped })
	lab.send(t, 0, 1, false)
	lab.send(t, 1, 2, true)
	lab.hubPort.enqueue(ipPacket(b.ip, a.ip, 2))
	expectPacket(t, a.tun.written, 2)
	if b.engine.receiveLAN(ipPacket(a.ip+32, b.ip, 3)) || b.engine.receiveLAN(ipPacket(a.ip, b.ip+32, 3)) {
		t.Fatal("LAN accepted an unauthorized source or nonlocal destination")
	}
	requireOK(t, b.engine.configureLAN("replace_peers=true\n", "", 0))
	lab.rejectLAN(t, 1)
}

func TestSuspendExpiresLANAuthorizationAndProof(t *testing.T) {
	lab := newNativeLab(t)
	lab.renewLAN(t)
	lab.proveLAN(t)
	lab.send(t, 0, 1, false)
	lab.send(t, 1, 2, false)

	lab.relay.blocked.Store(3)
	a, b := lab.peers[0], lab.peers[1]
	a.engine.sendProbes()
	a.engine.mu.Lock()
	oldNonce := a.engine.peers[b.ip].probe.nonce
	a.engine.mu.Unlock()
	oldResponse := probePacket(b.ip, a.ip, 2, oldNonce[:])

	// Only the injected elapsed clock advances, as CLOCK_BOOTTIME does
	// while Go's scheduler and monotonic timers are paused in suspend.
	lab.elapsed.Add(int64(testAuthorizationTTL))
	a.engine.receiveLAN(oldResponse)
	lab.rejectLAN(t, 0)
	lab.send(t, 0, 3, true)

	lab.renewLAN(t)
	a.engine.receiveLAN(oldResponse)
	a.engine.receiveLAN(probePacket(b.ip, a.ip, 1, oldNonce[:]))
	lab.send(t, 0, 4, true)

	lab.relay.blocked.Store(0)
	lab.proveLAN(t)
	lab.send(t, 0, 5, false)
	lab.send(t, 1, 6, false)
}

func TestDelayedPollCannotAuthorizeLAN(t *testing.T) {
	for _, name := range []string{"initial", "unchanged"} {
		t.Run(name, func(t *testing.T) {
			lab := newNativeLab(t)
			a, b := lab.peers[0], lab.peers[1]
			if name == "unchanged" {
				lab.renewLAN(t)
				lab.proveLAN(t)
				lab.elapsed.Add(int64(time.Second))
			}
			request := time.Duration(lab.elapsed.Load())
			deadline := request + testAuthorizationTTL
			// The hub responded after a normal five-second poll. Simulate suspend
			// after that observation and resume at the request's exact deadline.
			lab.elapsed.Add(int64(5 * time.Second))
			lab.elapsed.Store(int64(deadline))
			requireOK(t, a.engine.configureLAN(a.config, b.ipText, deadline))
			lab.rejectLAN(t, 0)
			if a.engine.paths() != "" {
				t.Fatal("the delayed reply reauthorized a direct path")
			}
			lab.send(t, 0, 1, true)

			// A timely renewal may authorize ingress, but it must not reuse old
			// outbound proof or extend the lease from the time of installation.
			freshDeadline := time.Duration(lab.elapsed.Load()) + testAuthorizationTTL
			lab.elapsed.Add(int64(5 * time.Second))
			requireOK(t, a.engine.configureLAN(a.config, b.ipText, freshDeadline))
			a.engine.mu.Lock()
			lease := a.engine.lease
			a.engine.mu.Unlock()
			if lease != freshDeadline || !a.engine.receiveLAN(ipPacket(b.ip, a.ip, 2)) {
				t.Fatal("timely reply did not install the request-bounded ingress lease")
			}
			lab.send(t, 0, 3, true)
			requireOK(t, b.engine.configureLAN(b.config, a.ipText, freshDeadline))
			lab.proveFrom(t, 0)
			lab.send(t, 0, 4, false)
			lab.elapsed.Store(int64(freshDeadline))
			lab.rejectLAN(t, 0)
			lab.send(t, 0, 5, true)
		})
	}
}

func TestQueuedLANPacketFallsBackWhenProofExpires(t *testing.T) {
	lab := newNativeLab(t)
	lab.renewLAN(t)
	lab.proveFrom(t, 0)
	a, b := lab.peers[0], lab.peers[1]
	port := newPort(a.tun)
	defer port.Close()
	port.toPeer = a.engine.transmitLAN
	port.enqueue(ipPacket(a.ip, b.ip, 1))
	lab.elapsed.Add(int64(probeTTL))
	// The fresh lease still permits probes while the queued data must go via hub.
	port.enqueue(probePacket(a.ip, b.ip, 1, make([]byte, 16)))
	bufs, sizes := [][]byte{make([]byte, mtu)}, []int{0}
	_, err := port.Read(bufs, sizes, 0)
	requireOK(t, err)
	if sizes[0] != probeSize {
		t.Fatal("queued data reached the LAN WireGuard device with expired proof")
	}
	expectPacket(t, lab.hubTun.written, 1)
}

func TestDeniedForwardingLeavesOnlyHubControlAndDiscardsOldLANLease(t *testing.T) {
	lab := newNativeLab(t)
	lab.renewLAN(t)
	lab.proveFrom(t, 0)
	a, b := lab.peers[0], lab.peers[1]
	control := a.engine.control
	tcp := func(src, dst uint32, sourcePort, destinationPort uint16) []byte {
		packet := append(ipPacket(src, dst, 0)[:20], make([]byte, 20)...)
		packet[3], packet[9], packet[32] = 40, 6, 0x50
		binary.BigEndian.PutUint16(packet[20:], sourcePort)
		binary.BigEndian.PutUint16(packet[22:], destinationPort)
		return packet
	}
	request := tcp(a.ip, control, 40000, a.engine.controlPort)
	reply := tcp(control, a.ip, a.engine.controlPort, 40000)
	data := ipPacket(a.ip, b.ip, 1)

	// Recheck at the device queue when forwarding is withdrawn.
	port := newPort(a.tun)
	defer port.Close()
	port.toPeer = a.engine.transmitHub
	port.enqueue(data)
	a.engine.setForwarding(false)
	port.enqueue(request)
	bufs, sizes := [][]byte{make([]byte, mtu)}, []int{0}
	_, err := port.Read(bufs, sizes, 0)
	requireOK(t, err)
	if sizes[0] != len(request) || !a.engine.receiveHub(reply) {
		t.Fatal("control TCP could not pass the forwarding gate")
	}
	if a.engine.receiveHub(tcp(control, a.ip, 22, 40000)) ||
		a.engine.receiveHub(ipPacket(b.ip, a.ip, 2)) ||
		a.engine.transmitHub(tcp(a.ip, control, 40000, 22)) ||
		a.engine.transmitHub(tcp(a.ip, b.ip, 40000, a.engine.controlPort)) ||
		a.engine.transmitLAN(data) {
		t.Fatal("disabled tunnel accepted non-control traffic")
	}
	request[6] = 0x20 // more fragments
	if a.engine.transmitHub(request) {
		t.Fatal("fragmented packet bypassed the control gate")
	}
	lab.rejectLAN(t, 0)

	a.engine.setForwarding(true)
	lab.rejectLAN(t, 0)
	lab.send(t, 0, 3, true)
}
