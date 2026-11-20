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
