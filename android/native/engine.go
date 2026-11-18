package main

import (
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// A LAN entry is installed exclusively from the hub's live control config.
type lanPeer struct {
	address netip.Addr
	probe   probe
}

type engine struct {
	tun              tun.Device
	hubPort, lanPort *packetPort
	hub, lan         *device.Device
	local            uint32
	control          uint32
	controlPort      uint16
	elapsed          func() time.Duration
	mu               sync.Mutex
	forwarding       bool
	peers            map[uint32]*lanPeer
	lease            time.Duration
	lanConfig        string
	shutdown         chan struct{}
	work             sync.WaitGroup
}

func newEngine(in tun.Device, local, control uint32, port uint16, elapsed func() time.Duration) (*engine, error) {
	e := &engine{
		tun: in, local: local, control: control, controlPort: port, elapsed: elapsed, shutdown: make(chan struct{}),
		hubPort: newPort(in), lanPort: newPort(in),
	}
	e.hubPort.fromPeer = e.receiveHub
	e.hubPort.toPeer = e.transmitHub
	e.lanPort.fromPeer = e.receiveLAN
	e.lanPort.toPeer = e.transmitLAN
	makeDevice := func(port *packetPort) *device.Device {
		dev := device.NewDevice(port, conn.NewStdNetBind(), device.NewLogger(device.LogLevelSilent, ""))
		dev.DisableSomeRoamingForBrokenMobileSemantics()
		return dev
	}
	e.hub, e.lan = makeDevice(e.hubPort), makeDevice(e.lanPort)
	if err := e.hub.Up(); err != nil {
		e.close()
		return nil, err
	}
	if err := e.lan.Up(); err != nil {
		e.close()
		return nil, err
	}
	e.work.Add(1)
	go e.dispatch()
	return e, nil
}

func (e *engine) setForwarding(enabled bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forwarding = enabled
	if !enabled {
		e.lease = 0
	}
}

func (e *engine) receiveHub(packet []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return ipv4(packet, 16) == e.local &&
		(e.forwarding || controlTCP(packet, 12, 0, e.control, e.controlPort))
}

func (e *engine) transmitHub(packet []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.forwarding || controlTCP(packet, 16, 2, e.control, e.controlPort)
}

// During bootstrap only unfragmented IPv4 TCP to/from the control listener
// can cross the hub path, including packets queued before a denial.
func controlTCP(packet []byte, addrOffset, portOffset int, ip uint32, port uint16) bool {
	if ipv4(packet, addrOffset) != ip || len(packet) < 20 || packet[9] != 6 ||
		binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
		return false
	}
	header := int(packet[0]&0x0f) * 4
	return header >= 20 && len(packet) >= header+20 &&
		binary.BigEndian.Uint16(packet[header+portOffset:]) == port
}

func (e *engine) close() {
	close(e.shutdown)
	e.tun.Close()
	e.work.Wait()
	e.hub.Close()
	e.lan.Close()
}

func (e *engine) dispatch() {
	defer e.work.Done()
	buf := make([]byte, mtu+64)
	packets, sizes := [][]byte{buf}, []int{0}
	for {
		n, err := e.tun.Read(packets, sizes, 0)
		if err != nil {
			return
		}
		if n != 1 || ipv4(buf[:sizes[0]], 12) != e.local {
			continue
		}
		packet := append([]byte(nil), buf[:sizes[0]]...)
		e.mu.Lock()
		if e.direct(ipv4(packet, 16), e.elapsed()) {
			e.lanPort.enqueue(packet)
		} else if e.forwarding || controlTCP(packet, 16, 2, e.control, e.controlPort) {
			e.hubPort.enqueue(packet)
		}
		e.mu.Unlock()
	}
}

func (e *engine) authorized(now time.Duration) bool {
	return e.forwarding && beforeDeadline(now, e.lease)
}

func beforeDeadline(now, deadline time.Duration) bool { return now > 0 && now < deadline }

func (e *engine) direct(ip uint32, now time.Duration) bool {
	p := e.peers[ip]
	return p != nil && e.authorized(now) && now < p.probe.provedUntil
}

func (e *engine) transmitLAN(packet []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.elapsed()
	if dst := ipv4(packet, 16); dst != 0 {
		if e.direct(dst, now) {
			return true
		}
		// The packet may have waited in the queue across suspend or revocation.
		if e.forwarding {
			e.hubPort.enqueue(packet)
		}
		return false
	}
	// The only IPv6 packets enqueued on this port are internal probes.
	return len(packet) == probeSize && e.authorized(now) && e.peers[binary.BigEndian.Uint32(packet[36:])] != nil
}

func (e *engine) receiveLAN(packet []byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.elapsed()
	if !e.authorized(now) {
		return false
	}
	// WireGuard checked the decrypted packet against its peer's allowed IPs.
	// Our own round-trip proof only controls where we send traffic.
	if ipv4(packet, 16) == e.local && e.peers[ipv4(packet, 12)] != nil {
		return true
	}
	if validProbe(packet, e.local) {
		src := binary.BigEndian.Uint32(packet[20:])
		if p := e.peers[src]; p != nil {
			switch packet[48] {
			case 1:
				e.lanPort.enqueue(probePacket(e.local, src, 2, packet[49:]))
			case 2:
				p.probe.response(now, packet[49:])
			}
		}
	}
	return false
}

func (e *engine) probeLAN() {
	defer e.work.Done()
	// Separate the first probe among simultaneously starting clients,
	// which could otherwise send competing WireGuard initiations.
	ticker := time.NewTimer(500*time.Millisecond + rand.N(1500*time.Millisecond))
	defer ticker.Stop()
	for {
		select {
		case <-e.shutdown:
			return
		case <-ticker.C:
			ticker.Reset(2 * time.Second)
			e.sendProbes()
		}
	}
}

func (e *engine) sendProbes() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.elapsed()
	if !e.authorized(now) {
		return
	}
	for ip, p := range e.peers {
		nonce := p.probe.challenge(now)
		e.lanPort.enqueue(probePacket(e.local, ip, 1, nonce[:]))
	}
}

// Keep packet authorization closed during replacement. IpcSet can wait on a
// peer's receive goroutine, so it must run without the packet path lock.
func (e *engine) configureLAN(config, addresses string, deadline time.Duration) error {
	e.mu.Lock()
	now := e.elapsed()
	if deadline != 0 && !beforeDeadline(now, deadline) {
		e.lease = 0
		e.mu.Unlock()
		return nil
	}
	if deadline != 0 && config == e.lanConfig && e.authorized(now) {
		e.lease = deadline
		e.mu.Unlock()
		return nil
	}
	e.peers = nil
	e.lease = 0
	e.lanConfig = ""
	e.mu.Unlock()

	if err := e.lan.IpcSet(config); err != nil {
		return err
	}
	peers := make(map[uint32]*lanPeer)
	for _, text := range strings.Fields(addresses) {
		ip, err := netip.ParseAddr(text)
		if err != nil || !ip.Is4() {
			continue
		}
		raw := ip.As4()
		peers[binary.BigEndian.Uint32(raw[:])] = &lanPeer{address: ip}
	}
	e.mu.Lock()
	if beforeDeadline(e.elapsed(), deadline) {
		e.peers = peers
		e.lease = deadline
	}
	e.lanConfig = config
	e.mu.Unlock()
	return nil
}

func (e *engine) paths() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	var list []string
	now := e.elapsed()
	for ip, p := range e.peers {
		if e.direct(ip, now) {
			list = append(list, p.address.String())
		}
	}
	return strings.Join(list, "\n")
}

func main() {}
