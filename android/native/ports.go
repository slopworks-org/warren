package main

import (
	"encoding/binary"
	"net"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

const mtu = 1420

type packetPort struct {
	tun      tun.Device
	incoming chan []byte
	done     chan struct{}
	events   chan tun.Event
	once     sync.Once
	fromPeer func([]byte) bool
	toPeer   func([]byte) bool
}

func newPort(input tun.Device) *packetPort {
	return &packetPort{tun: input, incoming: make(chan []byte, 256), done: make(chan struct{}), events: make(chan tun.Event)}
}

func (p *packetPort) File() *os.File           { return nil }
func (p *packetPort) MTU() (int, error)        { return mtu, nil }
func (p *packetPort) Name() (string, error)    { return "warren", nil }
func (p *packetPort) BatchSize() int           { return 1 }
func (p *packetPort) Events() <-chan tun.Event { return p.events }
func (p *packetPort) Close() error {
	p.once.Do(func() { close(p.done); close(p.events) })
	return nil
}

// WireGuard runs a separate reader for each logical device.
func (p *packetPort) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	for {
		select {
		case <-p.done:
			return 0, net.ErrClosed
		case packet := <-p.incoming:
			if p.toPeer != nil && !p.toPeer(packet) {
				continue
			}
			sizes[0] = copy(bufs[0][offset:], packet)
			return 1, nil
		}
	}
}

func (p *packetPort) Write(bufs [][]byte, offset int) (int, error) {
	for i, buf := range bufs {
		if p.fromPeer(buf[offset:]) {
			if _, err := p.tun.Write(bufs[i:i+1], offset); err != nil {
				return i, err
			}
		}
	}
	return len(bufs), nil
}

func (p *packetPort) enqueue(packet []byte) {
	select {
	case p.incoming <- packet:
	default:
		// Never let backpressure from one path stop the other.
	}
}

func ipv4(packet []byte, start int) uint32 {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet[start : start+4])
}
