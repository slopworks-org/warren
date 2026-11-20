package main

import (
	"crypto/rand"
	"encoding/binary"
	"slices"
	"time"
)

const (
	probePort = 51821
	probeUDP  = 8 + 17
	probeSize = 40 + probeUDP
	probeTTL  = 8 * time.Second
)

var probePrefix = []byte{0xfd, 0x77, 0x61, 0x72, 0x72, 0x65, 0x6e, 0, 0, 0, 0, 0}

type probe struct {
	nonce        [16]byte
	pendingUntil time.Duration
	provedUntil  time.Duration
}

func (p *probe) challenge(now time.Duration) [16]byte {
	if now >= p.pendingUntil {
		rand.Read(p.nonce[:])
		p.pendingUntil = now + probeTTL
	}
	return p.nonce
}

func (p *probe) response(now time.Duration, nonce []byte) {
	if now < p.pendingUntil && slices.Equal(nonce, p.nonce[:]) {
		p.provedUntil = now + probeTTL
		p.pendingUntil = 0
	}
}

func probePacket(src, dst uint32, kind byte, nonce []byte) []byte {
	packet := make([]byte, probeSize)
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:], probeUDP)
	copy(packet[8:], probePrefix)
	binary.BigEndian.PutUint32(packet[20:], src)
	copy(packet[24:], probePrefix)
	binary.BigEndian.PutUint32(packet[36:], dst)
	binary.BigEndian.PutUint16(packet[40:], probePort)
	binary.BigEndian.PutUint16(packet[42:], probePort)
	binary.BigEndian.PutUint16(packet[44:], probeUDP)
	packet[48] = kind
	copy(packet[49:], nonce)
	checksum := udpChecksum(packet)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(packet[46:], checksum)
	return packet
}

func validProbe(packet []byte, dst uint32) bool {
	return len(packet) == probeSize && packet[0]>>4 == 6 && packet[6] == 17 &&
		binary.BigEndian.Uint16(packet[4:]) == probeUDP &&
		slices.Equal(packet[8:20], probePrefix) && slices.Equal(packet[24:36], probePrefix) &&
		binary.BigEndian.Uint32(packet[36:]) == dst &&
		binary.BigEndian.Uint16(packet[40:]) == probePort &&
		binary.BigEndian.Uint16(packet[42:]) == probePort &&
		binary.BigEndian.Uint16(packet[44:]) == probeUDP &&
		binary.BigEndian.Uint16(packet[46:]) != 0 && udpChecksum(packet) == 0
}

func udpChecksum(packet []byte) uint16 {
	// UDP's IPv6 pseudo-header consists of both addresses, length and protocol.
	sum := uint32(probeUDP + 17)
	for _, part := range [][]byte{packet[8:40], packet[40:]} {
		for len(part) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(part))
			part = part[2:]
		}
		if len(part) != 0 {
			sum += uint32(part[0]) << 8
		}
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
