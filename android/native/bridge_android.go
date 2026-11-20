package main

// #include <stdint.h>
// #include <stdlib.h>
import "C"

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

// The VPN service serializes these calls. Only WireGuard's device and packet
// path workers access the engine concurrently.
var tunnel *engine

//export warrenKeyPair
func warrenKeyPair() *C.char {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil
	}
	return C.CString(hex.EncodeToString(key.Bytes()) + hex.EncodeToString(key.PublicKey().Bytes()))
}

// CLOCK_BOOTTIME advances during device suspend. An unavailable clock must
// leave the LAN path closed.
func elapsedRealtime() time.Duration {
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_BOOTTIME, &now) != nil {
		return 0
	}
	return time.Duration(now.Nano())
}

//export warrenOpen
func warrenOpen(fd C.int, local, control C.uint32_t, port C.uint16_t) C.int {
	if tunnel != nil {
		unix.Close(int(fd))
		return 0
	}
	in, _, err := tun.CreateUnmonitoredTUNFromFD(int(fd))
	if err != nil {
		unix.Close(int(fd))
		return 0
	}
	tunnel, err = newEngine(in, uint32(local), uint32(control), uint16(port), elapsedRealtime)
	if err != nil {
		return 0
	}
	tunnel.work.Add(1)
	go tunnel.probeLAN()
	return 1
}

//export warrenSetForwarding
func warrenSetForwarding(enabled C.int) {
	if tunnel != nil {
		tunnel.setForwarding(enabled != 0)
	}
}

//export warrenSocket
func warrenSocket(mesh, ipv6 C.int) C.int {
	if tunnel == nil {
		return -1
	}
	dev := tunnel.hub
	if mesh != 0 {
		dev = tunnel.lan
	}
	bind := dev.Bind().(conn.PeekLookAtSocketFd)
	fd, err := bind.PeekLookAtSocketFd4()
	if ipv6 != 0 {
		fd, err = bind.PeekLookAtSocketFd6()
	}
	if err != nil {
		return -1
	}
	return C.int(fd)
}

//export warrenLanPort
func warrenLanPort() C.int {
	if tunnel != nil {
		config, err := tunnel.lan.IpcGet()
		if err == nil {
			for _, line := range strings.Split(config, "\n") {
				if port, ok := strings.CutPrefix(line, "listen_port="); ok {
					n, _ := strconv.Atoi(port)
					return C.int(n)
				}
			}
		}
	}
	return 0
}

//export warrenSetHub
func warrenSetHub(config *C.char) C.int {
	if tunnel == nil || tunnel.hub.IpcSet(C.GoString(config)) != nil {
		return 0
	}
	return 1
}

//export warrenSetLAN
func warrenSetLAN(config, ips *C.char, deadline C.int64_t) C.int {
	if tunnel == nil || tunnel.configureLAN(C.GoString(config), C.GoString(ips), time.Duration(deadline)) != nil {
		return 0
	}
	return 1
}

//export warrenDirectPaths
func warrenDirectPaths() *C.char {
	if tunnel == nil {
		return C.CString("")
	}
	return C.CString(tunnel.paths())
}

//export warrenClose
func warrenClose() {
	if tunnel != nil {
		tunnel.close()
		tunnel = nil
	}
}
