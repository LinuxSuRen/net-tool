package cmd

import (
	"net"
	"strconv"
	"testing"
)

func listenOn(t *testing.T, addr string) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("listen %s: %v", addr, err)
	}
	return l
}

func portOf(t *testing.T, l net.Listener) int {
	t.Helper()
	tcp, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("not a TCP listener: %T", l.Addr())
	}
	return tcp.Port
}

func TestIsAddrInUse(t *testing.T) {
	occupied := listenOn(t, "127.0.0.1:0")
	defer occupied.Close()
	_, err := net.Listen("tcp", occupied.Addr().String())
	if err == nil {
		t.Fatal("second listen on an occupied port should fail")
	}
	if !isAddrInUse(err) {
		t.Errorf("port conflict not detected as EADDRINUSE: %v", err)
	}
}

func TestListenWithPortDrift(t *testing.T) {
	first := listenOn(t, "127.0.0.1:0")
	defer first.Close()
	port := portOf(t, first)
	next := net.JoinHostPort("127.0.0.1", strconv.Itoa(port+1))
	second, err := net.Listen("tcp", next)
	if err != nil {
		t.Skipf("cannot reserve %s for the test: %v", next, err)
	}
	defer second.Close()

	l, requested, err := listenWithPortDrift(first.Addr().String(), 5)
	if err != nil {
		t.Fatalf("drift listen: %v", err)
	}
	defer l.Close()
	if requested != strconv.Itoa(port) {
		t.Errorf("requested port = %q, want %d", requested, port)
	}
	if got := portOf(t, l); got != port+2 {
		t.Errorf("bound port = %d, want %d", got, port+2)
	}
}

func TestListenWithPortDriftDisabled(t *testing.T) {
	occupied := listenOn(t, "127.0.0.1:0")
	defer occupied.Close()
	if _, _, err := listenWithPortDrift(occupied.Addr().String(), 0); err == nil {
		t.Fatal("zero drift attempts should report the conflict")
	}
}

func TestListenWithPortDriftBadAddr(t *testing.T) {
	if _, _, err := listenWithPortDrift("127.0.0.1", 5); err == nil {
		t.Error("address without a port should fail")
	}
	if _, _, err := listenWithPortDrift("127.0.0.1:notaport", 5); err == nil {
		t.Error("non-numeric port should fail")
	}
}
