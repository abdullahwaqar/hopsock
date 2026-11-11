package hopsock

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

// udpEcho echoes datagrams back to their sender.
func udpEcho(t *testing.T) string {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, from, err := c.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			_, _ = c.WriteToUDPAddrPort(buf[:n], from)
		}
	}()
	return c.LocalAddr().String()
}

// echoRoundTrip sends msg to target through pc and checks the echo.
func echoRoundTrip(t *testing.T, pc PacketConn, target, msg string) {
	t.Helper()
	if _, err := pc.WriteTo([]byte(msg), target); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64*1024)
	n, from, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if got := string(buf[:n]); got != msg {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
	if from != target {
		t.Fatalf("from = %q, want %q", from, target)
	}
}

func TestUDPAssociateDirect(t *testing.T) {
	echo := udpEcho(t)
	stats := &Stats{}
	proxy := socksServer(t, &Server{Stats: stats})

	pc, err := (&SOCKS5Dialer{Addr: proxy}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	for _, msg := range []string{"hello", "second datagram", string(bytes.Repeat([]byte("x"), 1400))} {
		echoRoundTrip(t, pc, echo, msg)
	}
	if got := len(stats.Snapshot().Active); got != 1 {
		t.Fatalf("active = %d, want 1 udp relay", got)
	}
}

func TestUDPAssociateHostname(t *testing.T) {
	echo := udpEcho(t)
	_, port, _ := net.SplitHostPort(echo)
	proxy := socksServer(t, &Server{})

	pc, err := (&SOCKS5Dialer{Addr: proxy}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	// The name is resolved by the server, socks5h style; replies come back
	// from the resolved address.
	if _, err := pc.WriteTo([]byte("ping"), net.JoinHostPort("localhost", port)); err != nil {
		t.Fatal(err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 100)
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("echo = %q", buf[:n])
	}
}

func TestUDPAssociateThroughChain(t *testing.T) {
	echo := udpEcho(t)
	exit := socksServer(t, &Server{Username: "u", Password: "p"})
	middle := socksServer(t, &Server{})

	chain, err := NewChain([]string{
		"socks5://" + middle,
		"socks5://u:p@" + exit,
	}, &ChainOptions{SSHConfig: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, blocker := chain.UDPSupport(); !ok {
		t.Fatalf("UDPSupport = false (%s)", blocker)
	}
	// A local server on top: client -> local -> middle -> exit -> echo.
	local := socksServer(t, &Server{Dialer: chain})

	pc, err := (&SOCKS5Dialer{Addr: local}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	echoRoundTrip(t, pc, echo, "through three proxies")
	echoRoundTrip(t, pc, echo, "and again")
}

func TestUDPAssociateBadCredentials(t *testing.T) {
	proxy := socksServer(t, &Server{Username: "u", Password: "p"})
	_, err := (&SOCKS5Dialer{Addr: proxy, Username: "u", Password: "wrong"}).DialPacket(context.Background())
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("err = %v, want ErrAuthFailed", err)
	}
}

func TestUDPAssociateRefusedOverTCPOnlyHop(t *testing.T) {
	chain, err := NewChain([]string{"http://127.0.0.1:1"}, &ChainOptions{SSHConfig: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := chain.UDPSupport(); ok {
		t.Fatal("UDPSupport = true for an http hop")
	}
	if _, err := chain.DialPacket(context.Background()); !errors.Is(err, ErrUDPNotSupported) {
		t.Fatalf("chain err = %v, want ErrUDPNotSupported", err)
	}

	// A SOCKS5 hop reached through an HTTP hop can't relay UDP either.
	chain2, err := NewChain([]string{"http://127.0.0.1:1", "socks5://127.0.0.1:2"}, &ChainOptions{SSHConfig: "none"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := chain2.DialPacket(context.Background()); !errors.Is(err, ErrUDPNotSupported) {
		t.Fatalf("chain2 err = %v, want ErrUDPNotSupported", err)
	}

	proxy := socksServer(t, &Server{Dialer: chain})
	_, err = (&SOCKS5Dialer{Addr: proxy}).DialPacket(context.Background())
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("command not supported")) {
		t.Fatalf("err = %v, want command not supported", err)
	}
}

func TestUDPAssociateDisabled(t *testing.T) {
	proxy := socksServer(t, &Server{DisableUDP: true})
	_, err := (&SOCKS5Dialer{Addr: proxy}).DialPacket(context.Background())
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("command not supported")) {
		t.Fatalf("err = %v, want command not supported", err)
	}
}

func TestUDPAssociateEndsWithControlConn(t *testing.T) {
	stats := &Stats{}
	proxy := socksServer(t, &Server{Stats: stats})
	pc, err := (&SOCKS5Dialer{Addr: proxy}).DialPacket(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pc.Close()
	deadline := time.Now().Add(5 * time.Second)
	for len(stats.Snapshot().Active) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("udp relay still open after the control connection closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestUDPRelayDropsStrangers(t *testing.T) {
	echo := udpEcho(t)
	proxy := socksServer(t, &Server{})

	// Raw handshake so we can see the relay address.
	ctrl, err := net.Dial("tcp", proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	bound, err := socks5Associate(ctrl, "", "")
	if err != nil {
		t.Fatal(err)
	}
	relay, err := net.ResolveUDPAddr("udp", bound)
	if err != nil {
		t.Fatal(err)
	}
	mine, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer mine.Close()
	other, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer other.Close()

	send := func(c *net.UDPConn, msg string) {
		pkt, _ := appendUDPHeader(nil, echo)
		_, _ = c.WriteToUDP(append(pkt, msg...), relay)
	}
	send(mine, "first") // locks the association to mine's port
	buf := make([]byte, 1024)
	_ = mine.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, _, err := mine.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	if p, _, _, _ := parseUDPHeader(buf[:n]); string(p) != "first" {
		t.Fatalf("got %q", p)
	}

	send(other, "intruder")
	_ = other.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := other.ReadFromUDP(buf); err == nil {
		t.Fatal("relay answered a second source port")
	}
}

func TestUDPHeaderRoundTrip(t *testing.T) {
	for _, addr := range []string{"1.2.3.4:53", "[2001:db8::1]:443", "example.com:3478"} {
		pkt, err := appendUDPHeader(nil, addr)
		if err != nil {
			t.Fatal(err)
		}
		pkt = append(pkt, "data"...)
		p, got, frag, err := parseUDPHeader(pkt)
		if err != nil || got != addr || frag != 0 || string(p) != "data" {
			t.Fatalf("%s: got %q %q frag=%d err=%v", addr, p, got, frag, err)
		}
	}
	if _, _, _, err := parseUDPHeader([]byte{0, 0}); err == nil {
		t.Fatal("short header accepted")
	}
	if _, _, _, err := parseUDPHeader([]byte{1, 0, 0, atypIPv4, 1, 2, 3, 4, 0, 53}); err == nil {
		t.Fatal("nonzero RSV accepted")
	}
}

func TestRelayAddr(t *testing.T) {
	cases := []struct{ bound, proxy, want string }{
		{"0.0.0.0:5000", "proxy.example.com:1080", "proxy.example.com:5000"},
		{"127.0.0.1:5000", "203.0.113.9:1080", "203.0.113.9:5000"},
		{"127.0.0.1:5000", "127.0.0.1:1080", "127.0.0.1:5000"},
		{"198.51.100.7:5000", "203.0.113.9:1080", "198.51.100.7:5000"},
		{"[::]:5000", "203.0.113.9:1080", "203.0.113.9:5000"},
	}
	for _, c := range cases {
		if got := relayAddr(c.bound, c.proxy); got != c.want {
			t.Errorf("relayAddr(%q, %q) = %q, want %q", c.bound, c.proxy, got, c.want)
		}
	}
}

func TestReplyBound(t *testing.T) {
	r := replyBound(repSuccess, netip.MustParseAddrPort("127.0.0.1:4242"))
	addr, _, err := readAddr(bytes.NewReader(r[3:]))
	if err != nil || addr != "127.0.0.1:4242" {
		t.Fatalf("got %q, %v", addr, err)
	}
}
