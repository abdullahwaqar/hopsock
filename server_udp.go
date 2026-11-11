package hopsock

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// handleUDP serves one UDP ASSOCIATE. The client sends SOCKS5-wrapped
// datagrams to a relay socket we open; we unwrap them and send them out
// through the Dialer's PacketConn, and wrap the replies on the way back.
// The association lives as long as the TCP control connection.
func (s *Server) handleUDP(ctx context.Context, conn net.Conn) {
	client := conn.RemoteAddr().String()

	pd, err := packetDialerFor(s.Dialer)
	if s.DisableUDP {
		err = errors.New("disabled on this server")
	}
	if err != nil {
		s.Log.logf(LevelWarn, "%s: udp associate refused: %v", client, err)
		_, _ = conn.Write(reply(repCmdNotSupported))
		return
	}

	// Open the relay on the address the client reached us on, so a server
	// listening on loopback doesn't expose UDP to the network.
	local := addrPortOf(conn.LocalAddr())
	relay, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(local.Addr(), 0)))
	if err != nil {
		s.Log.logf(LevelError, "%s: udp relay: %v", client, err)
		_, _ = conn.Write(reply(repGeneralFailure))
		return
	}
	defer relay.Close()

	timeout := s.DialTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	start := time.Now()
	up, err := pd.DialPacket(dctx)
	cancel()
	if err != nil {
		s.Stats.fail()
		s.Log.logf(LevelError, "%s -> udp: %v", client, err)
		code := dialErrCode(err)
		if errors.Is(err, ErrUDPNotSupported) {
			code = repCmdNotSupported
		}
		_, _ = conn.Write(reply(code))
		return
	}
	defer up.Close()

	bound := netip.AddrPortFrom(local.Addr(), uint16(relay.LocalAddr().(*net.UDPAddr).Port))
	if _, err := conn.Write(replyBound(repSuccess, bound)); err != nil {
		return
	}

	ci := s.Stats.open(client, "udp relay")
	defer s.Stats.close(ci)
	s.Log.logf(LevelDebug, "%s -> udp relay %s ready in %s", client, bound, time.Since(start).Round(time.Millisecond))

	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			conn.Close()
			relay.Close()
			up.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeAll)
	defer stop()

	u := &udpAssoc{
		s:        s,
		client:   client,
		clientIP: addrPortOf(conn.RemoteAddr()).Addr(),
		relay:    relay,
		up:       up,
		ci:       ci,
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); defer closeAll(); _, _ = io.Copy(io.Discard, conn) }()
	go func() { defer wg.Done(); defer closeAll(); u.clientToUp() }()
	go func() { defer wg.Done(); defer closeAll(); u.upToClient() }()
	wg.Wait()

	s.Log.logf(LevelDebug, "%s -> udp relay closed after %s (up %d, down %d)", client,
		time.Since(ci.Start).Round(time.Millisecond), ci.Up.Load(), ci.Down.Load())
}

type udpAssoc struct {
	s        *Server
	client   string
	clientIP netip.Addr
	relay    *net.UDPConn
	up       PacketConn
	ci       *ConnInfo

	// peer is the client's UDP address, learned from its first datagram.
	// Later datagrams from anywhere else are dropped.
	peer atomic.Pointer[netip.AddrPort]
}

func (u *udpAssoc) clientToUp() {
	buf := make([]byte, maxDatagram)
	errs := 0
	for {
		n, from, err := u.relay.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if errs++; errs >= maxReadErrs {
				return
			}
			continue
		}
		errs = 0
		from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
		if from.Addr() != u.clientIP {
			u.s.Log.logf(LevelDebug, "%s: udp from stranger %s dropped", u.client, from)
			continue
		}
		if p := u.peer.Load(); p == nil {
			u.peer.CompareAndSwap(nil, &from)
		}
		if *u.peer.Load() != from {
			continue
		}
		payload, dst, frag, err := parseUDPHeader(buf[:n])
		if err != nil || frag != 0 {
			continue // we don't reassemble fragments; drop them like most servers
		}
		if _, err := u.up.WriteTo(payload, dst); err != nil {
			u.s.Log.logf(LevelDebug, "%s -> udp %s: %v", u.client, dst, err)
			continue
		}
		u.ci.Up.Add(int64(len(payload)))
	}
}

func (u *udpAssoc) upToClient() {
	buf := make([]byte, maxDatagram)
	for {
		n, src, err := u.up.ReadFrom(buf)
		if err != nil {
			return
		}
		p := u.peer.Load()
		if p == nil {
			continue // the client hasn't sent anything yet, so we can't answer
		}
		pkt, err := appendUDPHeader(make([]byte, 0, n+22), src)
		if err != nil {
			continue
		}
		pkt = append(pkt, buf[:n]...)
		if _, err := u.relay.WriteToUDPAddrPort(pkt, *p); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		u.ci.Down.Add(int64(n))
	}
}

// replyBound builds a reply carrying a bound address.
func replyBound(code byte, ap netip.AddrPort) []byte {
	b := []byte{socksVersion, code, 0x00}
	if a := ap.Addr().Unmap(); a.Is4() {
		b = append(b, atypIPv4)
		b = append(b, a.AsSlice()...)
	} else {
		b = append(b, atypIPv6)
		b = append(b, a.AsSlice()...)
	}
	return binary.BigEndian.AppendUint16(b, ap.Port())
}

// addrPortOf converts a TCP or UDP net.Addr, unmapping IPv4-in-IPv6.
func addrPortOf(a net.Addr) netip.AddrPort {
	var ap netip.AddrPort
	switch a := a.(type) {
	case *net.TCPAddr:
		ap = a.AddrPort()
	case *net.UDPAddr:
		ap = a.AddrPort()
	default:
		ap, _ = netip.ParseAddrPort(a.String())
	}
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}
