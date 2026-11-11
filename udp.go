package hopsock

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PacketConn sends and receives datagrams to and from any "host:port".
// Hostnames are passed through unresolved where the transport allows it, so
// a SOCKS5 hop resolves them at the far end, like socks5h.
type PacketConn interface {
	WriteTo(b []byte, addr string) (int, error)
	ReadFrom(b []byte) (n int, addr string, err error)
	SetReadDeadline(t time.Time) error
	Close() error
}

// PacketDialer opens a PacketConn. The direct dialer and SOCKS5 hops (via
// UDP ASSOCIATE) implement it; HTTP CONNECT and SSH hops can't carry UDP.
type PacketDialer interface {
	DialPacket(ctx context.Context) (PacketConn, error)
}

// ErrUDPNotSupported is returned when some hop in the path can't carry UDP.
var ErrUDPNotSupported = errors.New("udp not supported")

// DirectPacket sends datagrams without any proxy.
var DirectPacket PacketDialer = directPacketDialer{}

type directPacketDialer struct{}

func (directPacketDialer) DialPacket(context.Context) (PacketConn, error) {
	c, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &udpPacketConn{c: c, resolved: make(map[string]netip.AddrPort)}, nil
}

// packetDialerFor returns how to send UDP the same way d sends TCP.
func packetDialerFor(d Dialer) (PacketDialer, error) {
	switch d := d.(type) {
	case nil, *net.Dialer:
		return DirectPacket, nil
	case PacketDialer:
		return d, nil
	}
	return nil, fmt.Errorf("%w through %T (tcp only)", ErrUDPNotSupported, d)
}

// maxResolved bounds the per-conn DNS cache of udpPacketConn.
const maxResolved = 256

// udpPacketConn is a plain UDP socket that resolves hostnames itself.
type udpPacketConn struct {
	c *net.UDPConn

	mu       sync.Mutex
	resolved map[string]netip.AddrPort
}

func (u *udpPacketConn) WriteTo(b []byte, addr string) (int, error) {
	ap, err := u.resolve(addr)
	if err != nil {
		return 0, err
	}
	return u.c.WriteToUDPAddrPort(b, ap)
}

func (u *udpPacketConn) resolve(addr string) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(addr); err == nil {
		return ap, nil
	}
	u.mu.Lock()
	ap, ok := u.resolved[addr]
	u.mu.Unlock()
	if ok {
		return ap, nil
	}
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	ap = ua.AddrPort()
	ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	u.mu.Lock()
	if len(u.resolved) >= maxResolved {
		clear(u.resolved)
	}
	u.resolved[addr] = ap
	u.mu.Unlock()
	return ap, nil
}

// maxReadErrs is how many read errors in a row an unconnected UDP socket
// tolerates. Windows reports ICMP port unreachable as a read error on the
// next ReadFrom; that's noise for a relay, not a reason to stop.
const maxReadErrs = 32

func (u *udpPacketConn) ReadFrom(b []byte) (int, string, error) {
	errs := 0
	for {
		n, ap, err := u.c.ReadFromUDPAddrPort(b)
		if err == nil {
			return n, netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()).String(), nil
		}
		var ne net.Error
		if errors.Is(err, net.ErrClosed) || (errors.As(err, &ne) && ne.Timeout()) {
			return 0, "", err
		}
		if errs++; errs >= maxReadErrs {
			return 0, "", err
		}
	}
}

func (u *udpPacketConn) SetReadDeadline(t time.Time) error { return u.c.SetReadDeadline(t) }
func (u *udpPacketConn) Close() error                      { return u.c.Close() }

// DialPacket sets up a UDP ASSOCIATE with the proxy. The association lasts
// until the returned conn is closed or the proxy drops the control
// connection. Datagrams reach the proxy's relay the same way TCP reaches the
// proxy, so the hops before this one must carry UDP too.
func (d *SOCKS5Dialer) DialPacket(ctx context.Context) (PacketConn, error) {
	base := CredRequest{Hop: "socks5://" + d.Addr, Scheme: "socks5", Addr: d.Addr}
	return dialWithPrompt(ctx, &d.creds, d.Ask, base, d.Username, d.Password,
		func(user, pass string) (PacketConn, bool, error) { return d.dialPacket(ctx, user, pass) })
}

func (d *SOCKS5Dialer) dialPacket(ctx context.Context, user, pass string) (PacketConn, bool, error) {
	pd, err := packetDialerFor(d.Forward)
	if err != nil {
		return nil, false, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	ctrl, err := fwd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, false, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	done := guardHandshake(ctx, ctrl)
	bound, err := socks5Associate(ctrl, user, pass)
	done()
	if err != nil {
		ctrl.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	inner, err := pd.DialPacket(ctx)
	if err != nil {
		ctrl.Close()
		return nil, false, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	pc := &socks5PacketConn{ctrl: ctrl, inner: inner, relay: relayAddr(bound, d.Addr)}
	go pc.watch()
	return pc, true, nil
}

func socks5Associate(conn net.Conn, user, pass string) (string, error) {
	if err := socks5Auth(conn, user, pass); err != nil {
		return "", err
	}
	// We don't know which address our datagrams will come from (they may
	// pass through other hops first), so send zeros as RFC 1928 allows.
	return socks5Request(conn, cmdUDPAssociate, "0.0.0.0:0")
}

// relayAddr picks where to send datagrams. Many proxies answer UDP
// ASSOCIATE with 0.0.0.0, or with an address only valid on their own
// machine; use the proxy's host with the relay port then.
func relayAddr(bound, proxy string) string {
	bh, bp, err := net.SplitHostPort(bound)
	if err != nil {
		return bound
	}
	ph, _, err := net.SplitHostPort(proxy)
	if err != nil {
		return bound
	}
	ip, err := netip.ParseAddr(bh)
	if err != nil {
		return bound // a hostname; trust it
	}
	if ip.IsUnspecified() {
		return net.JoinHostPort(ph, bp)
	}
	if ip.IsLoopback() {
		if pip, err := netip.ParseAddr(ph); err != nil || !pip.IsLoopback() {
			return net.JoinHostPort(ph, bp)
		}
	}
	return bound
}

// socks5PacketConn wraps datagrams in the SOCKS5 UDP header and sends them
// to the proxy's relay through inner.
type socks5PacketConn struct {
	ctrl  net.Conn
	inner PacketConn
	relay string

	rmu  sync.Mutex
	rbuf []byte

	closeOnce sync.Once
	closeErr  error
}

// maxDatagram is the largest UDP payload plus room for a SOCKS5 header.
const maxDatagram = 64*1024 + 262

func (c *socks5PacketConn) WriteTo(b []byte, addr string) (int, error) {
	pkt, err := appendUDPHeader(make([]byte, 0, len(b)+22), addr)
	if err != nil {
		return 0, err
	}
	pkt = append(pkt, b...)
	if _, err := c.inner.WriteTo(pkt, c.relay); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *socks5PacketConn) ReadFrom(b []byte) (int, string, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if c.rbuf == nil {
		c.rbuf = make([]byte, maxDatagram)
	}
	for {
		n, _, err := c.inner.ReadFrom(c.rbuf)
		if err != nil {
			return 0, "", err
		}
		payload, src, frag, err := parseUDPHeader(c.rbuf[:n])
		if err != nil || frag != 0 {
			continue // malformed or fragmented: drop, like most servers
		}
		return copy(b, payload), src, nil
	}
}

func (c *socks5PacketConn) SetReadDeadline(t time.Time) error { return c.inner.SetReadDeadline(t) }

func (c *socks5PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeErr = errors.Join(c.ctrl.Close(), c.inner.Close())
	})
	return c.closeErr
}

// watch ends the association when the proxy closes the control connection.
func (c *socks5PacketConn) watch() {
	_, _ = io.Copy(io.Discard, c.ctrl)
	c.Close()
}

// appendUDPHeader appends RSV RSV FRAG ATYP ADDR PORT (RFC 1928 section 7).
func appendUDPHeader(b []byte, addr string) ([]byte, error) {
	return appendAddr(append(b, 0, 0, 0), addr)
}

// parseUDPHeader splits a SOCKS5 UDP datagram into payload and address.
func parseUDPHeader(p []byte) (payload []byte, addr string, frag byte, err error) {
	if len(p) < 4 {
		return nil, "", 0, errors.New("short udp datagram")
	}
	if p[0] != 0 || p[1] != 0 {
		return nil, "", 0, errors.New("bad udp header")
	}
	r := bytes.NewReader(p[3:])
	addr, _, err = readAddr(r)
	if err != nil {
		return nil, "", 0, err
	}
	return p[len(p)-r.Len():], addr, p[2], nil
}

// DialPacket opens a UDP path through the chain. Every hop must be SOCKS5
// with UDP ASSOCIATE; an empty chain sends directly.
func (c *Chain) DialPacket(ctx context.Context) (PacketConn, error) {
	if c == nil || len(c.Hops) == 0 {
		return DirectPacket.DialPacket(ctx)
	}
	if ok, blocker := c.UDPSupport(); !ok {
		return nil, fmt.Errorf("%w: %s carries tcp only", ErrUDPNotSupported, blocker)
	}
	return c.Hops[len(c.Hops)-1].Dialer.(PacketDialer).DialPacket(ctx)
}

// UDPSupport reports whether every hop can carry UDP. If not, blocker is the
// label of the first hop that can't. Whether a SOCKS5 proxy really allows
// UDP ASSOCIATE is only known when it's tried.
func (c *Chain) UDPSupport() (ok bool, blocker string) {
	if c == nil {
		return true, ""
	}
	for _, h := range c.Hops {
		if _, ok := h.Dialer.(PacketDialer); !ok {
			return false, h.Label
		}
	}
	return true, ""
}
