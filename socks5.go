package hopsock

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 wire constants (RFC 1928 / RFC 1929).
const (
	socksVersion = 0x05

	methodNoAuth       = 0x00
	methodUserPass     = 0x02
	methodNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess            = 0x00
	repGeneralFailure     = 0x01
	repNotAllowed         = 0x02
	repNetworkUnreachable = 0x03
	repHostUnreachable    = 0x04
	repConnRefused        = 0x05
	repTTLExpired         = 0x06
	repCmdNotSupported    = 0x07
	repAddrNotSupported   = 0x08
)

var replyText = map[byte]string{
	repGeneralFailure:     "general failure",
	repNotAllowed:         "connection not allowed by ruleset",
	repNetworkUnreachable: "network unreachable",
	repHostUnreachable:    "host unreachable",
	repConnRefused:        "connection refused",
	repTTLExpired:         "TTL expired",
	repCmdNotSupported:    "command not supported",
	repAddrNotSupported:   "address type not supported",
}

// appendAddr encodes "host:port" as ATYP + ADDR + PORT.
func appendAddr(b []byte, addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("bad port %q", portStr)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			b = append(b, atypIPv4)
			b = append(b, ip4...)
		} else {
			b = append(b, atypIPv6)
			b = append(b, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, errors.New("hostname too long")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// readAddr reads ATYP + ADDR + PORT and returns "host:port".
func readAddr(r io.Reader) (string, byte, error) {
	var atyp [1]byte
	if _, err := io.ReadFull(r, atyp[:]); err != nil {
		return "", 0, err
	}
	var host string
	switch atyp[0] {
	case atypIPv4, atypIPv6:
		n := 4
		if atyp[0] == atypIPv6 {
			n = 16
		}
		ip := make(net.IP, n)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		host = ip.String()
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return "", 0, err
		}
		name := make([]byte, l[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return "", 0, err
		}
		host = string(name)
	default:
		return "", atyp[0], fmt.Errorf("unknown address type %d", atyp[0])
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return "", 0, err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), atyp[0], nil
}

// SOCKS5Dialer connects through an upstream SOCKS5 proxy.
type SOCKS5Dialer struct {
	Addr     string // proxy "host:port"
	Username string
	Password string
	Forward  Dialer // how to reach the proxy; nil means Direct

	// Ask, if set, is called when the proxy wants credentials that weren't
	// given or rejects the ones it got. What it returns is kept for later dials.
	Ask CredentialsFunc

	creds credStore
}

// ResetPrompt lets Ask be called again after it was declined.
func (d *SOCKS5Dialer) ResetPrompt() { d.creds.reset() }

func (d *SOCKS5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := checkTCP(network); err != nil {
		return nil, err
	}
	base := CredRequest{Hop: "socks5://" + d.Addr, Scheme: "socks5", Addr: d.Addr}
	return dialWithPrompt(ctx, &d.creds, d.Ask, base, d.Username, d.Password,
		func(user, pass string) (net.Conn, bool, error) { return d.dial(ctx, addr, user, pass) })
}

func (d *SOCKS5Dialer) dial(ctx context.Context, addr, user, pass string) (net.Conn, bool, error) {
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	conn, err := fwd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, false, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	done := guardHandshake(ctx, conn)
	err = socks5Handshake(conn, addr, user, pass)
	done()
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("socks5 %s: %w", d.Addr, err)
	}
	return conn, true, nil
}

func socks5Handshake(conn net.Conn, target, user, pass string) error {
	// Greeting: offer no-auth, plus user/pass if we have credentials.
	greet := []byte{socksVersion, 1, methodNoAuth}
	if user != "" {
		greet = []byte{socksVersion, 2, methodNoAuth, methodUserPass}
	}
	if _, err := conn.Write(greet); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return fmt.Errorf("reading method: %w", err)
	}
	if sel[0] != socksVersion {
		return fmt.Errorf("not a SOCKS5 server (version byte %d)", sel[0])
	}
	switch sel[1] {
	case methodNoAuth:
	case methodUserPass:
		if user == "" {
			return ErrAuthRequired
		}
		if len(user) > 255 || len(pass) > 255 {
			return errors.New("username or password longer than 255 bytes")
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		req = append(req, byte(len(pass)))
		req = append(req, pass...)
		if _, err := conn.Write(req); err != nil {
			return err
		}
		var res [2]byte
		if _, err := io.ReadFull(conn, res[:]); err != nil {
			return fmt.Errorf("reading auth reply: %w", err)
		}
		if res[1] != 0x00 {
			return ErrAuthFailed
		}
	case methodNoAcceptable:
		if user == "" {
			// We only offered no-auth, so the proxy wants credentials.
			return ErrAuthRequired
		}
		return errors.New("proxy accepted none of our auth methods")
	default:
		return fmt.Errorf("proxy picked unsupported auth method %d", sel[1])
	}

	req := []byte{socksVersion, cmdConnect, 0x00}
	req, err := appendAddr(req, target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fmt.Errorf("reading connect reply: %w", err)
	}
	if head[1] != repSuccess {
		msg := replyText[head[1]]
		if msg == "" {
			msg = fmt.Sprintf("reply code %d", head[1])
		}
		return fmt.Errorf("connect %s: %s", target, msg)
	}
	if _, _, err := readAddr(conn); err != nil { // bound address, unused
		return fmt.Errorf("reading bound addr: %w", err)
	}
	return nil
}
