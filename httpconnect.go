package hopsock

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
)

// HTTPDialer connects through an upstream HTTP proxy using CONNECT.
type HTTPDialer struct {
	Addr     string
	Username string
	Password string
	Forward  Dialer // how to reach the proxy; nil means Direct

	// Ask, if set, is called on a 407 when credentials weren't given or were
	// rejected. What it returns is kept for later dials.
	Ask CredentialsFunc

	creds credStore
}

// ResetPrompt lets Ask be called again after it was declined.
func (d *HTTPDialer) ResetPrompt() { d.creds.reset() }

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := checkTCP(network); err != nil {
		return nil, err
	}
	base := CredRequest{Hop: "http://" + d.Addr, Scheme: "http", Addr: d.Addr}
	return dialWithPrompt(ctx, &d.creds, d.Ask, base, d.Username, d.Password,
		func(user, pass string) (net.Conn, bool, error) { return d.dial(ctx, addr, user, pass) })
}

func (d *HTTPDialer) dial(ctx context.Context, addr, user, pass string) (net.Conn, bool, error) {
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	conn, err := fwd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, false, fmt.Errorf("http %s: %w", d.Addr, err)
	}
	done := guardHandshake(ctx, conn)
	out, err := httpConnect(conn, addr, user, pass)
	done()
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}
		return nil, true, fmt.Errorf("http %s: %w", d.Addr, err)
	}
	return out, true, nil
}

func httpConnect(conn net.Conn, target, user, pass string) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if user != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Proxy-Authorization", "Basic "+cred)
	}
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, fmt.Errorf("reading CONNECT reply: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode == http.StatusProxyAuthRequired {
		if user == "" {
			return nil, fmt.Errorf("CONNECT %s: %s: %w", target, resp.Status, ErrAuthRequired)
		}
		return nil, fmt.Errorf("CONNECT %s: %s: %w", target, resp.Status, ErrAuthFailed)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CONNECT %s: %s", target, resp.Status)
	}
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, r: br}, nil
	}
	return conn, nil
}

// bufferedConn returns bytes the bufio.Reader already pulled off the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }
