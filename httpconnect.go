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
}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := checkTCP(network); err != nil {
		return nil, err
	}
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	conn, err := fwd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		return nil, fmt.Errorf("http %s: %w", d.Addr, err)
	}
	done := guardHandshake(ctx, conn)
	out, err := d.connect(conn, addr)
	done()
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("http %s: %w", d.Addr, err)
	}
	return out, nil
}

func (d *HTTPDialer) connect(conn net.Conn, target string) (net.Conn, error) {
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: target},
		Host:   target,
		Header: make(http.Header),
	}
	if d.Username != "" {
		cred := base64.StdEncoding.EncodeToString([]byte(d.Username + ":" + d.Password))
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
