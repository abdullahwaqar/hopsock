// Package hopsock runs a local SOCKS5 proxy that forwards every connection
// through a chain of upstream hops: SOCKS5, HTTP CONNECT, or SSH.
//
//	chain, err := hopsock.NewChain([]string{
//		"socks5://user@isp.example.com:10001?passenv=PROXY_PASS",
//		"ssh://me@box.example.com?key=~/.ssh/id_ed25519",
//	}, nil)
//	if err != nil {
//		return err
//	}
//	defer chain.Close()
//	srv := &hopsock.Server{Addr: "127.0.0.1:1080", Dialer: chain}
//	return srv.ListenAndServe(ctx)
package hopsock

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Dialer opens a TCP connection to addr ("host:port"). Hostnames are passed
// through unresolved so DNS happens at the last hop, like socks5h.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Direct dials without any proxy.
var Direct Dialer = &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}

// DefaultHandshakeTimeout bounds proxy and SSH handshakes when the context
// has no deadline.
const DefaultHandshakeTimeout = 20 * time.Second

// Level is a log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DBG"
	case LevelInfo:
		return "INF"
	case LevelWarn:
		return "WRN"
	default:
		return "ERR"
	}
}

// LogFunc receives log lines from the library. A nil LogFunc is silent.
type LogFunc func(level Level, msg string)

func (f LogFunc) logf(level Level, format string, args ...any) {
	if f != nil {
		f(level, fmt.Sprintf(format, args...))
	}
}

// guardHandshake applies ctx's deadline (or DefaultHandshakeTimeout) to conn
// and aborts the handshake if ctx is cancelled. Call the returned func when
// the handshake is done to clear the deadline.
func guardHandshake(ctx context.Context, conn net.Conn) (done func()) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(DefaultHandshakeTimeout)
	}
	_ = conn.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Unix(1, 0)) })
	return func() {
		stop()
		_ = conn.SetDeadline(time.Time{})
	}
}

func checkTCP(network string) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return nil
	}
	return fmt.Errorf("network %q not supported (tcp only)", network)
}
