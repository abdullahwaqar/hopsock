package hopsock

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// Server is a local SOCKS5 proxy (CONNECT only) that sends every
// connection out through Dialer.
type Server struct {
	Addr     string // listen address, e.g. "127.0.0.1:1080"
	Username string // if set, clients must authenticate
	Password string
	Dialer   Dialer // upstream; nil means Direct
	Log      LogFunc
	Stats    *Stats // created by Serve if nil

	DialTimeout time.Duration // 0 means 30s
}

// ListenAndServe listens on s.Addr and serves until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	return s.Serve(ctx, ln)
}

// Listen binds the address without serving yet, so callers can report
// bind errors before starting a UI.
func (s *Server) Listen() (net.Listener, error) {
	return net.Listen("tcp", s.Addr)
}

// Serve accepts on ln until ctx is cancelled. Open connections are closed
// on return.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s.Stats == nil {
		s.Stats = &Stats{}
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	context.AfterFunc(ctx, func() { ln.Close() })

	s.Log.logf(LevelInfo, "socks5 listening on %s", ln.Addr())
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	client := conn.RemoteAddr().String()

	_ = conn.SetDeadline(time.Now().Add(DefaultHandshakeTimeout))
	target, err := s.negotiate(conn)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			s.Log.logf(LevelDebug, "%s: handshake: %v", client, err)
		}
		return
	}
	_ = conn.SetDeadline(time.Time{})

	timeout := s.DialTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	dctx, cancel := context.WithTimeout(ctx, timeout)
	d := s.Dialer
	if d == nil {
		d = Direct
	}
	start := time.Now()
	up, err := d.DialContext(dctx, "tcp", target)
	cancel()
	if err != nil {
		s.Stats.fail()
		s.Log.logf(LevelError, "%s -> %s: %v", client, target, err)
		_, _ = conn.Write(reply(dialErrCode(err)))
		return
	}
	defer up.Close()
	if _, err := conn.Write(reply(repSuccess)); err != nil {
		return
	}

	ci := s.Stats.open(client, target)
	defer s.Stats.close(ci)
	s.Log.logf(LevelDebug, "%s -> %s connected in %s", client, target, time.Since(start).Round(time.Millisecond))

	// Close both sides when the server shuts down.
	stop := context.AfterFunc(ctx, func() { conn.Close(); up.Close() })
	defer stop()

	pipe(conn, up, &ci.Up, &ci.Down)
	s.Log.logf(LevelDebug, "%s -> %s closed after %s (up %d, down %d)", client, target,
		time.Since(ci.Start).Round(time.Millisecond), ci.Up.Load(), ci.Down.Load())
}

// negotiate runs the SOCKS5 greeting, optional auth, and request, and
// returns the requested target.
func (s *Server) negotiate(conn net.Conn) (string, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return "", err
	}
	if hdr[0] != socksVersion {
		return "", fmt.Errorf("version %d is not SOCKS5", hdr[0])
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	want := byte(methodNoAuth)
	if s.Username != "" {
		want = methodUserPass
	}
	ok := false
	for _, m := range methods {
		if m == want {
			ok = true
		}
	}
	if !ok {
		_, _ = conn.Write([]byte{socksVersion, methodNoAcceptable})
		return "", errors.New("client offered no acceptable auth method")
	}
	if _, err := conn.Write([]byte{socksVersion, want}); err != nil {
		return "", err
	}
	if want == methodUserPass {
		if err := s.checkAuth(conn); err != nil {
			return "", err
		}
	}

	var req [3]byte
	if _, err := io.ReadFull(conn, req[:]); err != nil {
		return "", err
	}
	target, atyp, err := readAddr(conn)
	if err != nil {
		if atyp != 0 {
			_, _ = conn.Write(reply(repAddrNotSupported))
		}
		return "", err
	}
	if req[1] != cmdConnect {
		_, _ = conn.Write(reply(repCmdNotSupported))
		return "", fmt.Errorf("command %d not supported (CONNECT only)", req[1])
	}
	return target, nil
}

func (s *Server) checkAuth(conn net.Conn) error {
	var h [2]byte
	if _, err := io.ReadFull(conn, h[:]); err != nil {
		return err
	}
	user := make([]byte, h[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	var pl [1]byte
	if _, err := io.ReadFull(conn, pl[:]); err != nil {
		return err
	}
	pass := make([]byte, pl[0])
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	u := subtle.ConstantTimeCompare(user, []byte(s.Username))
	p := subtle.ConstantTimeCompare(pass, []byte(s.Password))
	if u&p != 1 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("bad credentials for user %q", user)
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

// reply builds a CONNECT reply with a zero bound address.
func reply(code byte) []byte {
	b := []byte{socksVersion, code, 0x00, atypIPv4, 0, 0, 0, 0}
	return binary.BigEndian.AppendUint16(b, 0)
}

func dialErrCode(err error) byte {
	var dnsErr *net.DNSError
	var chanErr *ssh.OpenChannelError
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return repConnRefused
	case errors.Is(err, syscall.ENETUNREACH):
		return repNetworkUnreachable
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, context.DeadlineExceeded), errors.As(err, &dnsErr):
		return repHostUnreachable
	case errors.As(err, &chanErr):
		// The SSH server only gives us a message; map the common one.
		if strings.Contains(chanErr.Message, "refused") {
			return repConnRefused
		}
		return repHostUnreachable
	}
	return repGeneralFailure
}

// halfDeadGrace is how long one direction may keep going after the other
// has finished before both sides are closed.
const halfDeadGrace = 2 * time.Minute

// pipe copies both directions until both are done, counting bytes.
func pipe(client, upstream net.Conn, up, down *atomic.Int64) {
	done := make(chan struct{}, 2)
	go copyCount(upstream, client, up, done)
	go copyCount(client, upstream, down, done)

	<-done
	// SSH channels don't support deadlines, so bound the other direction
	// with a timer instead of SetReadDeadline.
	t := time.AfterFunc(halfDeadGrace, func() {
		client.Close()
		upstream.Close()
	})
	<-done
	t.Stop()
}

func copyCount(dst, src net.Conn, n *atomic.Int64, done chan<- struct{}) {
	defer func() { done <- struct{}{} }()
	buf := make([]byte, 32*1024)
	for {
		r, err := src.Read(buf)
		if r > 0 {
			if _, werr := dst.Write(buf[:r]); werr != nil {
				break
			}
			n.Add(int64(r))
		}
		if err != nil {
			break
		}
	}
	// Half-close so the peer sees EOF but can still reply.
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
}
