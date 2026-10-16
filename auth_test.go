package hopsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// scriptedAsk answers prompts from a list and records the requests.
type scriptedAsk struct {
	mu      sync.Mutex
	answers [][2]string
	reqs    []CredRequest
	delay   time.Duration
}

func (s *scriptedAsk) ask(_ context.Context, req CredRequest) (string, string, error) {
	time.Sleep(s.delay)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, req)
	if len(s.answers) == 0 {
		return "", "", ErrPromptCanceled
	}
	a := s.answers[0]
	s.answers = s.answers[1:]
	return a[0], a[1], nil
}

func (s *scriptedAsk) calls() []CredRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]CredRequest(nil), s.reqs...)
}

func TestSOCKS5SentinelErrors(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "bob", Password: "pw"})
	_, err := (&SOCKS5Dialer{Addr: up}).DialContext(context.Background(), "tcp", echo)
	if !errors.Is(err, ErrAuthRequired) {
		t.Fatalf("no creds: want ErrAuthRequired, got %v", err)
	}
	_, err = (&SOCKS5Dialer{Addr: up, Username: "bob", Password: "nope"}).DialContext(context.Background(), "tcp", echo)
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("bad creds: want ErrAuthFailed, got %v", err)
	}
}

func TestSOCKS5AsksWhenMissing(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "bob", Password: "pw"})
	a := &scriptedAsk{answers: [][2]string{{"bob", "wrong"}, {"bob", "pw"}}}
	d := &SOCKS5Dialer{Addr: up, Ask: a.ask}

	roundTrip(t, d, echo, "first")
	roundTrip(t, d, echo, "second") // remembered, no new prompt

	reqs := a.calls()
	if len(reqs) != 2 {
		t.Fatalf("want 2 prompts, got %d: %+v", len(reqs), reqs)
	}
	if !reqs[0].NeedUser || reqs[0].Retry {
		t.Errorf("first prompt should ask for a user and not be a retry: %+v", reqs[0])
	}
	if !reqs[1].Retry || reqs[1].User != "bob" {
		t.Errorf("second prompt should be a retry prefilled with bob: %+v", reqs[1])
	}
}

func TestSOCKS5AsksPasswordOnlyForURLUser(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "bob", Password: "pw"})
	a := &scriptedAsk{answers: [][2]string{{"ignored", "pw"}}}
	d := &SOCKS5Dialer{Addr: up, Username: "bob", Ask: a.ask}
	roundTrip(t, d, echo, "hi")
	reqs := a.calls()
	if len(reqs) != 1 || reqs[0].NeedUser || reqs[0].Retry || reqs[0].User != "bob" {
		t.Fatalf("want one password-only, non-retry prompt for bob, got %+v", reqs)
	}
}

func TestNoPromptWithoutAuth(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{})
	a := &scriptedAsk{}
	roundTrip(t, &SOCKS5Dialer{Addr: up, Ask: a.ask}, echo, "open proxy")
	if n := len(a.calls()); n != 0 {
		t.Fatalf("open proxy must not prompt, got %d", n)
	}
}

func TestConcurrentDialsShareOnePrompt(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "u", Password: "p"})
	a := &scriptedAsk{answers: [][2]string{{"u", "p"}}, delay: 200 * time.Millisecond}
	d := &SOCKS5Dialer{Addr: up, Ask: a.ask}
	var wg sync.WaitGroup
	var fails atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := d.DialContext(context.Background(), "tcp", echo)
			if err != nil {
				fails.Add(1)
				return
			}
			c.Close()
		}()
	}
	wg.Wait()
	if fails.Load() != 0 {
		t.Fatalf("%d dials failed", fails.Load())
	}
	if n := len(a.calls()); n != 1 {
		t.Fatalf("want exactly one prompt, got %d", n)
	}
}

func TestDeclinedPromptStopsAsking(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "u", Password: "p"})
	a := &scriptedAsk{} // declines
	d := &SOCKS5Dialer{Addr: up, Ask: a.ask}
	for i := 0; i < 3; i++ {
		if _, err := d.DialContext(context.Background(), "tcp", echo); !errors.Is(err, ErrAuthRequired) {
			t.Fatalf("want ErrAuthRequired, got %v", err)
		}
	}
	if n := len(a.calls()); n != 1 {
		t.Fatalf("declined prompt should not repeat, got %d", n)
	}
	d.ResetPrompt()
	a.mu.Lock()
	a.answers = [][2]string{{"u", "p"}}
	a.mu.Unlock()
	roundTrip(t, d, echo, "after reset")
}

func TestHTTPAsksOn407(t *testing.T) {
	echo := echoServer(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				req := string(buf[:n])
				// "u:p" base64
				if !strings.Contains(req, "Proxy-Authorization: Basic dTpw") {
					c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					return
				}
				target := strings.SplitN(req, " ", 3)[1]
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n"))
				go func() { buf := make([]byte, 4096); n, _ := c.Read(buf); up.Write(buf[:n]) }()
				n, _ = up.Read(buf)
				c.Write(buf[:n])
			}()
		}
	}()
	a := &scriptedAsk{answers: [][2]string{{"u", "p"}}}
	roundTrip(t, &HTTPDialer{Addr: ln.Addr().String(), Ask: a.ask}, echo, "via 407")
	if n := len(a.calls()); n != 1 {
		t.Fatalf("want 1 prompt, got %d", n)
	}
}

// A later hop must not prompt because an earlier hop's auth failed.
func TestPromptBelongsToFailingHop(t *testing.T) {
	echo := echoServer(t)
	inner := socksServer(t, &Server{}) // open
	outer := socksServer(t, &Server{Username: "u", Password: "p"})
	outerAsk := &scriptedAsk{} // declines
	innerAsk := &scriptedAsk{}
	first := &SOCKS5Dialer{Addr: outer, Ask: outerAsk.ask}
	second := &SOCKS5Dialer{Addr: inner, Forward: first, Ask: innerAsk.ask}
	if _, err := second.DialContext(context.Background(), "tcp", echo); err == nil {
		t.Fatal("want error")
	}
	if len(outerAsk.calls()) != 1 || len(innerAsk.calls()) != 0 {
		t.Fatalf("outer asked %d, inner asked %d", len(outerAsk.calls()), len(innerAsk.calls()))
	}
}

func TestSSHAsksForPassword(t *testing.T) {
	echo := echoServer(t)
	sshd := sshServer(t, "tunnel", "hunter2")
	a := &scriptedAsk{answers: [][2]string{{"", "nope"}, {"", "hunter2"}}}
	t.Setenv("SSH_AUTH_SOCK", "")
	chain, err := NewChain([]string{
		"ssh://tunnel@" + sshd.addr + "?agent=0&hostkey=" + ssh.FingerprintSHA256(sshd.hostKey),
	}, &ChainOptions{Credentials: a.ask})
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	roundTrip(t, chain, echo, "ssh prompt")

	reqs := a.calls()
	if len(reqs) != 2 || reqs[0].Retry || !reqs[1].Retry || reqs[0].NeedUser || reqs[0].User != "tunnel" {
		t.Fatalf("unexpected prompts %+v", reqs)
	}

	// Reconnect reuses the password that worked.
	sshd.killSessions()
	time.Sleep(100 * time.Millisecond)
	roundTrip(t, chain, echo, "after reconnect")
	if n := len(a.calls()); n != 2 {
		t.Fatalf("reconnect should not prompt, got %d prompts", n)
	}
}

func TestSSHWithoutAuthNeedsPrompt(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	_, err := NewChain([]string{"ssh://u@127.0.0.1:1?agent=0&insecure=1"}, nil)
	if err == nil || !strings.Contains(err.Error(), "no auth available") {
		t.Fatalf("without a prompt, want no-auth error, got %v", err)
	}
	ask := func(context.Context, CredRequest) (string, string, error) { return "", "", fmt.Errorf("x") }
	if _, err := NewChain([]string{"ssh://u@127.0.0.1:1?agent=0&insecure=1"}, &ChainOptions{Credentials: ask}); err != nil {
		t.Fatalf("with a prompt, chain should build: %v", err)
	}
}
