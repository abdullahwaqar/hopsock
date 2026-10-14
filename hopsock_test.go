package hopsock

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// echoServer echoes whatever it receives.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	return ln.Addr().String()
}

// socksServer starts a hopsock Server and returns its address.
func socksServer(t *testing.T, s *Server) string {
	t.Helper()
	if s.Addr == "" {
		s.Addr = "127.0.0.1:0"
	}
	ln, err := s.Listen()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String()
}

type testSSH struct {
	addr     string
	hostKey  ssh.PublicKey
	mu       sync.Mutex
	sessions []*ssh.ServerConn
}

func (s *testSSH) killSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.sessions {
		c.Close()
	}
	s.sessions = nil
}

// sshServer is a minimal SSH server that only does direct-tcpip forwarding.
func sshServer(t *testing.T, user, pass string) *testSSH {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if c.User() == user && string(p) == pass {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &testSSH{addr: ln.Addr().String(), hostKey: signer.PublicKey()}
	go func() {
		for {
			nc, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(nc, cfg)
				if err != nil {
					nc.Close()
					return
				}
				srv.mu.Lock()
				srv.sessions = append(srv.sessions, sc)
				srv.mu.Unlock()
				go ssh.DiscardRequests(reqs)
				for nch := range chans {
					if nch.ChannelType() != "direct-tcpip" {
						nch.Reject(ssh.UnknownChannelType, "nope")
						continue
					}
					var p struct {
						Host     string
						Port     uint32
						OrigHost string
						OrigPort uint32
					}
					if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil {
						nch.Reject(ssh.ConnectionFailed, "bad payload")
						continue
					}
					target, err := net.Dial("tcp", net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))))
					if err != nil {
						nch.Reject(ssh.ConnectionFailed, err.Error())
						continue
					}
					ch, creqs, err := nch.Accept()
					if err != nil {
						target.Close()
						continue
					}
					go ssh.DiscardRequests(creqs)
					go func() {
						defer ch.Close()
						defer target.Close()
						go func() { io.Copy(target, ch); target.(*net.TCPConn).CloseWrite() }()
						io.Copy(ch, target)
					}()
				}
			}()
		}
	}()
	return srv
}

func roundTrip(t *testing.T, d Dialer, target, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := d.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatalf("dial %s: %v", target, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q want %q", buf, msg)
	}
}

func TestSOCKS5WithAuth(t *testing.T) {
	echo := echoServer(t)
	up := socksServer(t, &Server{Username: "bob", Password: "p@ss:w/rd#1"})

	roundTrip(t, &SOCKS5Dialer{Addr: up, Username: "bob", Password: "p@ss:w/rd#1"}, echo, "hello")

	_, err := (&SOCKS5Dialer{Addr: up, Username: "bob", Password: "wrong"}).DialContext(context.Background(), "tcp", echo)
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("want auth failure, got %v", err)
	}
}

func TestHTTPConnect(t *testing.T) {
	echo := echoServer(t)
	// tiny CONNECT proxy
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
				line := strings.SplitN(string(buf[:n]), " ", 3)
				if !strings.Contains(string(buf[:n]), "Proxy-Authorization: Basic") {
					c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
					return
				}
				up, err := net.Dial("tcp", line[1])
				if err != nil {
					c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
					return
				}
				defer up.Close()
				c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	roundTrip(t, &HTTPDialer{Addr: ln.Addr().String(), Username: "u", Password: "p"}, echo, "via http")
	if _, err := (&HTTPDialer{Addr: ln.Addr().String()}).DialContext(context.Background(), "tcp", echo); err == nil {
		t.Fatal("want 407 error")
	}
}

// Full chain: local SOCKS5 -> upstream SOCKS5 (auth) -> SSH -> target.
func TestChainSOCKSthenSSH(t *testing.T) {
	echo := echoServer(t)
	upSocks := socksServer(t, &Server{Username: "bd", Password: "secret"})
	sshd := sshServer(t, "tunnel", "hunter2")

	t.Setenv("HS_TEST_PASS", "hunter2")
	chain, err := NewChain([]string{
		"socks5://bd:secret@" + upSocks,
		"ssh://tunnel@" + sshd.addr + "?passenv=HS_TEST_PASS&hostkey=" + ssh.FingerprintSHA256(sshd.hostKey) + "&agent=0",
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()

	stats := &Stats{}
	local := socksServer(t, &Server{Dialer: chain, Stats: stats})
	client := &SOCKS5Dialer{Addr: local}

	for i := 0; i < 5; i++ {
		roundTrip(t, client, echo, fmt.Sprintf("msg-%d", i))
	}
	// Hostnames must reach the SSH server unresolved and still work.
	_, port, _ := net.SplitHostPort(echo)
	roundTrip(t, client, "localhost:"+port, "by name")

	if st := chain.SSH()[0].State(); !st.Connected {
		t.Fatal("ssh session should be up")
	}

	// Server drops the session: next dial must transparently reconnect.
	sshd.killSessions()
	time.Sleep(100 * time.Millisecond)
	roundTrip(t, client, echo, "after reconnect")

	time.Sleep(50 * time.Millisecond)
	snap := stats.Snapshot()
	if snap.Total != 7 || snap.Up == 0 || snap.Down == 0 {
		t.Fatalf("unexpected stats %+v", snap)
	}
}

func TestSSHWrongHostKey(t *testing.T) {
	sshd := sshServer(t, "u", "p")
	chain, err := NewChain([]string{"ssh://u:p@" + sshd.addr + "?hostkey=SHA256:nope&agent=0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = chain.DialContext(context.Background(), "tcp", "127.0.0.1:1")
	if err == nil || !strings.Contains(err.Error(), "host key mismatch") {
		t.Fatalf("want host key mismatch, got %v", err)
	}
}

func TestParseHopErrors(t *testing.T) {
	for _, raw := range []string{"host:1080", "ftp://x:1", "ssh://", "socks5://u@h:1?passenv=HS_DEFINITELY_UNSET"} {
		if _, err := ParseHop(raw, Direct, nil); err == nil {
			t.Errorf("%q: want error", raw)
		}
	}
	h, err := ParseHop("socks5h://user:pw@example.com", Direct, nil)
	if err != nil || h.Addr != "example.com:1080" || strings.Contains(h.Label, "pw") {
		t.Fatalf("got %+v %v", h, err)
	}
}

func TestParseExit(t *testing.T) {
	i := &ExitInfo{}
	parseExit(i, []byte(`{"ip":"1.2.3.4","city":"Lahore","region":"Punjab","country":"PK","org":"AS1 Foo"}`))
	if i.IP != "1.2.3.4" || i.Location != "Lahore, Punjab, PK" || i.Org != "AS1 Foo" {
		t.Fatalf("%+v", i)
	}
	i = &ExitInfo{}
	parseExit(i, []byte(`{"proxy":{"ip":"5.6.7.8"},"city":{"name":"Dallas","state":"Texas"},"country":{"code":"US"},"isp":{"isp":"ISP Co"}}`))
	if i.IP != "5.6.7.8" || i.Location != "Dallas, Texas, US" || i.Org != "ISP Co" {
		t.Fatalf("%+v", i)
	}
	i = &ExitInfo{}
	parseExit(i, []byte("9.9.9.9\n"))
	if i.IP != "9.9.9.9" {
		t.Fatalf("%+v", i)
	}
}

// Fingerprints are base64 and often contain "+", which URL query parsing
// turns into a space. The pin must still match.
func TestHostKeyPinWithPlus(t *testing.T) {
	for i := 0; i < 200; i++ {
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		key, _ := ssh.NewPublicKey(pub)
		fp := ssh.FingerprintSHA256(key)
		if !strings.Contains(fp, "+") {
			continue
		}
		u, _ := url.Parse("ssh://h?hostkey=" + fp) // unescaped, like a user would type it
		cb, err := hostKeyCallback(u.Query(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := cb("h:22", nil, key); err != nil {
			t.Fatalf("pin %s rejected: %v", fp, err)
		}
		return
	}
	t.Skip("no fingerprint with '+' generated")
}

func TestPassenvRejectsSecretValue(t *testing.T) {
	_, err := ParseHop("socks5://u@h:1080?passenv=9-not-a-var-name", Direct, nil)
	if err == nil || !strings.Contains(err.Error(), "variable name") {
		t.Fatalf("want variable-name error, got %v", err)
	}
	if strings.Contains(err.Error(), "9-not-a-var-name") {
		t.Fatal("error must not echo the secret")
	}
	t.Setenv("HS_PASS", "s3cret")
	h, err := ParseHop("socks5://u@h:1080?passenv=HS_PASS", Direct, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Dialer.(*SOCKS5Dialer).Password != "s3cret" {
		t.Fatal("password not read from env")
	}
}

func TestRedact(t *testing.T) {
	if got := redact("socks5://user:p%zz@host:1"); strings.Contains(got, "p%zz") {
		t.Fatalf("leaked: %s", got)
	}
}
