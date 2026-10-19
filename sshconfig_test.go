package hopsock

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// keyServer is an SSH server that accepts user with any of keys, and
// records every key a client offers.
type keyServer struct {
	*testSSH
	mu      sync.Mutex
	offered []ssh.PublicKey
}

func sshKeyServer(t *testing.T, user string, keys ...ssh.PublicKey) *keyServer {
	t.Helper()
	ks := &keyServer{}
	ks.testSSH = startSSH(t, &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			ks.mu.Lock()
			ks.offered = append(ks.offered, k)
			ks.mu.Unlock()
			for _, want := range keys {
				if c.User() == user && bytes.Equal(k.Marshal(), want.Marshal()) {
					return nil, nil
				}
			}
			return nil, fmt.Errorf("denied")
		},
	})
	return ks
}

func (ks *keyServer) sawKey(k ssh.PublicKey) bool {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	for _, o := range ks.offered {
		if bytes.Equal(o.Marshal(), k.Marshal()) {
			return true
		}
	}
	return false
}

func (s *testSSH) port() string {
	_, p, _ := net.SplitHostPort(s.addr)
	return p
}

func (s *testSSH) sessionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions)
}

// fakeHome makes a temp $HOME with a .ssh dir and no agent, and returns
// the .ssh path.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	dir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// writeKey writes a new private key to path (encrypted when passphrase is
// set) and its .pub, and returns the signer.
func writeKey(t *testing.T, path, passphrase string) ssh.Signer {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	var block *pem.Block
	var err error
	if passphrase == "" {
		block, err = ssh.MarshalPrivateKey(priv, "")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte(passphrase))
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _ := ssh.NewSignerFromKey(priv)
	if err := os.WriteFile(path+".pub", ssh.MarshalAuthorizedKey(s.PublicKey()), 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func knownHostsLine(s *testSSH) string {
	return knownhosts.Line([]string{knownhosts.Normalize(s.addr)}, s.hostKey) + "\n"
}

// The case that started this: `ssh lmw-live-chat-server` works from
// ~/.ssh/config, so hopsock should accept the same name.
func TestSSHConfigAlias(t *testing.T) {
	dir := fakeHome(t)
	key := writeKey(t, filepath.Join(dir, "lmw_key"), "")
	srv := sshKeyServer(t, "ubuntu", key.PublicKey())
	writeFile(t, filepath.Join(dir, "known_hosts"), knownHostsLine(srv.testSSH))
	writeFile(t, filepath.Join(dir, "config"), `
# comment
Host lmw-live-chat-server
    HostName 127.0.0.1
    Port `+srv.port()+`
    User ubuntu
    IdentityFile ~/.ssh/lmw_key

Host *
    User someone-else
    IdentityFile ~/.ssh/nope
`)
	echo := echoServer(t)

	for _, raw := range []string{"lmw-live-chat-server", "ssh://lmw-live-chat-server"} {
		chain, err := NewChain([]string{raw}, nil)
		if err != nil {
			t.Fatalf("%s: %v", raw, err)
		}
		h := chain.Hops[0]
		if h.Addr != srv.addr || h.User != "ubuntu" || h.Label != "ssh://ubuntu@lmw-live-chat-server" {
			t.Fatalf("%s: got %+v", raw, h)
		}
		roundTrip(t, chain, echo, "via alias")
		chain.Close()
	}

	// The URL still wins over the config.
	h, err := ParseHop("ssh://root@lmw-live-chat-server:2222", Direct, nil)
	if err != nil || h.User != "root" || h.Addr != "127.0.0.1:2222" {
		t.Fatalf("URL override: got %+v %v", h, err)
	}
	// ssh_config=none ignores it.
	if h, err := ParseHop("ssh://u:p@lmw-live-chat-server?ssh_config=none&insecure=1", Direct, nil); err != nil || h.Addr != "lmw-live-chat-server:22" {
		t.Fatalf("ssh_config=none: got %+v %v", h, err)
	}
	// A bare name ssh config doesn't know is still an error.
	if _, err := NewChain([]string{"not-in-config"}, nil); err == nil || !strings.Contains(err.Error(), "~/.ssh/config") {
		t.Fatalf("unknown bare host: %v", err)
	}
}

func TestSSHConfigProxyJump(t *testing.T) {
	dir := fakeHome(t)
	key := writeKey(t, filepath.Join(dir, "id_ed25519"), "")
	bastion := sshKeyServer(t, "jumper", key.PublicKey())
	app := sshKeyServer(t, "deploy", key.PublicKey())
	writeFile(t, filepath.Join(dir, "known_hosts"), knownHostsLine(bastion.testSSH)+knownHostsLine(app.testSSH))
	writeFile(t, filepath.Join(dir, "config"), `
Host bastion
  HostName 127.0.0.1
  Port `+bastion.port()+`
  User jumper
Host app
  HostName=127.0.0.1
  Port=`+app.port()+`
  User=deploy
  ProxyJump bastion
`)
	chain, err := NewChain([]string{"app"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	if len(chain.Hops) != 2 || chain.Hops[0].Label != "ssh://jumper@bastion" || chain.Hops[1].Label != "ssh://deploy@app" {
		t.Fatalf("hops: %+v", chain.Hops)
	}
	roundTrip(t, chain, echoServer(t), "through the bastion")
	if bastion.sessionCount() != 1 || app.sessionCount() != 1 {
		t.Fatalf("sessions: bastion %d, app %d", bastion.sessionCount(), app.sessionCount())
	}
}

func TestSSHConfigProxyJumpLoop(t *testing.T) {
	dir := fakeHome(t)
	writeKey(t, filepath.Join(dir, "id_ed25519"), "")
	writeFile(t, filepath.Join(dir, "config"), "Host a\n  ProxyJump b\nHost b\n  ProxyJump a\n")
	if _, err := NewChain([]string{"a"}, nil); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Fatalf("want loop error, got %v", err)
	}
}

// TestHelperProxyCommand is not a real test: ProxyCommand runs the test
// binary as a tiny `nc host port`.
func TestHelperProxyCommand(_ *testing.T) {
	if os.Getenv("HOPSOCK_HELPER_NC") != "1" {
		return
	}
	args := os.Args[len(os.Args)-2:]
	c, err := net.Dial("tcp", net.JoinHostPort(args[0], args[1]))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	go func() { io.Copy(c, os.Stdin); c.(*net.TCPConn).CloseWrite() }()
	io.Copy(os.Stdout, c)
	os.Exit(0)
}

func TestSSHConfigProxyCommand(t *testing.T) {
	dir := fakeHome(t)
	key := writeKey(t, filepath.Join(dir, "id_ed25519"), "")
	srv := sshKeyServer(t, "me", key.PublicKey())
	writeFile(t, filepath.Join(dir, "known_hosts"), knownHostsLine(srv.testSSH))
	t.Setenv("HOPSOCK_HELPER_NC", "1")
	writeFile(t, filepath.Join(dir, "config"), fmt.Sprintf(`
Host viacmd
  HostName 127.0.0.1
  Port %s
  User me
  ProxyCommand %s -test.run=TestHelperProxyCommand -- %%h %%p
`, srv.port(), os.Args[0]))

	chain, err := NewChain([]string{"viacmd"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	roundTrip(t, chain, echoServer(t), "through a proxy command")

	// It can't sit behind another hop.
	up := socksServer(t, &Server{})
	if _, err := NewChain([]string{"socks5://" + up, "viacmd"}, nil); err == nil || !strings.Contains(err.Error(), "ProxyCommand") {
		t.Fatalf("want ProxyCommand error, got %v", err)
	}
}

// An encrypted IdentityFile with IdentitiesOnly: the matching agent key is
// used and no other agent key is offered.
func TestSSHConfigIdentitiesOnlyWithAgent(t *testing.T) {
	dir := fakeHome(t)
	want := writeKey(t, filepath.Join(dir, "work_key"), "s3cret")
	other := writeKey(t, filepath.Join(dir, "other_key"), "")

	kr := agent.NewKeyring()
	for _, p := range []string{"other_key", "work_key"} {
		b, _ := os.ReadFile(filepath.Join(dir, p))
		raw, err := ssh.ParseRawPrivateKeyWithPassphrase(b, []byte("s3cret"))
		if err != nil {
			raw, err = ssh.ParseRawPrivateKey(b)
		}
		if err != nil {
			t.Fatal(err)
		}
		if err := kr.Add(agent.AddedKey{PrivateKey: raw}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Skip("no unix sockets:", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()

	srv := sshKeyServer(t, "me", want.PublicKey())
	writeFile(t, filepath.Join(dir, "config"), `
Host work
  HostName 127.0.0.1
  Port `+srv.port()+`
  User me
  IdentityFile ~/.ssh/work_key
  IdentitiesOnly yes
  IdentityAgent `+sock+`
  StrictHostKeyChecking accept-new
  UserKnownHostsFile /dev/null
`)
	chain, err := NewChain([]string{"work"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	roundTrip(t, chain, echoServer(t), "agent key")
	if srv.sawKey(other.PublicKey()) {
		t.Fatal("IdentitiesOnly: the other agent key was offered")
	}
}

func TestSSHConfigHostKeyAlias(t *testing.T) {
	dir := fakeHome(t)
	key := writeKey(t, filepath.Join(dir, "id_ed25519"), "")
	srv := sshKeyServer(t, "me", key.PublicKey())
	writeFile(t, filepath.Join(dir, "known_hosts"), knownhosts.Line([]string{"stable-name"}, srv.hostKey)+"\n")
	writeFile(t, filepath.Join(dir, "config"), `
Host box
  HostName 127.0.0.1
  Port `+srv.port()+`
  User me
  HostKeyAlias stable-name
`)
	chain, err := NewChain([]string{"box"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain.Close()
	roundTrip(t, chain, echoServer(t), "alias key")

	// Without the alias the same host is unknown, and that's still refused.
	writeFile(t, filepath.Join(dir, "config"), "Host box\n  HostName 127.0.0.1\n  Port "+srv.port()+"\n  User me\n")
	chain2, err := NewChain([]string{"box"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer chain2.Close()
	if err := chain2.SSH()[0].Connect(t.Context()); err == nil || !strings.Contains(err.Error(), "unknown host") {
		t.Fatalf("want unknown host, got %v", err)
	}
}
