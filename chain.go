package hopsock

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/abdullahwaqar/hopsock/internal/pathx"
)

// Hop is one parsed upstream in a chain.
type Hop struct {
	Scheme string // "socks5", "http" or "ssh"
	Addr   string // host:port
	User   string
	Label  string // display form, never contains secrets
	Dialer Dialer // dials through this hop and every hop before it
}

// Chain dials through each hop in order. The first hop is reached directly
// and the target is reached from the last hop. An empty chain dials directly.
type Chain struct {
	Hops []Hop
}

func (c *Chain) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if c == nil || len(c.Hops) == 0 {
		return Direct.DialContext(ctx, network, addr)
	}
	return c.Hops[len(c.Hops)-1].Dialer.DialContext(ctx, network, addr)
}

// SSH returns the SSH dialers in the chain, in hop order.
func (c *Chain) SSH() []*SSHDialer {
	var out []*SSHDialer
	for _, h := range c.Hops {
		if s, ok := h.Dialer.(*SSHDialer); ok {
			out = append(out, s)
		}
	}
	return out
}

// Close closes any SSH sessions in the chain. The chain stays usable and
// reconnects on the next dial.
func (c *Chain) Close() error {
	var errs []error
	for _, s := range c.SSH() {
		errs = append(errs, s.Close())
	}
	return errors.Join(errs...)
}

// ChainOptions tune NewChain. The zero value is fine.
type ChainOptions struct {
	Log          LogFunc
	SSHKeepAlive time.Duration // see SSHDialer.KeepAlive
}

// NewChain builds a chain from hop URLs, outermost first:
//
//	socks5://user:pass@host:1080        (also socks5h://, socks://)
//	socks5://user@host:1080?passenv=VAR (password read from $VAR)
//	http://user:pass@host:8080          (HTTP CONNECT)
//	ssh://user@host:22?key=~/.ssh/id_ed25519
//
// SSH query options:
//
//	key=PATH          private key file (repeatable)
//	keypassenv=VAR    passphrase for encrypted keys
//	passenv=VAR       password from env
//	agent=0           don't use $SSH_AUTH_SOCK
//	known_hosts=PATH  default ~/.ssh/known_hosts
//	hostkey=SHA256:x  pin the server key fingerprint instead
//	insecure=1        skip host key checking (testing only)
//	timeout=20s       handshake timeout
func NewChain(urls []string, opts *ChainOptions) (*Chain, error) {
	c := &Chain{}
	prev := Direct
	for i, raw := range urls {
		h, err := ParseHop(raw, prev, opts)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i+1, err)
		}
		c.Hops = append(c.Hops, h)
		prev = h.Dialer
	}
	return c, nil
}

var (
	defaultPorts = map[string]string{"socks5": "1080", "http": "8080", "ssh": "22"}
	envName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// ParseHop parses one hop URL. forward is how this hop is reached.
func ParseHop(raw string, forward Dialer, opts *ChainOptions) (Hop, error) {
	if opts == nil {
		opts = &ChainOptions{}
	}
	if !strings.Contains(raw, "://") {
		return Hop{}, fmt.Errorf("%q: want scheme://host:port", raw)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Hop{}, fmt.Errorf("parse %s: %w (URL-encode special characters in the password, or use passenv=VAR)", redact(raw), err)
	}
	q := u.Query()

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks", "socks5h":
		scheme = "socks5"
	case "https":
		return Hop{}, errors.New("https:// proxies are not supported, use http:// (CONNECT)")
	}
	defPort, ok := defaultPorts[scheme]
	if !ok {
		return Hop{}, fmt.Errorf("unknown scheme %q (want socks5, http or ssh)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return Hop{}, fmt.Errorf("%s: missing host", u.Redacted())
	}
	port := u.Port()
	if port == "" {
		port = defPort
	}
	addr := net.JoinHostPort(host, port)

	username := u.User.Username()
	password, _ := u.User.Password()
	if q.Has("passenv") {
		if password, err = readEnv("passenv", q.Get("passenv")); err != nil {
			return Hop{}, err
		}
	}
	if scheme == "ssh" && username == "" {
		username = currentUser()
	}

	h := Hop{Scheme: scheme, Addr: addr, User: username, Label: scheme + "://" + addr}
	if username != "" {
		h.Label = scheme + "://" + username + "@" + addr
	}

	switch scheme {
	case "socks5":
		h.Dialer = &SOCKS5Dialer{Addr: addr, Username: username, Password: password, Forward: forward}
	case "http":
		h.Dialer = &HTTPDialer{Addr: addr, Username: username, Password: password, Forward: forward}
	case "ssh":
		cfg, err := sshClientConfig(username, password, q, opts.Log)
		if err != nil {
			return Hop{}, err
		}
		h.Dialer = &SSHDialer{Addr: addr, Config: cfg, Forward: forward, KeepAlive: opts.SSHKeepAlive, Log: opts.Log}
	}
	return h, nil
}

// readEnv resolves a passenv/keypassenv option. It catches the common
// mistake of passing the secret itself instead of a variable name, without
// echoing the value.
func readEnv(opt, name string) (string, error) {
	if !envName.MatchString(name) {
		return "", fmt.Errorf("%s= takes an environment variable name (e.g. %s=PROXY_PASS), not the secret itself", opt, opt)
	}
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("%s=%s but $%s is empty or unset", opt, name, name)
	}
	return v, nil
}

func sshClientConfig(username, password string, q url.Values, log LogFunc) (*ssh.ClientConfig, error) {
	cfg := &ssh.ClientConfig{User: username, Timeout: DefaultHandshakeTimeout}
	if t := q.Get("timeout"); t != "" {
		d, err := time.ParseDuration(t)
		if err != nil {
			return nil, fmt.Errorf("timeout=%q: %w", t, err)
		}
		cfg.Timeout = d
	}

	var passphrase string
	if q.Has("keypassenv") {
		var err error
		if passphrase, err = readEnv("keypassenv", q.Get("keypassenv")); err != nil {
			return nil, err
		}
	}

	var signers []ssh.Signer
	keyFiles := q["key"]
	for _, p := range keyFiles {
		s, err := loadKey(pathx.ExpandHome(p), passphrase)
		if err != nil {
			return nil, err
		}
		signers = append(signers, s)
	}
	// With nothing explicit, try the usual default keys like ssh does.
	if len(keyFiles) == 0 && password == "" {
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			if s, err := loadKey(filepath.Join(pathx.Home(), ".ssh", name), passphrase); err == nil {
				signers = append(signers, s)
			}
		}
	}

	var ag *sshAgent
	if sock := os.Getenv("SSH_AUTH_SOCK"); sock != "" && q.Get("agent") != "0" {
		ag = &sshAgent{sock: sock, log: log}
	}
	if len(signers) > 0 || ag != nil {
		cfg.Auth = append(cfg.Auth, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return slices.Concat(signers, ag.signers()), nil
		}))
	}
	if password != "" {
		cfg.Auth = append(cfg.Auth,
			ssh.Password(password),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}))
	}
	if len(cfg.Auth) == 0 {
		return nil, errors.New("ssh: no auth available (set a password, key=PATH, or run ssh-agent)")
	}

	hk, err := hostKeyCallback(q, log)
	if err != nil {
		return nil, err
	}
	cfg.HostKeyCallback = hk
	return cfg, nil
}

// sshAgent is a lazily dialed ssh-agent connection. It stays open because
// agent signers sign through it during the handshake.
type sshAgent struct {
	sock string
	log  LogFunc

	mu     sync.Mutex
	client agent.ExtendedAgent
	conn   net.Conn
}

func (a *sshAgent) signers() []ssh.Signer {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if a.client == nil {
			conn, err := net.Dial("unix", a.sock)
			if err != nil {
				a.log.logf(LevelDebug, "ssh agent at %s unavailable: %v", a.sock, err)
				return nil
			}
			a.conn, a.client = conn, agent.NewClient(conn)
		}
		s, err := a.client.Signers()
		if err == nil {
			return s
		}
		// The agent may have restarted; reconnect once.
		a.conn.Close()
		a.conn, a.client = nil, nil
	}
	return nil
}

func hostKeyCallback(q url.Values, log LogFunc) (ssh.HostKeyCallback, error) {
	switch strings.ToLower(q.Get("insecure")) {
	case "1", "true", "yes":
		return func(host string, _ net.Addr, key ssh.PublicKey) error {
			log.logf(LevelWarn, "ssh %s: host key NOT verified (%s)", host, ssh.FingerprintSHA256(key))
			return nil
		}, nil
	}

	if pin := q.Get("hostkey"); pin != "" {
		// Query decoding turns "+" into " ", and base64 fingerprints often contain "+".
		pin = strings.ReplaceAll(strings.TrimSpace(pin), " ", "+")
		if !strings.HasPrefix(pin, "SHA256:") {
			pin = "SHA256:" + pin
		}
		return func(host string, _ net.Addr, key ssh.PublicKey) error {
			got := ssh.FingerprintSHA256(key)
			if subtle.ConstantTimeCompare([]byte(got), []byte(pin)) != 1 {
				return fmt.Errorf("host key mismatch for %s: got %s, pinned %s", host, got, pin)
			}
			return nil
		}, nil
	}

	path := q.Get("known_hosts")
	if path == "" {
		path = filepath.Join(pathx.Home(), ".ssh", "known_hosts")
	}
	path = pathx.ExpandHome(path)
	kh, err := knownhosts.New(path)
	if err != nil {
		return nil, fmt.Errorf("ssh: can't read %s: %w (pass hostkey=SHA256:... or insecure=1)", path, err)
	}
	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		err := kh(host, remote, key)
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			fp := ssh.FingerprintSHA256(key)
			return fmt.Errorf("unknown host %s (key %s): log in once with ssh to trust it, or pass hostkey=%s", host, fp, fp)
		}
		return err
	}, nil
}

func loadKey(path, passphrase string) (ssh.Signer, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ssh key: %w", err)
	}
	s, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == "" {
			return nil, fmt.Errorf("ssh key %s is encrypted; set keypassenv=VAR", path)
		}
		s, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase))
	}
	if err != nil {
		return nil, fmt.Errorf("ssh key %s: %w", path, err)
	}
	return s, nil
}

func currentUser() string {
	u, err := user.Current()
	if err != nil || u.Username == "" {
		return os.Getenv("USER")
	}
	// Windows reports DOMAIN\name.
	if i := strings.LastIndex(u.Username, `\`); i >= 0 {
		return u.Username[i+1:]
	}
	return u.Username
}

// redact hides credentials in a hop URL that url.Parse rejected.
func redact(raw string) string {
	scheme, rest, ok := strings.Cut(raw, "://")
	at := strings.LastIndex(rest, "@")
	if !ok || at < 0 {
		return raw
	}
	return scheme + "://***" + rest[at:]
}
