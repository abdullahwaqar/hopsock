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
	"github.com/abdullahwaqar/hopsock/internal/sshconfig"
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

// ResetPrompts lets every hop ask for credentials again after a prompt was
// declined.
func (c *Chain) ResetPrompts() {
	for _, h := range c.Hops {
		if r, ok := h.Dialer.(interface{ ResetPrompt() }); ok {
			r.ResetPrompt()
		}
	}
}

// ChainOptions tune NewChain. The zero value is fine.
type ChainOptions struct {
	Log          LogFunc
	SSHKeepAlive time.Duration // see SSHDialer.KeepAlive

	// Credentials, if set, is asked for usernames and passwords that a hop
	// needs but the URL didn't give, and again when they're rejected.
	Credentials CredentialsFunc

	// SSHConfig is the OpenSSH client config that ssh:// hosts are looked up
	// in. Empty reads ~/.ssh/config, then /etc/ssh/ssh_config, like ssh.
	// "none" turns the lookup off.
	SSHConfig string
}

// NewChain builds a chain from hop URLs, outermost first:
//
//	socks5://user:pass@host:1080        (also socks5h://, socks://)
//	socks5://user@host:1080?passenv=VAR (password read from $VAR)
//	http://user:pass@host:8080          (HTTP CONNECT)
//	ssh://user@host:22?key=~/.ssh/id_ed25519
//	ssh://myalias                       (a Host from ~/.ssh/config)
//	myalias                             (same, when ~/.ssh/config names it)
//
// SSH hosts are looked up in ~/.ssh/config like ssh does: HostName, User,
// Port, IdentityFile, IdentitiesOnly, IdentityAgent, ProxyJump,
// ProxyCommand, UserKnownHostsFile, StrictHostKeyChecking, HostKeyAlias and
// ConnectTimeout are honored. Values in the URL win. A ProxyJump adds the
// jump hosts to the chain as hops of their own.
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
//	ssh_config=PATH   read this ssh config instead, or "none" for none
func NewChain(urls []string, opts *ChainOptions) (*Chain, error) {
	c := &Chain{}
	prev := Direct
	for i, raw := range urls {
		hops, err := ParseHops(raw, prev, opts)
		if err != nil {
			return nil, fmt.Errorf("hop %d: %w", i+1, err)
		}
		c.Hops = append(c.Hops, hops...)
		prev = hops[len(hops)-1].Dialer
	}
	return c, nil
}

var (
	defaultPorts = map[string]string{"socks5": "1080", "http": "8080", "ssh": "22"}
	envName      = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// maxJumps bounds ProxyJump nesting, which also stops config loops.
const maxJumps = 8

// ParseHop parses one hop URL. forward is how this hop is reached. If the
// hop's ssh config sets ProxyJump, the jump hosts are folded into the
// returned hop's Dialer; use ParseHops to get them as separate hops.
func ParseHop(raw string, forward Dialer, opts *ChainOptions) (Hop, error) {
	hops, err := ParseHops(raw, forward, opts)
	if err != nil {
		return Hop{}, err
	}
	return hops[len(hops)-1], nil
}

// ParseHops parses one hop URL into the hops it stands for: usually one,
// more when an ssh:// host has a ProxyJump in ~/.ssh/config (the jump hosts
// come first). forward is how the first of them is reached.
func ParseHops(raw string, forward Dialer, opts *ChainOptions) ([]Hop, error) {
	if opts == nil {
		opts = &ChainOptions{}
	}
	p := &hopParser{opts: opts, res: resolverFor(opts.SSHConfig)}
	return p.parse(raw, forward, 0)
}

type hopParser struct {
	opts *ChainOptions
	res  *sshconfig.Resolver // nil when ssh config lookup is off
}

func resolverFor(path string) *sshconfig.Resolver {
	switch {
	case strings.EqualFold(path, "none"):
		return nil
	case path == "":
		return sshconfig.Default(pathx.Home(), currentUser())
	default:
		return &sshconfig.Resolver{Files: []string{pathx.ExpandHome(path)}, Home: pathx.Home(), LocalUser: currentUser()}
	}
}

func (p *hopParser) parse(raw string, forward Dialer, depth int) ([]Hop, error) {
	if !strings.Contains(raw, "://") {
		// A bare name works when ssh config knows it, like `ssh myalias`.
		if p.res == nil || !p.res.HasHost(bareHost(raw)) {
			return nil, fmt.Errorf("%q: want scheme://host:port, or a Host from ~/.ssh/config", raw)
		}
		raw = "ssh://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w (URL-encode special characters in the password, or use passenv=VAR)", redact(raw), err)
	}
	q := u.Query()

	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks", "socks5h":
		scheme = "socks5"
	case "https":
		return nil, errors.New("https:// proxies are not supported, use http:// (CONNECT)")
	}
	defPort, ok := defaultPorts[scheme]
	if !ok {
		return nil, fmt.Errorf("unknown scheme %q (want socks5, http or ssh)", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("%s: missing host", u.Redacted())
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	if q.Has("passenv") {
		if password, err = readEnv("passenv", q.Get("passenv")); err != nil {
			return nil, err
		}
	}

	if scheme == "ssh" {
		return p.parseSSH(host, u.Port(), username, password, q, forward, depth)
	}

	port := u.Port()
	if port == "" {
		port = defPort
	}
	addr := net.JoinHostPort(host, port)
	h := Hop{Scheme: scheme, Addr: addr, User: username, Label: scheme + "://" + addr}
	if username != "" {
		h.Label = scheme + "://" + username + "@" + addr
	}
	switch scheme {
	case "socks5":
		h.Dialer = &SOCKS5Dialer{Addr: addr, Username: username, Password: password, Forward: forward, Ask: p.opts.Credentials}
	case "http":
		h.Dialer = &HTTPDialer{Addr: addr, Username: username, Password: password, Forward: forward, Ask: p.opts.Credentials}
	}
	return []Hop{h}, nil
}

// parseSSH builds an ssh hop. port and username are "" when the URL
// doesn't give them, so ssh config can fill them in.
func (p *hopParser) parseSSH(host, port, username, password string, q url.Values, forward Dialer, depth int) ([]Hop, error) {
	res := p.res
	if q.Has("ssh_config") {
		res = resolverFor(q.Get("ssh_config"))
	}
	var sc *sshconfig.Settings
	hostname := host
	if res != nil {
		var err error
		if sc, err = res.Resolve(host, username, port); err != nil {
			return nil, err
		}
		for _, w := range sc.Warnings {
			p.opts.Log.logf(LevelWarn, "ssh config: %s", w)
		}
		hostname, port, username = sc.HostName, sc.Port, sc.User
	}
	if port == "" {
		port = "22"
	}
	if username == "" {
		username = currentUser()
	}
	addr := net.JoinHostPort(hostname, port)

	var hops []Hop
	if sc != nil {
		jump, cmd := sc.ProxyJump, sc.ProxyCommand
		switch {
		case jump != "" && !strings.EqualFold(jump, "none"):
			if depth >= maxJumps {
				return nil, fmt.Errorf("ssh config: ProxyJump for %s nests more than %d deep (a loop?)", host, maxJumps)
			}
			// Jump hosts use the same config file, and their own
			// ProxyJump settings, but none of this hop's URL options.
			jp := &hopParser{opts: p.opts, res: res}
			for _, j := range strings.Split(jump, ",") {
				j = strings.TrimSpace(j)
				if j == "" {
					continue
				}
				if !strings.Contains(j, "://") {
					j = "ssh://" + j
				}
				jh, err := jp.parse(j, forward, depth+1)
				if err != nil {
					return nil, fmt.Errorf("ProxyJump %s for %s: %w", j, host, err)
				}
				hops = append(hops, jh...)
				forward = jh[len(jh)-1].Dialer
			}
		case cmd != "" && !strings.EqualFold(cmd, "none"):
			if forward != Direct {
				return nil, fmt.Errorf("ssh config for %s uses ProxyCommand, which can't run behind another hop; make it the first -F, or use ProxyJump", host)
			}
			p.opts.Log.logf(LevelDebug, "ssh %s: via ProxyCommand %s", host, cmd)
			forward = &CommandDialer{Command: cmd, Log: p.opts.Log}
		}
	}

	label := "ssh://" + username + "@" + addr
	if hostname != host {
		// Show the alias the user typed; the dashboard shows the real address.
		label = "ssh://" + username + "@" + host
	}
	h := Hop{Scheme: "ssh", Addr: addr, User: username, Label: label}

	ask := p.opts.Credentials != nil
	cfg, err := sshClientConfig(username, password, q, sc, p.opts.Log, ask)
	if err != nil {
		if hostname != host {
			err = fmt.Errorf("%s: %w", host, err)
		}
		return nil, err
	}
	d := &SSHDialer{Addr: addr, Config: cfg, Forward: forward, KeepAlive: p.opts.SSHKeepAlive, Log: p.opts.Log}
	if ask {
		// The dialer tries the password first and asks when it's
		// missing or wrong.
		d.Ask, d.Password = p.opts.Credentials, password
	}
	h.Dialer = d
	return append(hops, h), nil
}

// bareHost pulls the host out of "[user@]host[:port]".
func bareHost(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
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

// sshClientConfig builds the client config. With prompt set, password auth
// is left to SSHDialer.Ask so it can be asked for and retried. sc is the
// host's ssh config, or nil.
func sshClientConfig(username, password string, q url.Values, sc *sshconfig.Settings, log LogFunc, prompt bool) (*ssh.ClientConfig, error) {
	if sc == nil {
		sc = &sshconfig.Settings{}
	}
	cfg := &ssh.ClientConfig{User: username, Timeout: DefaultHandshakeTimeout}
	if sc.ConnectTimeout > 0 {
		cfg.Timeout = sc.ConnectTimeout
	}
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
	// Public halves of the identities, so IdentitiesOnly can still use an
	// encrypted key that ssh-agent holds unlocked.
	allowed := map[string]bool{}
	addKey := func(s ssh.Signer, pub ssh.PublicKey) {
		if s != nil {
			signers = append(signers, s)
			pub = s.PublicKey()
		}
		if pub != nil {
			allowed[string(pub.Marshal())] = true
		}
	}

	keyFiles := q["key"]
	for _, p := range keyFiles {
		s, err := loadKey(pathx.ExpandHome(p), passphrase)
		if err != nil {
			return nil, err
		}
		addKey(s, nil)
	}
	// IdentityFile entries are tried like ssh does: a missing file is
	// skipped, and an encrypted one is used through the agent if it's there.
	for _, p := range sc.IdentityFiles {
		s, pub, err := loadKeySoft(p, passphrase)
		switch {
		case err == nil:
			addKey(s, pub)
		case errors.Is(err, os.ErrNotExist):
			log.logf(LevelDebug, "ssh config: IdentityFile %s not found, skipping", p)
		default:
			log.logf(LevelWarn, "ssh config: IdentityFile %s: %v", p, err)
		}
	}
	// With nothing explicit, try the usual default keys like ssh does.
	if len(keyFiles) == 0 && len(sc.IdentityFiles) == 0 && password == "" {
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			if s, pub, err := loadKeySoft(filepath.Join(pathx.Home(), ".ssh", name), passphrase); err == nil {
				addKey(s, pub)
			}
		}
	}

	var ag *sshAgent
	if sock := agentSocket(q, sc); sock != "" {
		ag = &sshAgent{sock: sock, log: log}
		if sc.IdentitiesOnly {
			ag.only = allowed
		}
	}
	if len(signers) > 0 || ag != nil {
		cfg.Auth = append(cfg.Auth, ssh.PublicKeysCallback(func() ([]ssh.Signer, error) {
			return slices.Concat(signers, ag.signers()), nil
		}))
	}
	if password != "" && !prompt {
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
	if len(cfg.Auth) == 0 && !prompt {
		return nil, errors.New("ssh: no auth available (set a password, key=PATH, or run ssh-agent)")
	}

	hk, err := hostKeyCallback(q, sc, log)
	if err != nil {
		return nil, err
	}
	cfg.HostKeyCallback = hk
	return cfg, nil
}

// agentSocket picks the ssh-agent socket: agent=0 turns it off, then the
// config's IdentityAgent, then $SSH_AUTH_SOCK.
func agentSocket(q url.Values, sc *sshconfig.Settings) string {
	if q.Get("agent") == "0" {
		return ""
	}
	switch sc.IdentityAgent {
	case "none":
		return ""
	case "", "SSH_AUTH_SOCK":
		return os.Getenv("SSH_AUTH_SOCK")
	default:
		return sc.IdentityAgent
	}
}

// sshAgent is a lazily dialed ssh-agent connection. It stays open because
// agent signers sign through it during the handshake.
type sshAgent struct {
	sock string
	log  LogFunc
	only map[string]bool // with IdentitiesOnly: the keys that may be offered

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
			if a.only != nil {
				s = slices.DeleteFunc(s, func(k ssh.Signer) bool { return !a.only[string(k.PublicKey().Marshal())] })
			}
			return s
		}
		// The agent may have restarted; reconnect once.
		a.conn.Close()
		a.conn, a.client = nil, nil
	}
	return nil
}

func hostKeyCallback(q url.Values, sc *sshconfig.Settings, log LogFunc) (ssh.HostKeyCallback, error) {
	if sc == nil {
		sc = &sshconfig.Settings{}
	}
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

	// StrictHostKeyChecking no/accept-new: trust a host we've never seen,
	// but still refuse one whose key changed.
	acceptNew := false
	switch sc.StrictHostKeyChecking {
	case "no", "off", "false", "accept-new":
		acceptNew = true
	}

	var files []string
	if p := q.Get("known_hosts"); p != "" {
		p = pathx.ExpandHome(p)
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("ssh: can't read %s: %w (pass hostkey=SHA256:... or insecure=1)", p, err)
		}
		files = []string{p}
	} else {
		user := sc.UserKnownHostsFiles
		if len(user) == 0 {
			user = []string{
				filepath.Join(pathx.Home(), ".ssh", "known_hosts"),
				filepath.Join(pathx.Home(), ".ssh", "known_hosts2"),
			}
		}
		global := sc.GlobalKnownHostsFiles
		if len(global) == 0 {
			global = []string{"/etc/ssh/ssh_known_hosts", "/etc/ssh/ssh_known_hosts2"}
		}
		for _, f := range slices.Concat(user, global) {
			if _, err := os.Stat(f); err == nil {
				files = append(files, f)
			}
		}
	}

	var kh ssh.HostKeyCallback
	if len(files) > 0 {
		var err error
		if kh, err = knownhosts.New(files...); err != nil {
			return nil, fmt.Errorf("ssh: can't read %s: %w (pass hostkey=SHA256:... or insecure=1)", strings.Join(files, ", "), err)
		}
	} else if !acceptNew {
		path := filepath.Join(pathx.Home(), ".ssh", "known_hosts")
		if len(sc.UserKnownHostsFiles) > 0 {
			path = sc.UserKnownHostsFiles[0]
		}
		return nil, fmt.Errorf("ssh: can't read %s: %w (pass hostkey=SHA256:... or insecure=1)", path, os.ErrNotExist)
	}

	return func(host string, remote net.Addr, key ssh.PublicKey) error {
		if sc.HostKeyAlias != "" {
			// known_hosts entries for an alias are stored without a port.
			host = net.JoinHostPort(sc.HostKeyAlias, "22")
		}
		var err error
		if kh != nil {
			err = kh(host, remote, key)
		} else {
			err = &knownhosts.KeyError{}
		}
		var ke *knownhosts.KeyError
		if errors.As(err, &ke) && len(ke.Want) == 0 {
			fp := ssh.FingerprintSHA256(key)
			if acceptNew {
				log.logf(LevelWarn, "ssh %s: new host key %s accepted (StrictHostKeyChecking %s); it isn't saved", host, fp, sc.StrictHostKeyChecking)
				return nil
			}
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

// loadKeySoft loads a key ssh would try on its own. An encrypted key with no
// passphrase isn't an error: it returns just the public key (from the key
// itself or PATH.pub) so a matching ssh-agent key can be used instead.
func loadKeySoft(path, passphrase string) (ssh.Signer, ssh.PublicKey, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	s, err := ssh.ParsePrivateKey(pem)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase != "" {
			if s, err = ssh.ParsePrivateKeyWithPassphrase(pem, []byte(passphrase)); err == nil {
				return s, nil, nil
			}
		}
		pub := missing.PublicKey
		if pub == nil {
			if b, rerr := os.ReadFile(path + ".pub"); rerr == nil {
				pub, _, _, _, _ = ssh.ParseAuthorizedKey(b)
			}
		}
		return nil, pub, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return s, nil, nil
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
