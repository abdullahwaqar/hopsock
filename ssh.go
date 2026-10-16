package hopsock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHDialer opens connections as SSH "direct-tcpip" channels (what
// `ssh -D` does). One SSH session is shared by all connections and is
// re-established on demand if it drops.
type SSHDialer struct {
	Addr      string            // ssh server "host:port"
	Config    *ssh.ClientConfig // user, auth, host key check
	Forward   Dialer            // how to reach the ssh server; nil means Direct
	KeepAlive time.Duration     // 0 means 30s, negative disables
	Log       LogFunc

	// Ask, if set, is offered as password and keyboard-interactive auth after
	// Config.Auth. Password is tried first without asking. A password that
	// works is reused when the session reconnects.
	Ask      CredentialsFunc
	Password string

	mu         sync.Mutex
	client     *ssh.Client
	since      time.Time
	lastErr    error
	connecting *sshConnect

	pwMu       sync.Mutex
	pwInit     bool
	pw         string
	pwDeclined bool
	prompting  bool
}

// sshConnect is one in-flight connection attempt shared by every caller
// that needs the session while it's being set up.
type sshConnect struct {
	done   chan struct{}
	client *ssh.Client
	err    error
}

// SSHState describes the shared session.
type SSHState struct {
	Connected bool
	Since     time.Time
	LastErr   error
}

// State reports whether the session is up.
func (d *SSHDialer) State() SSHState {
	d.mu.Lock()
	defer d.mu.Unlock()
	return SSHState{Connected: d.client != nil, Since: d.since, LastErr: d.lastErr}
}

// Prompting reports whether the dialer is waiting on Ask right now.
func (d *SSHDialer) Prompting() bool {
	d.pwMu.Lock()
	defer d.pwMu.Unlock()
	return d.prompting
}

// ResetPrompt lets Ask be called again after it was declined.
func (d *SSHDialer) ResetPrompt() {
	d.pwMu.Lock()
	d.pwDeclined = false
	d.pwMu.Unlock()
}

// Connect establishes the session now instead of on first use.
func (d *SSHDialer) Connect(ctx context.Context) error {
	_, _, err := d.session(ctx)
	return err
}

// Close tears down the session. The next dial reconnects.
func (d *SSHDialer) Close() error {
	d.mu.Lock()
	c := d.client
	d.client = nil
	d.mu.Unlock()
	if c != nil {
		return c.Close()
	}
	return nil
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := checkTCP(network); err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		c, fresh, err := d.session(ctx)
		if err != nil {
			return nil, err
		}
		conn, err := c.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		// The server refused this one channel (e.g. target unreachable):
		// the session itself is fine.
		var oce *ssh.OpenChannelError
		if errors.As(err, &oce) || ctx.Err() != nil || fresh || attempt > 0 {
			return nil, fmt.Errorf("ssh %s -> %s: %w", d.Addr, addr, err)
		}
		// Session looked alive but wasn't. Drop it and retry once.
		d.Log.logf(LevelWarn, "ssh %s: session went stale (%v), reconnecting", d.Addr, err)
		d.drop(c, err)
	}
}

// session returns the live client, connecting if needed. fresh is true
// when the client was set up during this call.
//
// The handshake runs detached from ctx: it may wait on a password prompt,
// and one caller giving up shouldn't abort it for everyone else.
func (d *SSHDialer) session(ctx context.Context) (c *ssh.Client, fresh bool, err error) {
	d.mu.Lock()
	if d.client != nil {
		c = d.client
		d.mu.Unlock()
		return c, false, nil
	}
	if d.Config == nil {
		d.mu.Unlock()
		return nil, false, errors.New("ssh: no ClientConfig")
	}
	call := d.connecting
	if call == nil {
		call = &sshConnect{done: make(chan struct{})}
		d.connecting = call
		go d.connect(call)
	}
	d.mu.Unlock()

	select {
	case <-call.done:
	case <-ctx.Done():
		return nil, false, ctx.Err()
	}
	if call.err != nil {
		return nil, false, call.err
	}
	return call.client, true, nil
}

func (d *SSHDialer) connect(call *sshConnect) {
	c, err := d.handshake()
	d.mu.Lock()
	d.connecting = nil
	if err != nil {
		d.lastErr = err
		err = fmt.Errorf("ssh %s: %w", d.Addr, err)
	} else {
		d.client, d.since, d.lastErr = c, time.Now(), nil
	}
	call.client, call.err = c, err
	d.mu.Unlock()
	close(call.done)
	if c == nil {
		return
	}
	closed := make(chan struct{})
	go func() {
		err := c.Wait()
		close(closed)
		d.drop(c, err)
	}()
	go d.keepalive(c, closed)
}

func (d *SSHDialer) handshake() (*ssh.Client, error) {
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	start := time.Now()
	d.Log.logf(LevelInfo, "ssh %s: connecting as %s", d.Addr, d.Config.User)
	timeout := d.Config.Timeout
	if timeout <= 0 {
		timeout = DefaultHandshakeTimeout
	}
	dctx, cancel := context.WithTimeout(context.Background(), timeout)
	raw, err := fwd.DialContext(dctx, "tcp", d.Addr)
	cancel()
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(timeout))
	cfg := d.Config
	if d.Ask != nil {
		cp := *d.Config
		cp.Auth = append(slices.Clone(cp.Auth), d.promptAuth(raw, timeout)...)
		cfg = &cp
	}
	sc, chans, reqs, err := ssh.NewClientConn(raw, d.Addr, cfg)
	if err != nil {
		raw.Close()
		return nil, err
	}
	_ = raw.SetDeadline(time.Time{})
	d.Log.logf(LevelInfo, "ssh %s: session up in %s (server %s)", d.Addr,
		time.Since(start).Round(time.Millisecond), sc.ServerVersion())
	return ssh.NewClient(sc, chans, reqs), nil
}

// promptAuth builds password and keyboard-interactive methods for one
// handshake. The first answer is the remembered password, if any; after
// that it asks. The handshake deadline is paused while a prompt is open.
func (d *SSHDialer) promptAuth(raw net.Conn, timeout time.Duration) []ssh.AuthMethod {
	tries := 0
	hop := "ssh://" + d.Config.User + "@" + d.Addr
	ask := func(retry bool, question string) (string, error) {
		d.pwMu.Lock()
		d.prompting = true
		d.pwMu.Unlock()
		_ = raw.SetDeadline(time.Time{})
		_, p, err := d.Ask(context.Background(), CredRequest{
			Hop: hop, Scheme: "ssh", Addr: d.Addr, User: d.Config.User,
			Retry: retry, Prompt: question,
		})
		_ = raw.SetDeadline(time.Now().Add(timeout))
		d.pwMu.Lock()
		d.prompting = false
		d.pwMu.Unlock()
		return p, err
	}
	password := func(question string) (string, error) {
		d.pwMu.Lock()
		if !d.pwInit {
			d.pw, d.pwInit = d.Password, true
		}
		cached, declined := d.pw, d.pwDeclined
		tries++
		if tries == 1 && cached != "" {
			d.pwMu.Unlock()
			return cached, nil
		}
		d.pwMu.Unlock()
		if declined {
			return "", ErrPromptCanceled
		}

		p, err := ask(tries > 1, question)

		d.pwMu.Lock()
		if err != nil {
			d.pwDeclined = true
		} else {
			d.pw = p
		}
		d.pwMu.Unlock()
		return p, err
	}
	return []ssh.AuthMethod{
		ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) { return password("") }), maxAuthPrompts),
		ssh.RetryableAuthMethod(ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
			answers := make([]string, len(questions))
			for i, q := range questions {
				// A lone hidden question is the password; anything else
				// (OTP codes, ...) is asked as is and not remembered.
				if len(questions) == 1 && !echos[i] {
					a, err := password(q)
					if err != nil {
						return nil, err
					}
					answers[i] = a
					continue
				}
				a, err := ask(false, q)
				if err != nil {
					return nil, err
				}
				answers[i] = a
			}
			return answers, nil
		}), maxAuthPrompts),
	}
}

func (d *SSHDialer) drop(c *ssh.Client, cause error) {
	d.mu.Lock()
	mine := d.client == c
	if mine {
		d.client = nil
		if cause != nil {
			d.lastErr = cause
		}
	}
	d.mu.Unlock()
	c.Close()
	if mine {
		d.Log.logf(LevelWarn, "ssh %s: session closed (%v); will reconnect on next request", d.Addr, cause)
	}
}

func (d *SSHDialer) keepalive(c *ssh.Client, closed <-chan struct{}) {
	iv := d.KeepAlive
	if iv < 0 {
		return
	}
	if iv == 0 {
		iv = 30 * time.Second
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-closed:
			return
		case <-t.C:
		}
		errc := make(chan error, 1)
		go func() {
			_, _, err := c.SendRequest("keepalive@openssh.com", true, nil)
			errc <- err
		}()
		select {
		case err := <-errc:
			if err != nil {
				d.drop(c, fmt.Errorf("keepalive: %w", err))
				return
			}
		case <-time.After(15 * time.Second):
			d.drop(c, errors.New("keepalive timed out"))
			return
		case <-closed:
			return
		}
	}
}
