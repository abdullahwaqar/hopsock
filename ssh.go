package hopsock

import (
	"context"
	"errors"
	"fmt"
	"net"
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

	mu      sync.Mutex
	client  *ssh.Client
	since   time.Time
	lastErr error
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
// when this call created it.
func (d *SSHDialer) session(ctx context.Context) (c *ssh.Client, fresh bool, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.client != nil {
		return d.client, false, nil
	}
	if d.Config == nil {
		return nil, false, errors.New("ssh: no ClientConfig")
	}
	fwd := d.Forward
	if fwd == nil {
		fwd = Direct
	}
	start := time.Now()
	d.Log.logf(LevelInfo, "ssh %s: connecting as %s", d.Addr, d.Config.User)
	raw, err := fwd.DialContext(ctx, "tcp", d.Addr)
	if err != nil {
		d.lastErr = err
		return nil, false, fmt.Errorf("ssh %s: %w", d.Addr, err)
	}
	done := guardHandshake(ctx, raw)
	sc, chans, reqs, err := ssh.NewClientConn(raw, d.Addr, d.Config)
	done()
	if err != nil {
		raw.Close()
		d.lastErr = err
		return nil, false, fmt.Errorf("ssh %s: %w", d.Addr, err)
	}
	c = ssh.NewClient(sc, chans, reqs)
	d.client, d.since, d.lastErr = c, time.Now(), nil
	d.Log.logf(LevelInfo, "ssh %s: session up in %s (server %s)", d.Addr,
		time.Since(start).Round(time.Millisecond), sc.ServerVersion())

	closed := make(chan struct{})
	go func() {
		err := c.Wait()
		close(closed)
		d.drop(c, err)
	}()
	go d.keepalive(c, closed)
	return c, true, nil
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
