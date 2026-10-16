package hopsock

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrAuthRequired means a proxy wants a username and password and none
	// were configured.
	ErrAuthRequired = errors.New("proxy wants a username and password")
	// ErrAuthFailed means a proxy rejected the username or password.
	ErrAuthFailed = errors.New("authentication failed (bad username or password)")
	// ErrPromptCanceled is what a CredentialsFunc returns when the user
	// declines to enter credentials.
	ErrPromptCanceled = errors.New("credential prompt canceled")
)

// CredRequest describes a hop that needs credentials.
type CredRequest struct {
	Hop      string // display form, e.g. socks5://proxy.example.com:1080
	Scheme   string // "socks5", "http" or "ssh"
	Addr     string // host:port
	User     string // username known so far, may be empty
	NeedUser bool   // false when only a password is wanted
	Retry    bool   // the previous credentials were rejected
	Prompt   string // server-supplied question (SSH keyboard-interactive), optional
}

// CredentialsFunc is asked for a username and password when a hop needs
// them and none were configured, or the configured ones were rejected. When
// NeedUser is false the returned user is ignored. Returning an error (such as
// ErrPromptCanceled) gives up; that hop then stops asking until ResetPrompts.
//
// Calls for one hop are never concurrent, and concurrent dials share one call.
type CredentialsFunc func(ctx context.Context, req CredRequest) (user, pass string, err error)

// credStore holds credentials that can be replaced at runtime, so many
// concurrent dials that hit an auth error trigger a single prompt.
type credStore struct {
	mu       sync.Mutex
	init     bool
	user     string
	pass     string
	gen      int // bumped on every change
	asking   chan struct{}
	lastErr  error
	declined bool
}

func (c *credStore) get(defUser, defPass string) (user, pass string, gen int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.init {
		c.user, c.pass, c.init = defUser, defPass, true
	}
	return c.user, c.pass, c.gen
}

// renew replaces the credentials seen at gen by asking for new ones. If
// another caller already replaced them it returns at once. The prompt runs
// detached from ctx so one impatient connection can't cancel it for all.
func (c *credStore) renew(ctx context.Context, gen int, ask func() (string, string, error)) error {
	c.mu.Lock()
	if c.gen != gen {
		c.mu.Unlock()
		return nil
	}
	if c.declined {
		c.mu.Unlock()
		return ErrPromptCanceled
	}
	ch := c.asking
	if ch == nil {
		ch = make(chan struct{})
		c.asking = ch
		go func() {
			u, p, err := ask()
			c.mu.Lock()
			if err == nil {
				c.user, c.pass = u, p
				c.gen++
			} else {
				c.declined = true
			}
			c.lastErr, c.asking = err, nil
			c.mu.Unlock()
			close(ch)
		}()
	}
	c.mu.Unlock()

	select {
	case <-ch:
	case <-ctx.Done():
		return ctx.Err()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gen != gen {
		return nil
	}
	if c.lastErr != nil {
		return c.lastErr
	}
	return ErrPromptCanceled
}

// reset lets a declined prompt be shown again.
func (c *credStore) reset() {
	c.mu.Lock()
	c.declined = false
	c.mu.Unlock()
}

// maxAuthPrompts bounds how often one dial re-asks after rejected credentials.
const maxAuthPrompts = 3

// dialWithPrompt runs dial with the stored credentials and, when this hop's
// own handshake reports ErrAuthRequired or ErrAuthFailed, asks for new ones
// and tries again. dial sets ours=false for errors from reaching the hop
// (earlier hops in the chain), which are never treated as this hop's auth.
func dialWithPrompt[T any](ctx context.Context, cs *credStore, ask CredentialsFunc, base CredRequest,
	defUser, defPass string, dial func(user, pass string) (out T, ours bool, err error),
) (T, error) {
	for attempt := 0; ; attempt++ {
		user, pass, gen := cs.get(defUser, defPass)
		out, ours, err := dial(user, pass)
		if err == nil || !ours || ask == nil || attempt >= maxAuthPrompts {
			return out, err
		}
		failed := errors.Is(err, ErrAuthFailed)
		if !failed && !errors.Is(err, ErrAuthRequired) {
			return out, err
		}
		req := base
		req.User = user
		req.NeedUser = defUser == ""
		// A username with no password "fails" on the first try; that's not
		// a rejection worth reporting.
		req.Retry = failed && pass != ""
		if rerr := cs.renew(ctx, gen, func() (string, string, error) {
			u, p, err := ask(context.Background(), req)
			if !req.NeedUser {
				u = req.User
			}
			return u, p, err
		}); rerr != nil {
			return out, err
		}
	}
}
