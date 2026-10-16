package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/term"

	"github.com/abdullahwaqar/hopsock"
)

// prompter answers hopsock.CredentialsFunc calls: through the TUI while it
// runs, otherwise on the terminal.
type prompter struct {
	in  *os.File
	out io.Writer

	serial sync.Mutex // one prompt on screen at a time

	mu       sync.Mutex
	send     func(tea.Msg) // set while the TUI runs
	closed   bool
	done     chan struct{}
	ttyState *term.State // terminal state to put back if we exit mid-prompt
}

type credReply struct {
	user, pass string
	err        error
}

// credAskMsg asks the TUI to show a login form.
type credAskMsg struct {
	req   hopsock.CredRequest
	reply chan credReply
}

func newPrompter(in *os.File, out io.Writer) *prompter {
	return &prompter{in: in, out: out, done: make(chan struct{})}
}

// attach routes prompts to a running TUI.
func (p *prompter) attach(send func(tea.Msg)) {
	p.mu.Lock()
	p.send = send
	p.mu.Unlock()
}

// close cancels the open prompt and any later ones, and puts terminal echo
// back if a password read was in progress. Called on shutdown; safe to call
// more than once.
func (p *prompter) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		close(p.done)
	}
	if p.ttyState != nil {
		_ = term.Restore(p.in.Fd(), p.ttyState)
		p.ttyState = nil
		fmt.Fprintln(p.out)
	}
}

func (p *prompter) ask(_ context.Context, req hopsock.CredRequest) (string, string, error) {
	p.serial.Lock()
	defer p.serial.Unlock()

	p.mu.Lock()
	send, closed := p.send, p.closed
	p.mu.Unlock()
	if closed {
		return "", "", hopsock.ErrPromptCanceled
	}
	if send != nil {
		reply := make(chan credReply, 1)
		go send(credAskMsg{req: req, reply: reply})
		select {
		case r := <-reply:
			return r.user, r.pass, r.err
		case <-p.done:
			return "", "", hopsock.ErrPromptCanceled
		}
	}
	return p.askTerminal(req)
}

// askTerminal reads a username and a hidden password from the terminal.
// An empty answer skips.
func (p *prompter) askTerminal(req hopsock.CredRequest) (string, string, error) {
	fd := p.in.Fd()
	state, err := term.GetState(fd)
	if err != nil {
		return "", "", fmt.Errorf("no terminal to ask for %s credentials", req.Hop)
	}
	p.mu.Lock()
	p.ttyState = state
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.ttyState = nil
		p.mu.Unlock()
	}()

	type result struct {
		user, pass string
		err        error
	}
	res := make(chan result, 1)
	go func() {
		var r result
		fmt.Fprintln(p.out)
		fmt.Fprintln(p.out, credHeadline(req))
		if req.Retry {
			fmt.Fprintln(p.out, "  that was rejected, try again")
		}
		fmt.Fprintln(p.out, "  (leave empty to skip)")
		r.user = req.User
		if req.NeedUser {
			q := "  username: "
			if req.User != "" {
				q = fmt.Sprintf("  username [%s]: ", req.User)
			}
			fmt.Fprint(p.out, q)
			line, err := readLine(p.in)
			if err != nil {
				r.err = err
				res <- r
				return
			}
			if line != "" {
				r.user = line
			}
			if r.user == "" {
				r.err = hopsock.ErrPromptCanceled
				res <- r
				return
			}
		}
		fmt.Fprint(p.out, "  "+passwordLabel(req)+": ")
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(p.out)
		if err != nil {
			r.err = err
		} else if len(pw) == 0 {
			r.err = hopsock.ErrPromptCanceled
		}
		r.pass = string(pw)
		res <- r
	}()

	select {
	case r := <-res:
		if r.err != nil && !errors.Is(r.err, hopsock.ErrPromptCanceled) {
			r.err = fmt.Errorf("%w: %w", hopsock.ErrPromptCanceled, r.err)
		}
		return r.user, r.pass, r.err
	case <-p.done:
		// Ctrl+C mid-prompt; close() already put echo back.
		return "", "", hopsock.ErrPromptCanceled
	}
}

// readLine reads up to a newline without buffering past it, so the hidden
// password read that follows sees the rest of the input.
func readLine(f *os.File) (string, error) {
	var b []byte
	var c [1]byte
	for {
		n, err := f.Read(c[:])
		if n == 1 {
			if c[0] == '\n' {
				break
			}
			b = append(b, c[0])
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(b) > 0 {
				break
			}
			return "", err
		}
	}
	return strings.TrimSpace(string(b)), nil
}

func credHeadline(req hopsock.CredRequest) string {
	switch {
	case req.Scheme == "ssh" && req.Prompt != "":
		return req.Hop + " asks: " + strings.TrimSpace(req.Prompt)
	case req.Scheme == "ssh":
		return req.Hop + " wants a password"
	case req.NeedUser:
		return req.Hop + " wants a username and password"
	default:
		return req.Hop + " wants the password for " + req.User
	}
}

func passwordLabel(req hopsock.CredRequest) string {
	if req.Scheme == "ssh" && req.Prompt != "" {
		return "answer"
	}
	return "password"
}
