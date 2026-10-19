package hopsock

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// CommandDialer reaches an SSH server through a command's stdin and stdout,
// like OpenSSH's ProxyCommand. Every dial starts the command again. The
// addr passed to DialContext is ignored: the command already knows where to
// connect.
type CommandDialer struct {
	Command string // run with sh -c (cmd /C on Windows)
	Log     LogFunc
}

func (d *CommandDialer) DialContext(ctx context.Context, network, _ string) (net.Conn, error) {
	if err := checkTCP(network); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", d.Command)
	} else {
		cmd = exec.Command("sh", "-c", d.Command)
	}
	// Our own pipes rather than cmd.StdinPipe, so deadlines work on them.
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{inR, inW, outR, outW, errR, errW} {
			f.Close()
		}
		return nil, err
	}
	inR.Close()
	outW.Close()
	errW.Close()

	c := &cmdConn{cmd: cmd, in: inW, out: outR, exited: make(chan struct{})}
	go func() {
		sc := bufio.NewScanner(errR)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				d.Log.logf(LevelWarn, "proxy command: %s", line)
			}
		}
		errR.Close()
	}()
	go func() {
		c.waitErr = cmd.Wait()
		close(c.exited)
	}()
	return c, nil
}

// cmdConn is a net.Conn over a child process's stdin and stdout.
type cmdConn struct {
	cmd     *exec.Cmd
	in      *os.File
	out     *os.File
	exited  chan struct{}
	waitErr error
	once    sync.Once
}

func (c *cmdConn) Read(p []byte) (int, error) {
	n, err := c.out.Read(p)
	if err != nil && n == 0 {
		select {
		case <-c.exited:
			if c.waitErr != nil {
				return 0, errors.New("proxy command exited: " + c.waitErr.Error())
			}
		default:
		}
	}
	return n, err
}

func (c *cmdConn) Write(p []byte) (int, error) { return c.in.Write(p) }

func (c *cmdConn) Close() error {
	c.once.Do(func() {
		c.in.Close()
		c.out.Close()
		select {
		case <-c.exited:
		case <-time.After(2 * time.Second):
			_ = c.cmd.Process.Kill()
		}
	})
	return nil
}

// The addresses are zero TCP addresses, like an SSH channel's: host key
// checks parse RemoteAddr as host:port and use the hostname instead.
func (c *cmdConn) LocalAddr() net.Addr  { return &net.TCPAddr{IP: net.IPv4zero} }
func (c *cmdConn) RemoteAddr() net.Addr { return &net.TCPAddr{IP: net.IPv4zero} }

func (c *cmdConn) SetDeadline(t time.Time) error {
	return errors.Join(c.in.SetWriteDeadline(t), c.out.SetReadDeadline(t))
}
func (c *cmdConn) SetReadDeadline(t time.Time) error  { return c.out.SetReadDeadline(t) }
func (c *cmdConn) SetWriteDeadline(t time.Time) error { return c.in.SetWriteDeadline(t) }
