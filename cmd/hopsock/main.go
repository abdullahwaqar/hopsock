// Command hopsock runs a local SOCKS5 proxy that forwards through a chain of
// upstream hops (SOCKS5, HTTP CONNECT, SSH), with a terminal dashboard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/abdullahwaqar/hopsock"
)

type hopList []string

func (h *hopList) String() string     { return strings.Join(*h, ",") }
func (h *hopList) Set(v string) error { *h = append(*h, v); return nil }

type config struct {
	listen    string
	localUser string
	localPass string
	hops      hopList
	testURL   string
	browser   string
	profile   string
	execCmd   string
	plain     bool
	verbose   bool
	keepAlive time.Duration
	stay      bool
}

const usageText = `hopsock: a local SOCKS5 proxy that tunnels through SOCKS5, HTTP and SSH hops

Usage:
  hopsock [flags]

Examples:
  # SSH dynamic forward, like ssh -D 1080 me@server
  hopsock -F ssh://me@server.example.com

  # Authenticated upstream SOCKS5, then open Vivaldi through it
  # (or leave out -browser and press b in the TUI to pick a browser)
  export PROXY_PASS='...'
  hopsock -F 'socks5://user@proxy.example.com:10001?passenv=PROXY_PASS' -browser vivaldi-stable

  # Chain: reach the SSH box through the SOCKS5 proxy, exit from the SSH box
  hopsock -F 'socks5://user@proxy:1080?passenv=PROXY_PASS' -F 'ssh://me@box?key=~/.ssh/id_ed25519'

Hop URLs (-F, repeatable, the first hop is dialed directly):
  socks5://[user[:pass]@]host[:1080]     also socks5h:// and socks://
  http://[user[:pass]@]host[:8080]       HTTP CONNECT proxy
  ssh://[user[:pass]@]host[:22]          SSH direct-tcpip, like ssh -D
  All:  passenv=VAR   read the password from $VAR (no URL-encoding needed)
  SSH:  key=PATH  keypassenv=VAR  agent=0  known_hosts=PATH
        hostkey=SHA256:...  insecure=1  timeout=20s

Flags:
`

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := parseFlags(os.Args[1:])
	if errors.Is(err, errVersion) {
		fmt.Println("hopsock", versionString())
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "hopsock:", err)
		return 2
	}

	useTUI := !cfg.plain && isTerminal(os.Stdout) && isTerminal(os.Stdin)
	logs := newLogBus(useTUI, cfg.verbose)

	chain, err := hopsock.NewChain(cfg.hops, &hopsock.ChainOptions{Log: logs.Log, SSHKeepAlive: cfg.keepAlive})
	if err != nil {
		fmt.Fprintln(os.Stderr, "hopsock:", err)
		return 2
	}
	defer chain.Close()

	stats := &hopsock.Stats{}
	srv := &hopsock.Server{
		Addr:     cfg.listen,
		Username: cfg.localUser,
		Password: cfg.localPass,
		Dialer:   chain,
		Log:      logs.Log,
		Stats:    stats,
	}
	ln, err := srv.Listen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "hopsock: listen %s: %v\n", cfg.listen, err)
		return 1
	}
	proxyAddr := dialableAddr(ln.Addr().String())

	a := &app{cfg: cfg, proxyAddr: proxyAddr, chain: chain, stats: stats, logs: logs, started: time.Now()}
	switch {
	case cfg.browser != "":
		if cfg.localUser != "" {
			logs.Log(hopsock.LevelWarn, "Chromium browsers can't do SOCKS5 auth, so the browser will fail against a password-protected -L")
		}
		a.launch = browserLauncher(cfg.browser, cfg.profile, proxyAddr)
	case cfg.execCmd != "":
		a.launch = execLauncher(cfg.execCmd, proxyAddr)
	}
	defer a.stopLaunched()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(ctx, ln) }()

	code := 0
	if useTUI {
		p := tea.NewProgram(newModel(a), tea.WithAltScreen())
		context.AfterFunc(ctx, p.Quit)
		if _, err := p.Run(); err != nil {
			fmt.Fprintln(os.Stderr, "hopsock: tui:", err)
			code = 1
		}
	} else {
		code = runPlain(ctx, a)
	}

	stop()
	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
	}
	snap := stats.Snapshot()
	fmt.Fprintf(os.Stderr, "hopsock: %d connections (%d failed), %s up, %s down, ran %s\n",
		snap.Total, snap.Failed, humanBytes(snap.Up), humanBytes(snap.Down), humanDur(time.Since(a.started)))
	return code
}

var errVersion = errors.New("version requested")

func parseFlags(args []string) (config, error) {
	var cfg config
	var listen string
	var showVersion bool
	fs := flag.NewFlagSet("hopsock", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usageText)
		fs.PrintDefaults()
	}
	fs.StringVar(&listen, "L", "127.0.0.1:1080", "local listen `addr`: 127.0.0.1:1080, a bare port, or socks5://user:pass@127.0.0.1:1080")
	fs.Var(&cfg.hops, "F", "upstream hop `url` (repeat for a chain, outermost first)")
	fs.StringVar(&cfg.testURL, "test", "https://ipinfo.io/json", "`url` fetched through the chain at startup; \"off\" to skip")
	fs.StringVar(&cfg.browser, "browser", "", "open a Chromium-based browser `binary` through the proxy once the test passes (vivaldi-stable, google-chrome, ...)")
	fs.StringVar(&cfg.profile, "profile", "", "pass --user-data-dir=`dir` to the browser for a separate instance; without it the browser must not already be running")
	fs.StringVar(&cfg.execCmd, "exec", "", "run `command` (via sh -c) once the proxy is ready; {addr} becomes the proxy address")
	fs.BoolVar(&cfg.stay, "stay", false, "keep running after the -browser/-exec process exits")
	fs.BoolVar(&cfg.plain, "plain", false, "no TUI, log to stderr")
	fs.BoolVar(&cfg.verbose, "v", false, "per-connection log lines")
	fs.DurationVar(&cfg.keepAlive, "keepalive", 30*time.Second, "SSH keepalive `interval` (0 disables)")
	fs.BoolVar(&showVersion, "version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		return cfg, err
	}
	if showVersion {
		return cfg, errVersion
	}
	if fs.NArg() > 0 {
		return cfg, fmt.Errorf("unexpected argument %q (hops go after -F)", fs.Arg(0))
	}
	if err := parseListen(listen, &cfg); err != nil {
		return cfg, fmt.Errorf("-L: %w", err)
	}
	if cfg.browser != "" && cfg.execCmd != "" {
		return cfg, errors.New("use either -browser or -exec, not both")
	}
	if strings.EqualFold(cfg.testURL, "off") || strings.EqualFold(cfg.testURL, "none") {
		cfg.testURL = ""
	}
	if cfg.keepAlive == 0 {
		cfg.keepAlive = -1 // SSHDialer treats 0 as "default", negative as off
	}
	return cfg, nil
}

// app is state shared by the TUI and plain modes.
type app struct {
	cfg       config
	proxyAddr string
	chain     *hopsock.Chain
	stats     *hopsock.Stats
	logs      *logBus
	launch    *launcher   // from -browser or -exec
	manual    []*launcher // opened from the TUI picker
	started   time.Time
}

func (a *app) preflight(ctx context.Context) (*hopsock.ExitInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	return hopsock.Preflight(ctx, a.chain, a.cfg.testURL)
}

func (a *app) stopLaunched() {
	a.launch.stop()
	for _, l := range a.manual {
		l.stop()
	}
}

func runPlain(ctx context.Context, a *app) int {
	a.logs.Log(hopsock.LevelInfo, "route: "+routeText(a))
	if a.cfg.testURL != "" {
		a.logs.Log(hopsock.LevelInfo, "testing chain via "+a.cfg.testURL)
		info, err := a.preflight(ctx)
		if err != nil {
			a.logs.Log(hopsock.LevelError, "preflight failed: "+err.Error())
			return 1
		}
		a.logs.Log(hopsock.LevelInfo, "exit "+exitText(info))
	}
	if a.launch == nil {
		a.logs.Log(hopsock.LevelInfo, "ready, Ctrl+C to stop")
		<-ctx.Done()
		return 0
	}
	done, err := a.launch.start(a.logs.Log)
	if err != nil {
		a.logs.Log(hopsock.LevelError, err.Error())
		return 1
	}
	select {
	case err := <-done:
		a.logs.Log(hopsock.LevelInfo, a.launch.name+" exited"+errSuffix(err))
		if a.cfg.stay {
			<-ctx.Done()
		}
	case <-ctx.Done():
	}
	return 0
}

func parseListen(s string, cfg *config) error {
	if !strings.Contains(s, "://") {
		if _, err := strconv.Atoi(s); err == nil {
			s = net.JoinHostPort("127.0.0.1", s)
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			return err
		}
		cfg.listen = s
		return nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "socks5", "socks5h", "socks":
	default:
		return fmt.Errorf("only socks5:// listeners are supported, got %s://", u.Scheme)
	}
	cfg.listen = u.Host
	if u.Port() == "" {
		cfg.listen = net.JoinHostPort(u.Hostname(), "1080")
	}
	cfg.localUser = u.User.Username()
	cfg.localPass, _ = u.User.Password()
	return nil
}

// dialableAddr turns a wildcard listen address like 0.0.0.0:1080 into one
// local clients can connect to.
func dialableAddr(a string) string {
	host, port, err := net.SplitHostPort(a)
	if err != nil {
		return a
	}
	if ip := net.ParseIP(host); ip == nil || ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func errSuffix(err error) string {
	if err == nil {
		return ""
	}
	var ee interface{ ExitCode() int }
	if errors.As(err, &ee) {
		return fmt.Sprintf(" (code %d)", ee.ExitCode())
	}
	return " (" + err.Error() + ")"
}
