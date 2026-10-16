package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/abdullahwaqar/hopsock"
	"github.com/abdullahwaqar/hopsock/internal/pathx"
)

type appKind int

const (
	kindExec appKind = iota
	kindBrowser
	kindDiscord
)

// launcher runs a browser, Discord or -exec command through the proxy.
type launcher struct {
	name    string
	argv    []string // full argv; for -exec this is the shell invocation
	desc    string   // shown in the UI
	addr    string   // proxy host:port, exported as HOPSOCK_PROXY
	kind    appKind
	profile string // --user-data-dir, empty = the browser's normal profile

	mu  sync.Mutex
	cmd *exec.Cmd
}

// chromiumProxyArgs are the switches every Chromium or Electron launch gets.
func chromiumProxyArgs(proxyAddr string) []string {
	host, _, _ := strings.Cut(proxyAddr, ":")
	return []string{
		"--proxy-server=socks5://" + proxyAddr,
		// Force all DNS through the proxy; only the proxy itself resolves locally.
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE " + host,
		// Keep WebRTC from leaking your real IP around the proxy.
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
	}
}

// appLauncher picks the right launch for a browser or Discord binary.
func appLauncher(bin, profile, proxyAddr string) *launcher {
	if isDiscord(bin) {
		return discordLauncher(bin, proxyAddr)
	}
	return browserLauncher(bin, profile, proxyAddr)
}

// browserLauncher builds a Chromium-style launch. --user-data-dir is only
// passed when profile is set explicitly.
func browserLauncher(bin, profile, proxyAddr string) *launcher {
	argv := append([]string{bin}, chromiumProxyArgs(proxyAddr)...)
	name := browserName(bin)
	desc := name + " · your normal profile"
	if profile != "" {
		profile = pathx.ExpandHome(profile)
		argv = append(argv, "--user-data-dir="+profile, "--no-first-run", "--no-default-browser-check")
		desc = name + " · profile " + profile
	}
	return &launcher{name: name, argv: argv, addr: proxyAddr, desc: desc, kind: kindBrowser, profile: profile}
}

// discordLauncher starts the Discord desktop app, which is Electron and
// takes the same Chromium switches. Discord keeps its own data directory,
// so there's no separate-profile option: it has to be fully quit first.
func discordLauncher(bin, proxyAddr string) *launcher {
	argv := append([]string{bin}, chromiumProxyArgs(proxyAddr)...)
	name := discordName(bin)
	return &launcher{name: name, argv: argv, addr: proxyAddr, desc: name, kind: kindDiscord}
}

func isDiscord(bin string) bool {
	return strings.Contains(strings.ToLower(filepath.Base(bin)), "discord")
}

func discordName(bin string) string {
	l := strings.ToLower(filepath.Base(bin))
	switch {
	case strings.Contains(l, "canary"):
		return "Discord Canary"
	case strings.Contains(l, "ptb"):
		return "Discord PTB"
	}
	return "Discord"
}

func execLauncher(command, proxyAddr string) *launcher {
	command = strings.ReplaceAll(command, "{addr}", proxyAddr)
	argv := []string{"sh", "-c", command}
	if runtime.GOOS == "windows" {
		argv = []string{"cmd", "/C", command}
	}
	name := strings.Fields(command)[0]
	return &launcher{name: filepath.Base(name), argv: argv, addr: proxyAddr, desc: command}
}

// start launches the process. The returned channel gets its exit error.
func (l *launcher) start(log hopsock.LogFunc) (<-chan error, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.cmd != nil {
		return nil, fmt.Errorf("%s is already running", l.name)
	}
	if _, err := exec.LookPath(l.argv[0]); err != nil {
		return nil, fmt.Errorf("can't find %q", l.argv[0])
	}
	// Without its own profile, a Chromium browser that's already open just
	// opens a window in the existing (unproxied) instance and ignores our
	// flags. Discord does the same. Refuse rather than silently go around
	// the proxy.
	switch {
	case l.kind == kindBrowser && l.profile == "" && browserRunning(l.argv[0]):
		return nil, fmt.Errorf("%s is already running, so the proxy flags would be ignored. Close it fully first, or use -profile DIR for a separate instance", l.name)
	case l.kind == kindDiscord && browserRunning(l.argv[0]):
		return nil, fmt.Errorf("%s is already running, so the proxy flags would be ignored. Quit it fully first (right-click the tray icon, Quit Discord)", l.name)
	}
	cmd := exec.Command(l.argv[0], l.argv[1:]...)
	out := &lineWriter{prefix: l.name + ": ", log: log}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.Env = append(os.Environ(), "HOPSOCK_PROXY=socks5://"+l.addr)
	// Browsers fork helpers that inherit stdout; don't wait on them forever.
	cmd.WaitDelay = 2 * time.Second
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", l.name, err)
	}
	l.cmd = cmd
	log(hopsock.LevelInfo, fmt.Sprintf("launched %s (pid %d)", l.desc, cmd.Process.Pid))
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		l.mu.Lock()
		l.cmd = nil
		l.mu.Unlock()
		done <- err
	}()
	return done, nil
}

func (l *launcher) running() bool {
	if l == nil {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.cmd != nil
}

// stop asks the process to exit (SIGTERM; kill on Windows).
func (l *launcher) stop() {
	if l == nil {
		return
	}
	l.mu.Lock()
	cmd := l.cmd
	l.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
}

// ---------- browser discovery ----------

type browserInfo struct {
	Label string
	Path  string
	Kind  appKind
}

// detectApps lists installed browsers, then Discord.
func detectApps() []browserInfo {
	return append(detectBrowsers(), detectDiscord()...)
}

// appSet collects installs, skipping missing files and duplicates.
type appSet struct {
	out  []browserInfo
	seen map[string]bool
}

func (a *appSet) add(label, path string, kind appKind) {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return
	}
	if st, err := os.Stat(real); err != nil || st.IsDir() || a.seen[real] {
		return
	}
	if a.seen == nil {
		a.seen = map[string]bool{}
	}
	a.seen[real] = true
	a.out = append(a.out, browserInfo{Label: label, Path: path, Kind: kind})
}

// detectBrowsers finds installed Chromium-based browsers.
func detectBrowsers() []browserInfo {
	var set appSet
	add := func(label, path string) { set.add(label, path, kindBrowser) }

	switch runtime.GOOS {
	case "darwin":
		for _, a := range [][2]string{
			{"Vivaldi", "Vivaldi"}, {"Google Chrome", "Google Chrome"}, {"Chromium", "Chromium"},
			{"Brave Browser", "Brave Browser"}, {"Microsoft Edge", "Microsoft Edge"},
		} {
			for _, root := range []string{"/Applications", filepath.Join(pathx.Home(), "Applications")} {
				add(a[0], filepath.Join(root, a[0]+".app", "Contents", "MacOS", a[1]))
			}
		}
	case "windows":
		var roots []string
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if v := os.Getenv(env); v != "" {
				roots = append(roots, v)
			}
		}
		for _, b := range [][2]string{
			{"Vivaldi", `Vivaldi\Application\vivaldi.exe`},
			{"Google Chrome", `Google\Chrome\Application\chrome.exe`},
			{"Brave", `BraveSoftware\Brave-Browser\Application\brave.exe`},
			{"Microsoft Edge", `Microsoft\Edge\Application\msedge.exe`},
			{"Chromium", `Chromium\Application\chrome.exe`},
		} {
			for _, r := range roots {
				add(b[0], filepath.Join(r, b[1]))
			}
		}
	default:
		for _, bin := range []string{
			"vivaldi-stable", "vivaldi", "google-chrome-stable", "google-chrome", "chromium",
			"chromium-browser", "brave-browser", "brave", "microsoft-edge-stable", "microsoft-edge", "thorium-browser",
		} {
			if p, err := exec.LookPath(bin); err == nil {
				add(bin, p)
			}
		}
	}
	return set.out
}

// detectDiscord finds Discord desktop installs (stable, PTB, Canary).
func detectDiscord() []browserInfo {
	var set appSet
	add := func(label, path string) { set.add(label, path, kindDiscord) }
	variants := []struct{ label, mac, win string }{
		{"Discord", "Discord", "Discord"},
		{"Discord PTB", "Discord PTB", "DiscordPTB"},
		{"Discord Canary", "Discord Canary", "DiscordCanary"},
	}

	switch runtime.GOOS {
	case "darwin":
		for _, v := range variants {
			for _, root := range []string{"/Applications", filepath.Join(pathx.Home(), "Applications")} {
				add(v.label, filepath.Join(root, v.mac+".app", "Contents", "MacOS", v.mac))
			}
		}
	case "windows":
		// %LocalAppData%\Discord\app-1.0.9187\Discord.exe. Update.exe would
		// relaunch it without our flags, so run the newest app-* build directly.
		local := os.Getenv("LocalAppData")
		if local == "" {
			break
		}
		for _, v := range variants {
			if p := newestAppDir(filepath.Join(local, v.win)); p != "" {
				add(v.label, filepath.Join(p, v.win+".exe"))
			}
		}
	default:
		for _, b := range [][2]string{
			{"Discord", "discord"}, {"Discord", "Discord"},
			{"Discord PTB", "discord-ptb"}, {"Discord PTB", "discordptb"},
			{"Discord Canary", "discord-canary"}, {"Discord Canary", "discordcanary"},
		} {
			if p, err := exec.LookPath(b[1]); err == nil {
				add(b[0], p)
			}
		}
		for _, b := range [][2]string{
			{"Discord", "/opt/discord/Discord"},
			{"Discord", "/usr/share/discord/Discord"},
			{"Discord", "/usr/lib/discord/Discord"},
			{"Discord PTB", "/opt/discord-ptb/DiscordPTB"},
			{"Discord PTB", "/usr/share/discord-ptb/DiscordPTB"},
			{"Discord Canary", "/opt/discord-canary/DiscordCanary"},
			{"Discord Canary", "/usr/share/discord-canary/DiscordCanary"},
		} {
			add(b[0], b[1])
		}
		// Flatpak exports a wrapper script that forwards its arguments.
		for _, root := range []string{
			"/var/lib/flatpak/exports/bin",
			filepath.Join(pathx.Home(), ".local", "share", "flatpak", "exports", "bin"),
		} {
			add("Discord (Flatpak)", filepath.Join(root, "com.discordapp.Discord"))
			add("Discord Canary (Flatpak)", filepath.Join(root, "com.discordapp.DiscordCanary"))
		}
	}
	return set.out
}

// newestAppDir returns the app-x.y.z folder with the highest version under
// a Squirrel install root, or "".
func newestAppDir(root string) string {
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	var best string
	var bestV []int
	for _, e := range entries {
		v, ok := strings.CutPrefix(e.Name(), "app-")
		if !e.IsDir() || !ok {
			continue
		}
		ver := parseVersion(v)
		if best == "" || slices.Compare(ver, bestV) > 0 {
			best, bestV = filepath.Join(root, e.Name()), ver
		}
	}
	return best
}

func parseVersion(s string) []int {
	var out []int
	for _, p := range strings.Split(s, ".") {
		n, _ := strconv.Atoi(p)
		out = append(out, n)
	}
	return out
}

// browserRunning is a best-effort check for an existing live instance.
func browserRunning(bin string) bool {
	names := processNames(bin)
	if runtime.GOOS == "windows" {
		for _, n := range names {
			if !strings.HasSuffix(strings.ToLower(n), ".exe") {
				continue
			}
			out, err := exec.Command("tasklist", "/FI", "IMAGENAME eq "+n, "/NH").Output()
			if err == nil && strings.Contains(strings.ToLower(string(out)), strings.ToLower(n)) {
				return true
			}
		}
		return false
	}
	out, err := exec.Command("ps", "-A", "-o", "stat=,comm=").Output()
	if err != nil {
		return false
	}
	return psHasLive(string(out), names)
}

// psHasLive scans `ps -o stat=,comm=` output for a non-zombie process with
// one of names. Linux truncates comm to 15 bytes; macOS reports full paths.
func psHasLive(psOut string, names []string) bool {
	for _, line := range strings.Split(psOut, "\n") {
		stat, comm, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || strings.HasPrefix(stat, "Z") {
			continue
		}
		comm = filepath.Base(strings.TrimSpace(comm))
		for _, n := range names {
			if comm == n || (len(comm) == 15 && strings.HasPrefix(n, comm)) {
				return true
			}
		}
	}
	return false
}

func processNames(bin string) []string {
	base := filepath.Base(bin)
	names := []string{base}
	l := strings.ToLower(base)
	switch {
	case strings.Contains(l, "discord") && strings.Contains(l, "canary"):
		names = append(names, "DiscordCanary", "Discord Canary", "DiscordCanary.exe", "discord-canary")
	case strings.Contains(l, "discord") && strings.Contains(l, "ptb"):
		names = append(names, "DiscordPTB", "Discord PTB", "DiscordPTB.exe", "discord-ptb")
	case strings.Contains(l, "discord"):
		names = append(names, "Discord", "discord", "Discord.exe")
	case strings.Contains(l, "vivaldi"):
		names = append(names, "vivaldi-bin", "vivaldi", "Vivaldi", "vivaldi.exe")
	case strings.Contains(l, "chromium"):
		names = append(names, "chromium", "chromium-browser", "Chromium")
	case strings.Contains(l, "chrome"):
		names = append(names, "chrome", "Google Chrome", "chrome.exe")
	case strings.Contains(l, "brave"):
		names = append(names, "brave", "Brave Browser", "brave.exe")
	case strings.Contains(l, "edge"):
		names = append(names, "msedge", "Microsoft Edge", "msedge.exe")
	}
	return names
}

func browserName(bin string) string {
	b := filepath.Base(bin)
	return strings.TrimSuffix(b, filepath.Ext(b))
}
