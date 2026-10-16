package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/abdullahwaqar/hopsock"
)

func TestParseListen(t *testing.T) {
	cases := []struct {
		in, addr, user, pass string
	}{
		{"1080", "127.0.0.1:1080", "", ""},
		{"0.0.0.0:9050", "0.0.0.0:9050", "", ""},
		{"socks5://a:b@127.0.0.1:2000", "127.0.0.1:2000", "a", "b"},
		{"socks5://127.0.0.1", "127.0.0.1:1080", "", ""},
	}
	for _, c := range cases {
		var cfg config
		if err := parseListen(c.in, &cfg); err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if cfg.listen != c.addr || cfg.localUser != c.user || cfg.localPass != c.pass {
			t.Errorf("%s: got %+v", c.in, cfg)
		}
	}
	var cfg config
	if err := parseListen("http://127.0.0.1:1", &cfg); err == nil {
		t.Error("http listener should be rejected")
	}
}

func TestDialableAddr(t *testing.T) {
	for in, want := range map[string]string{
		"0.0.0.0:1080":   "127.0.0.1:1080",
		"[::]:1080":      "127.0.0.1:1080",
		"127.0.0.1:1080": "127.0.0.1:1080",
	} {
		if got := dialableAddr(in); got != want {
			t.Errorf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestBrowserArgs(t *testing.T) {
	l := browserLauncher("vivaldi-stable", "", "127.0.0.1:1080")
	args := strings.Join(l.argv, " ")
	if strings.Contains(args, "--user-data-dir") {
		t.Fatal("--user-data-dir must only be passed with -profile")
	}
	for _, want := range []string{"--proxy-server=socks5://127.0.0.1:1080", "EXCLUDE 127.0.0.1", "disable_non_proxied_udp"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %q in %s", want, args)
		}
	}
	l = browserLauncher("vivaldi-stable", "/tmp/p", "127.0.0.1:1080")
	if !strings.Contains(strings.Join(l.argv, " "), "--user-data-dir=/tmp/p") {
		t.Fatal("profile not passed")
	}
}

func TestVersionString(t *testing.T) {
	version, commit, date = "v1.2.3", "abcdef1234567", "2026-10-14T00:00:00Z"
	t.Cleanup(func() { version, commit, date = "", "", "" })
	if got := versionString(); !strings.HasPrefix(got, "v1.2.3 (abcdef1, 2026-10-14)") {
		t.Fatalf("got %q", got)
	}
}

func TestPsHasLive(t *testing.T) {
	ps := "Ss   systemd\nZ    vivaldi-stable\nS    bash\n"
	if psHasLive(ps, processNames("vivaldi-stable")) {
		t.Fatal("zombie must not count as running")
	}
	if !psHasLive("Sl   google-chrome-s\n", processNames("google-chrome-stable")) {
		t.Fatal("truncated Linux comm should match")
	}
	if !psHasLive("S    /Applications/Vivaldi.app/Contents/MacOS/Vivaldi\n", processNames("/Applications/Vivaldi.app/Contents/MacOS/Vivaldi")) {
		t.Fatal("macOS full path should match")
	}
}

func TestDiscordLauncher(t *testing.T) {
	for _, bin := range []string{"/usr/bin/discord", "/opt/discord/Discord", `C:\x\Discord\app-1.0.9\Discord.exe`, "/var/lib/flatpak/exports/bin/com.discordapp.Discord"} {
		l := appLauncher(bin, "/tmp/profile", "127.0.0.1:1080")
		if l.kind != kindDiscord || l.name != "Discord" {
			t.Fatalf("%s: want Discord launcher, got kind %d name %q", bin, l.kind, l.name)
		}
		args := strings.Join(l.argv, " ")
		if strings.Contains(args, "--user-data-dir") {
			t.Fatalf("%s: Discord must not get --user-data-dir", bin)
		}
		for _, want := range []string{"--proxy-server=socks5://127.0.0.1:1080", "EXCLUDE 127.0.0.1"} {
			if !strings.Contains(args, want) {
				t.Errorf("missing %q in %s", want, args)
			}
		}
	}
	if n := discordName("/usr/bin/discord-ptb"); n != "Discord PTB" {
		t.Errorf("got %q", n)
	}
	if n := discordName("/Applications/Discord Canary.app/Contents/MacOS/Discord Canary"); n != "Discord Canary" {
		t.Errorf("got %q", n)
	}
	if l := appLauncher("vivaldi-stable", "", "127.0.0.1:1080"); l.kind != kindBrowser {
		t.Error("vivaldi should be a browser")
	}
}

func TestDiscordRunningCheck(t *testing.T) {
	if !psHasLive("Sl   Discord\n", processNames("/usr/bin/discord")) {
		t.Fatal("linux Discord comm should match")
	}
	if !psHasLive("S    /Applications/Discord.app/Contents/MacOS/Discord\n", processNames("/Applications/Discord.app/Contents/MacOS/Discord")) {
		t.Fatal("macOS Discord should match")
	}
	if psHasLive("S    DiscordCanary\n", processNames("/usr/bin/discord")) {
		t.Fatal("Canary running must not block stable")
	}
	if !psHasLive("S    Discord\n", processNames("/var/lib/flatpak/exports/bin/com.discordapp.Discord")) {
		t.Fatal("flatpak Discord should match its process")
	}
}

func TestNewestAppDir(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"app-1.0.9", "app-1.0.10", "app-1.0.2", "packages"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := newestAppDir(root); filepath.Base(got) != "app-1.0.10" {
		t.Fatalf("got %s", got)
	}
	if newestAppDir(filepath.Join(root, "missing")) != "" {
		t.Fatal("missing root should give empty")
	}
}

func TestLaunchFlagsExclusive(t *testing.T) {
	if _, err := parseFlags([]string{"-discord", "-browser", "x"}); err == nil {
		t.Fatal("-discord with -browser should fail")
	}
	if _, err := parseFlags([]string{"-discord", "-exec", "x"}); err == nil {
		t.Fatal("-discord with -exec should fail")
	}
	cfg, err := parseFlags([]string{"-discord"})
	if err != nil || !cfg.discord || !cfg.prompt {
		t.Fatalf("got %+v %v", cfg, err)
	}
	cfg, _ = parseFlags([]string{"-prompt=false"})
	if cfg.prompt {
		t.Fatal("-prompt=false not applied")
	}
}

func TestCredHeadline(t *testing.T) {
	cases := map[string]hopsock.CredRequest{
		"socks5://p:1 wants a username and password": {Hop: "socks5://p:1", Scheme: "socks5", NeedUser: true},
		"http://p:1 wants the password for bob":      {Hop: "http://p:1", Scheme: "http", User: "bob"},
		"ssh://me@h:22 wants a password":             {Hop: "ssh://me@h:22", Scheme: "ssh", User: "me"},
		"ssh://me@h:22 asks: Verification code:":     {Hop: "ssh://me@h:22", Scheme: "ssh", Prompt: "Verification code: "},
	}
	for want, req := range cases {
		if got := credHeadline(req); got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestPrompterClosedCancels(t *testing.T) {
	p := newPrompter(os.Stdin, io.Discard)
	p.close()
	p.close() // idempotent
	if _, _, err := p.ask(context.Background(), hopsock.CredRequest{}); !errors.Is(err, hopsock.ErrPromptCanceled) {
		t.Fatalf("want canceled, got %v", err)
	}
}

func TestPrompterRoutesToTUI(t *testing.T) {
	p := newPrompter(os.Stdin, io.Discard)
	p.attach(func(msg tea.Msg) {
		m := msg.(credAskMsg)
		m.reply <- credReply{user: "u", pass: "p:" + m.req.Hop}
	})
	u, pw, err := p.ask(context.Background(), hopsock.CredRequest{Hop: "h"})
	if err != nil || u != "u" || pw != "p:h" {
		t.Fatalf("got %q %q %v", u, pw, err)
	}
}
