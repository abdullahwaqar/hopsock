package main

import (
	"strings"
	"testing"
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
