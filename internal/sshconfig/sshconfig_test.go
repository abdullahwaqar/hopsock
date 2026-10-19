package sshconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func setup(t *testing.T, files map[string]string) *Resolver {
	t.Helper()
	home := t.TempDir()
	for name, body := range files {
		p := filepath.Join(home, ".ssh", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return &Resolver{Files: []string{filepath.Join(home, ".ssh", "config")}, Home: home, LocalUser: "me"}
}

func TestResolve(t *testing.T) {
	r := setup(t, map[string]string{
		"config": `
# global-ish defaults come last, like most configs
Host web-* !web-legacy
    HostName %h.internal.example.com
    User deploy
    IdentityFile ~/.ssh/%r_%h

Host "web-1"
    Port 2201
    User admin

Host web-legacy
    HostName 10.0.0.5

Host *
    User fallback
    Port 2222
    IdentityFile ~/.ssh/id_ed25519
    ConnectTimeout=7
    IdentitiesOnly yes
    StrictHostKeyChecking Accept-New
    UserKnownHostsFile ~/.ssh/kh1 "~/.ssh/kh 2"
`,
	})
	home := r.Home

	s, err := r.Resolve("web-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.HostName != "web-1.internal.example.com" || s.User != "deploy" || s.Port != "2201" {
		t.Fatalf("web-1: %+v", s)
	}
	wantIDs := []string{
		filepath.Join(home, ".ssh", "deploy_web-1.internal.example.com"),
		filepath.Join(home, ".ssh", "id_ed25519"),
	}
	if !reflect.DeepEqual(s.IdentityFiles, wantIDs) {
		t.Fatalf("identity files %q, want %q", s.IdentityFiles, wantIDs)
	}
	if s.ConnectTimeout != 7*time.Second || !s.IdentitiesOnly || s.StrictHostKeyChecking != "accept-new" {
		t.Fatalf("options: %+v", s)
	}
	if !reflect.DeepEqual(s.UserKnownHostsFiles, []string{filepath.Join(home, ".ssh", "kh1"), filepath.Join(home, ".ssh", "kh 2")}) {
		t.Fatalf("known hosts %q", s.UserKnownHostsFiles)
	}

	// Negated pattern: web-legacy skips the web-* block.
	s, _ = r.Resolve("web-legacy", "", "")
	if s.HostName != "10.0.0.5" || s.User != "fallback" || s.Port != "2222" {
		t.Fatalf("web-legacy: %+v", s)
	}

	// Explicit user and port win, and feed %r.
	s, _ = r.Resolve("web-2", "ops", "22")
	if s.User != "ops" || s.Port != "22" || s.IdentityFiles[0] != filepath.Join(home, ".ssh", "ops_web-2.internal.example.com") {
		t.Fatalf("explicit: %+v", s)
	}

	// Case-insensitive host match.
	if s, _ := r.Resolve("WEB-1", "", ""); s.Port != "2201" {
		t.Fatalf("case: %+v", s)
	}

	// Unmatched host gets only Host * and keeps its own name.
	s, _ = r.Resolve("example.org", "", "")
	if s.HostName != "example.org" || s.User != "fallback" {
		t.Fatalf("unmatched: %+v", s)
	}
}

func TestInclude(t *testing.T) {
	r := setup(t, map[string]string{
		"config": `
Include conf.d/*.conf
Host db
    Include db.extra
Host *
    User fallback
`,
		"conf.d/10-app.conf": "Host app\n    HostName 192.0.2.10\n    ProxyJump bastion\n",
		"conf.d/20-x.conf":   "Host app\n    HostName ignored-second\n",
		"db.extra":           "Port 5432\nHost unrelated\nUser nope\n",
	})
	s, err := r.Resolve("app", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.HostName != "192.0.2.10" || s.ProxyJump != "bastion" || s.User != "fallback" {
		t.Fatalf("app: %+v", s)
	}
	// The conditional include applies to db, and its own Host line
	// doesn't leak out of the file.
	s, _ = r.Resolve("db", "", "")
	if s.Port != "5432" || s.User != "fallback" {
		t.Fatalf("db: %+v", s)
	}
	if s, _ := r.Resolve("app", "", ""); s.Port != "" {
		t.Fatalf("include leaked into app: %+v", s)
	}
	if !r.HasHost("app") || !r.HasHost("db") || r.HasHost("nothing") {
		t.Fatal("HasHost")
	}
}

func TestMatch(t *testing.T) {
	r := setup(t, map[string]string{
		"config": `
Host short
    HostName long.example.com
Match host *.example.com user deploy
    Port 2200
Match originalhost short !localuser root
    IdentityFile ~/.ssh/short_key
Match exec "true"
    User should-not-apply
Match all
    User deploy
`,
	})
	s, err := r.Resolve("short", "deploy", "")
	if err != nil {
		t.Fatal(err)
	}
	if s.Port != "2200" || len(s.IdentityFiles) != 1 || s.User != "deploy" {
		t.Fatalf("match: %+v", s)
	}
	if len(s.Warnings) == 0 {
		t.Fatal("want a warning about Match exec")
	}
	s, _ = r.Resolve("short", "other", "")
	if s.Port != "" {
		t.Fatalf("user criterion: %+v", s)
	}
}

func TestProxyCommandKeepsQuotes(t *testing.T) {
	r := setup(t, map[string]string{
		"config": `Host x
    ProxyCommand sh -c "nc %h %p" # not a comment to ssh either
`,
	})
	s, _ := r.Resolve("x", "", "")
	if s.ProxyCommand != `sh -c "nc x 22" # not a comment to ssh either` {
		t.Fatalf("got %q", s.ProxyCommand)
	}
}

func TestBadValues(t *testing.T) {
	for _, body := range []string{"Host x\n  Port abc\n", "Host x\n  ConnectTimeout soon\n", "Host x\n  User \"unterminated\n"} {
		r := setup(t, map[string]string{"config": body})
		if _, err := r.Resolve("x", "", ""); err == nil {
			t.Errorf("%q: want error", body)
		}
	}
}

func TestMissingFileIsFine(t *testing.T) {
	r := &Resolver{Files: []string{filepath.Join(t.TempDir(), "nope")}}
	s, err := r.Resolve("h", "", "")
	if err != nil || s.HostName != "h" {
		t.Fatalf("%+v %v", s, err)
	}
}

func TestMatchPattern(t *testing.T) {
	for _, c := range []struct {
		p, s string
		ok   bool
	}{
		{"*", "anything", true},
		{"web-?", "web-1", true},
		{"web-?", "web-10", false},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"a*b*c", "aXbYc", true},
		{"a*b*c", "aXbY", false},
	} {
		if got := match(c.p, c.s); got != c.ok {
			t.Errorf("match(%q, %q) = %v", c.p, c.s, got)
		}
	}
}
