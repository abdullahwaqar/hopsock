package sshconfig

import (
	"bufio"
	"crypto/sha1" //nolint:gosec // %C is defined by OpenSSH as a SHA-1 hash
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Settings is what the config says about one host. Empty fields were not set.
type Settings struct {
	Host string // the name that was looked up (an alias or a real host)

	HostName              string // with %h expanded; "" means Host
	User                  string
	Port                  string
	IdentityFiles         []string // tokens and ~ expanded, in order
	IdentitiesOnly        bool
	IdentityAgent         string // "none", "SSH_AUTH_SOCK" or a socket path
	ProxyJump             string // raw, comma-separated; "none" disables
	ProxyCommand          string // tokens expanded; "none" disables
	UserKnownHostsFiles   []string
	GlobalKnownHostsFiles []string
	StrictHostKeyChecking string // lowercased: yes, no, off, accept-new, ask
	HostKeyAlias          string
	ConnectTimeout        time.Duration

	// Warnings lists things in the config that were skipped.
	Warnings []string
}

// Resolver looks hosts up in a list of config files. The first file wins,
// like ssh reading ~/.ssh/config before /etc/ssh/ssh_config.
type Resolver struct {
	Files     []string
	Home      string
	LocalUser string
}

// Default returns a resolver for ~/.ssh/config and /etc/ssh/ssh_config.
func Default(home, localUser string) *Resolver {
	var files []string
	if home != "" {
		files = append(files, filepath.Join(home, ".ssh", "config"))
	}
	files = append(files, "/etc/ssh/ssh_config")
	return &Resolver{Files: files, Home: home, LocalUser: localUser}
}

// maxIncludeDepth matches OpenSSH's READCONF_MAX_DEPTH.
const maxIncludeDepth = 16

// raw option values as read, before token expansion.
type state struct {
	r          *Resolver
	host       string // as given
	cliUser    string
	vals       map[string][]string // first occurrence only
	identities []string
	warned     map[string]bool
	warnings   []string
}

// multi are options where every occurrence counts.
var multi = map[string]bool{"identityfile": true}

// known are the options this package reads. Others are ignored silently.
var known = map[string]bool{
	"hostname": true, "user": true, "port": true, "identityfile": true,
	"identitiesonly": true, "identityagent": true, "proxyjump": true,
	"proxycommand": true, "userknownhostsfile": true, "globalknownhostsfile": true,
	"stricthostkeychecking": true, "hostkeyalias": true, "connecttimeout": true,
}

// Resolve looks up host. user and port are values given explicitly (on the
// command line, or in a hop URL); they win over the config and feed the %r
// and %p tokens. Pass "" when not given.
func (r *Resolver) Resolve(host, user, port string) (*Settings, error) {
	st := &state{r: r, host: host, cliUser: user, vals: map[string][]string{}, warned: map[string]bool{}}
	for i, f := range r.Files {
		if err := st.readFile(f, true, 0, i == 0); err != nil {
			return nil, err
		}
	}
	return st.settings(user, port)
}

// HasHost reports whether some Host line names host exactly (not just via a
// wildcard). It's used to tell an alias apart from a typo.
func (r *Resolver) HasHost(host string) bool {
	host = strings.ToLower(host)
	found := false
	var walk func(path string, depth int, user bool)
	walk = func(path string, depth int, user bool) {
		if found || depth > maxIncludeDepth {
			return
		}
		lines, err := readLines(path)
		if err != nil {
			return
		}
		for _, ln := range lines {
			key, args, err := splitLine(ln)
			if err != nil || key == "" {
				continue
			}
			switch key {
			case "host":
				for _, p := range args {
					if strings.ToLower(p) == host {
						found = true
						return
					}
				}
			case "include":
				for _, a := range args {
					for _, m := range r.includeGlob(a, user) {
						walk(m, depth+1, user)
					}
				}
			}
		}
	}
	for i, f := range r.Files {
		walk(f, 0, i == 0)
	}
	return found
}

func (st *state) warn(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	if !st.warned[msg] {
		st.warned[msg] = true
		st.warnings = append(st.warnings, msg)
	}
}

func (st *state) readFile(path string, active bool, depth int, user bool) error {
	if depth > maxIncludeDepth {
		return fmt.Errorf("%s: Include nested too deeply", path)
	}
	lines, err := readLines(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("ssh config: %w", err)
	}
	for n, ln := range lines {
		key, args, err := splitLine(ln)
		if err != nil {
			return fmt.Errorf("%s line %d: %w", path, n+1, err)
		}
		if key == "" {
			continue
		}
		switch key {
		case "host":
			active = matchList(args, strings.ToLower(st.host))
			continue
		case "match":
			active = st.evalMatch(args, path, n+1)
			continue
		case "include":
			if !active {
				continue
			}
			for _, a := range args {
				for _, m := range st.r.includeGlob(a, user) {
					// An included file may change the active state with its
					// own Host lines; it's restored afterwards, as in ssh.
					if err := st.readFile(m, active, depth+1, user); err != nil {
						return err
					}
				}
			}
			continue
		}
		if !active || !known[key] || len(args) == 0 {
			continue
		}
		if multi[key] {
			st.identities = append(st.identities, args[0])
			continue
		}
		if _, set := st.vals[key]; !set {
			st.vals[key] = args
		}
	}
	return nil
}

func (r *Resolver) includeGlob(pattern string, user bool) []string {
	p := expandEnv(expandTilde(pattern, r.Home))
	if !filepath.IsAbs(p) {
		base := "/etc/ssh"
		if user {
			base = filepath.Join(r.Home, ".ssh")
		}
		p = filepath.Join(base, p)
	}
	m, err := filepath.Glob(p)
	if err != nil {
		return nil
	}
	sort.Strings(m)
	return m
}

func (st *state) evalMatch(args []string, path string, line int) bool {
	if len(args) == 0 {
		return false
	}
	result := true
	for i := 0; i < len(args); i++ {
		crit := strings.ToLower(args[i])
		neg := strings.HasPrefix(crit, "!")
		crit = strings.TrimPrefix(crit, "!")
		var ok bool
		switch crit {
		case "all":
			ok = true
		case "canonical", "final":
			ok = false
		case "host", "originalhost", "user", "localuser", "exec", "tagged", "localnetwork":
			if i+1 >= len(args) {
				st.warn("%s line %d: Match %s needs an argument", path, line, crit)
				return false
			}
			i++
			arg := args[i]
			list := strings.Split(arg, ",")
			switch crit {
			case "host":
				h := st.host
				if v := st.vals["hostname"]; len(v) > 0 {
					h = expandHostName(v[0], st.host)
				}
				ok = matchList(list, strings.ToLower(h))
			case "originalhost":
				ok = matchList(list, strings.ToLower(st.host))
			case "user":
				u := st.cliUser
				if u == "" {
					if v := st.vals["user"]; len(v) > 0 {
						u = v[0]
					} else {
						u = st.r.LocalUser
					}
				}
				ok = matchList(list, u)
			case "localuser":
				ok = matchList(list, st.r.LocalUser)
			default:
				st.warn("%s line %d: Match %s is not supported, treating it as not matching", path, line, crit)
				ok = false
			}
		default:
			st.warn("%s line %d: unknown Match criterion %q", path, line, crit)
			return false
		}
		if neg {
			ok = !ok
		}
		if !ok {
			result = false
		}
	}
	return result
}

func (st *state) settings(cliUser, cliPort string) (*Settings, error) {
	s := &Settings{Host: st.host, Warnings: st.warnings}
	first := func(k string) string {
		if v := st.vals[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}

	s.HostName = st.host
	if v := first("hostname"); v != "" {
		s.HostName = expandHostName(v, st.host)
	}
	s.User = cliUser
	if s.User == "" {
		s.User = first("user")
	}
	s.Port = cliPort
	if s.Port == "" {
		s.Port = first("port")
	}
	if s.Port != "" {
		if n, err := strconv.Atoi(s.Port); err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("ssh config for %s: bad Port %q", st.host, s.Port)
		}
	}
	s.HostKeyAlias = first("hostkeyalias")

	// Tokens see the final values, including explicit user and port.
	tok := st.tokens(s)
	for _, f := range st.identities {
		if strings.EqualFold(f, "none") {
			continue
		}
		s.IdentityFiles = append(s.IdentityFiles, st.expandPath(f, tok))
	}
	s.IdentitiesOnly = yes(first("identitiesonly"))
	if v := first("identityagent"); v != "" {
		switch {
		case strings.EqualFold(v, "none"):
			s.IdentityAgent = "none"
		case v == "SSH_AUTH_SOCK":
			s.IdentityAgent = v
		case strings.HasPrefix(v, "$"):
			// IdentityAgent $SOME_VAR names a variable holding the socket.
			s.IdentityAgent = os.Getenv(strings.Trim(v, "${}"))
		default:
			s.IdentityAgent = st.expandPath(v, tok)
		}
	}
	s.ProxyJump = first("proxyjump")
	if v := st.vals["proxycommand"]; len(v) > 0 {
		s.ProxyCommand = expandTokens(v[0], tok)
	}
	for _, f := range st.vals["userknownhostsfile"] {
		if !strings.EqualFold(f, "none") {
			s.UserKnownHostsFiles = append(s.UserKnownHostsFiles, st.expandPath(f, tok))
		}
	}
	for _, f := range st.vals["globalknownhostsfile"] {
		if !strings.EqualFold(f, "none") {
			s.GlobalKnownHostsFiles = append(s.GlobalKnownHostsFiles, st.expandPath(f, tok))
		}
	}
	s.StrictHostKeyChecking = strings.ToLower(first("stricthostkeychecking"))
	if v := first("connecttimeout"); v != "" && !strings.EqualFold(v, "none") {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("ssh config for %s: bad ConnectTimeout %q", st.host, v)
		}
		s.ConnectTimeout = time.Duration(n) * time.Second
	}
	return s, nil
}

func (st *state) tokens(s *Settings) map[byte]string {
	port := s.Port
	if port == "" {
		port = "22"
	}
	ruser := s.User
	if ruser == "" {
		ruser = st.r.LocalUser
	}
	local, _ := os.Hostname()
	short, _, _ := strings.Cut(local, ".")
	k := s.HostKeyAlias
	if k == "" {
		k = st.host
	}
	sum := sha1.Sum([]byte(short + s.HostName + port + ruser)) //nolint:gosec
	return map[byte]string{
		'%': "%",
		'C': hex.EncodeToString(sum[:]),
		'd': st.r.Home,
		'h': s.HostName,
		'k': k,
		'L': short,
		'l': local,
		'n': st.host,
		'p': port,
		'r': ruser,
		'u': st.r.LocalUser,
		'i': strconv.Itoa(os.Getuid()),
	}
}

func (st *state) expandPath(p string, tok map[byte]string) string {
	return expandTilde(expandEnv(expandTokens(p, tok)), st.r.Home)
}

// expandHostName applies the only tokens HostName allows: %h and %%.
func expandHostName(v, host string) string {
	return expandTokens(v, map[byte]string{'h': host, '%': "%"})
}

func expandTokens(s string, tok map[byte]string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+1 < len(s) {
			if v, ok := tok[s[i+1]]; ok {
				b.WriteString(v)
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(s string) string {
	return envRef.ReplaceAllStringFunc(s, func(m string) string {
		return os.Getenv(m[2 : len(m)-1])
	})
}

func expandTilde(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(home, rest)
	}
	return p
}

func yes(v string) bool {
	switch strings.ToLower(v) {
	case "yes", "true", "on":
		return true
	}
	return false
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out, sc.Err()
}

// splitLine returns the lowercased keyword and its arguments. Comments and
// blank lines give an empty keyword.
func splitLine(line string) (string, []string, error) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' {
		return "", nil, nil
	}
	end := strings.IndexAny(line, " \t=")
	if end < 0 {
		return strings.ToLower(line), nil, nil
	}
	key := strings.ToLower(line[:end])
	rest := strings.TrimLeft(line[end:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	if key == "proxycommand" {
		// Handed to a shell as is, quotes and all.
		if rest == "" {
			return key, nil, nil
		}
		return key, []string{rest}, nil
	}
	args, err := splitArgs(rest)
	return key, args, err
}

func splitArgs(s string) ([]string, error) {
	var out []string
	for {
		s = strings.TrimLeft(s, " \t")
		if s == "" || s[0] == '#' {
			return out, nil
		}
		if s[0] == '"' {
			end := strings.IndexByte(s[1:], '"')
			if end < 0 {
				return nil, fmt.Errorf("unterminated quote")
			}
			out = append(out, s[1:end+1])
			s = s[end+2:]
			continue
		}
		end := strings.IndexAny(s, " \t")
		if end < 0 {
			end = len(s)
		}
		out = append(out, s[:end])
		s = s[end:]
	}
}

// matchList applies an ssh pattern list: any negated match rejects, else any
// positive match accepts. Host patterns are matched case-insensitively.
func matchList(patterns []string, s string) bool {
	ok := false
	for _, p := range patterns {
		if neg, found := strings.CutPrefix(p, "!"); found {
			if match(strings.ToLower(neg), strings.ToLower(s)) {
				return false
			}
			continue
		}
		if match(strings.ToLower(p), strings.ToLower(s)) {
			ok = true
		}
	}
	return ok
}

// match is ssh's match_pattern: '*' and '?' wildcards only.
func match(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for len(p) > 0 && p[0] == '*' {
				p = p[1:]
			}
			if p == "" {
				return true
			}
			for i := 0; i <= len(s); i++ {
				if match(p, s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if s == "" {
				return false
			}
		default:
			if s == "" || p[0] != s[0] {
				return false
			}
		}
		p, s = p[1:], s[1:]
	}
	return s == ""
}
