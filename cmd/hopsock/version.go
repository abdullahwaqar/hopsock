package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"time"
)

// Set by GoReleaser via -ldflags "-X main.version=... -X main.commit=... -X main.date=...".
var (
	version = ""
	commit  = ""
	date    = ""
)

// versionString reports the release version, falling back to module build
// info so `go install github.com/abdullahwaqar/hopsock/cmd/hopsock@v1.2.3`
// also prints a real version.
func versionString() string {
	v, c, d := version, commit, date
	if info, ok := debug.ReadBuildInfo(); ok {
		if v == "" && info.Main.Version != "" && info.Main.Version != "(devel)" {
			v = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if c == "" {
					c = s.Value
				}
			case "vcs.time":
				if d == "" {
					d = s.Value
				}
			}
		}
	}
	// GoReleaser fills placeholders when git metadata is unavailable.
	if c == "none" {
		c = ""
	}
	if strings.HasPrefix(d, "0001-") {
		d = ""
	}
	if t, err := time.Parse(time.RFC3339, d); err == nil {
		d = t.UTC().Format("2006-01-02")
	}
	if v == "" {
		v = "dev"
	}
	if len(c) > 7 {
		c = c[:7]
	}
	out := v
	if c != "" {
		out += " (" + c
		if d != "" {
			out += ", " + d
		}
		out += ")"
	}
	return fmt.Sprintf("%s %s/%s", out, runtime.GOOS, runtime.GOARCH)
}
