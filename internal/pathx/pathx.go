package pathx

import (
	"os"
	"path/filepath"
	"strings"
)

// Home returns the user's home directory, or "" if unknown.
func Home() string {
	h, _ := os.UserHomeDir()
	return h
}

// ExpandHome replaces a leading "~" or "~/" with the home directory.
func ExpandHome(p string) string {
	if p == "~" {
		return Home()
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return filepath.Join(Home(), rest)
	}
	return p
}
