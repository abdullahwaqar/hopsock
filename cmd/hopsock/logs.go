package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/abdullahwaqar/hopsock"
)

type logLine struct {
	t     time.Time
	level hopsock.Level
	msg   string
}

// logBus fans library logs out to the TUI (via a channel) or stderr.
type logBus struct {
	tui     bool
	verbose bool
	ch      chan logLine
}

func newLogBus(tui, verbose bool) *logBus {
	return &logBus{tui: tui, verbose: verbose, ch: make(chan logLine, 4096)}
}

// Log matches hopsock.LogFunc. In TUI mode it never blocks: if the UI
// falls behind, lines are dropped rather than stalling the proxy.
func (b *logBus) Log(level hopsock.Level, msg string) {
	l := logLine{t: time.Now(), level: level, msg: msg}
	if !b.tui {
		if level == hopsock.LevelDebug && !b.verbose {
			return
		}
		fmt.Fprintf(os.Stderr, "%s %s %s\n", l.t.Format("15:04:05"), level, msg)
		return
	}
	select {
	case b.ch <- l:
	default:
	}
}

// lineWriter turns a child process's output into debug log lines.
const maxPartialLine = 8 << 10

type lineWriter struct {
	prefix string
	log    hopsock.LogFunc
	buf    []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := bytes.IndexByte(w.buf, '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.log(hopsock.LevelDebug, w.prefix+line)
		}
		w.buf = w.buf[i+1:]
	}
	if len(w.buf) > maxPartialLine {
		w.log(hopsock.LevelDebug, w.prefix+string(w.buf))
		w.buf = w.buf[:0]
	}
	return len(p), nil
}
