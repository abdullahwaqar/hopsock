package main

import (
	"context"
	"time"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/abdullahwaqar/hopsock"
)

var (
	cAccent = lipgloss.AdaptiveColor{Light: "#0F766E", Dark: "#5EEAD4"}
	cOK     = lipgloss.AdaptiveColor{Light: "#15803D", Dark: "#86EFAC"}
	cWarn   = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#FCD34D"}
	cErr    = lipgloss.AdaptiveColor{Light: "#B91C1C", Dark: "#FCA5A5"}
	cMuted  = lipgloss.AdaptiveColor{Light: "#6B7280", Dark: "#9CA3AF"}
	cFaint  = lipgloss.AdaptiveColor{Light: "#D1D5DB", Dark: "#374151"}
	cText   = lipgloss.AdaptiveColor{Light: "#111827", Dark: "#E5E7EB"}

	sBrand = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#0B1220")).Background(cAccent).Padding(0, 1)
	sMuted = lipgloss.NewStyle().Foreground(cMuted)
	sText  = lipgloss.NewStyle().Foreground(cText)
	sBold  = lipgloss.NewStyle().Foreground(cText).Bold(true)
	sOK    = lipgloss.NewStyle().Foreground(cOK)
	sWarn  = lipgloss.NewStyle().Foreground(cWarn)
	sErr   = lipgloss.NewStyle().Foreground(cErr)
	sAcc   = lipgloss.NewStyle().Foreground(cAccent)
	sPanel = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(cFaint).Padding(0, 1)
	sTitle = lipgloss.NewStyle().Foreground(cMuted).Bold(true)
)

type keyMap struct {
	Quit, Retest, Launch, Focus, Clear, Debug, Follow, Up, Down key.Binding
	Pick, Cancel                                                key.Binding
}

func (k keyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Retest, k.Launch, k.Focus, k.Debug, k.Follow, k.Clear, k.Quit}
}
func (k keyMap) FullHelp() [][]key.Binding { return [][]key.Binding{k.ShortHelp()} }

var keys = keyMap{
	Quit:   key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Retest: key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "retest")),
	Launch: key.NewBinding(key.WithKeys("b"), key.WithHelp("b", "open browser")),
	Pick:   key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open")),
	Cancel: key.NewBinding(key.WithKeys("esc", "b"), key.WithHelp("esc", "cancel")),
	Focus:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "focus")),
	Clear:  key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "clear log")),
	Debug:  key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "debug log")),
	Follow: key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "follow")),
	Up:     key.NewBinding(key.WithKeys("up", "k", "pgup")),
	Down:   key.NewBinding(key.WithKeys("down", "j", "pgdown")),
}

type tickMsg time.Time
type logMsg logLine
type testDoneMsg struct {
	info *hopsock.ExitInfo
	err  error
}
type launchStartedMsg struct {
	l    *launcher
	done <-chan error
}
type launchExitMsg struct {
	l          *launcher
	err        error
	didntStart bool
}

// launchStatus is what the UI shows for one launcher.
type launchStatus struct {
	state string // "waiting", "running", "exited", "failed"
	msg   string
}

const maxLogLines = 1000

type model struct {
	app *app

	width, height int
	spin          spinner.Model
	tbl           table.Model
	vp            viewport.Model
	help          help.Model

	lines     []logLine
	showDebug bool
	follow    bool
	focusLog  bool

	testing bool
	exit    *hopsock.ExitInfo
	testErr error

	launches map[*launcher]*launchStatus
	manual   *launcher // last browser opened from the picker

	picking  bool
	pickList []browserInfo
	pickIdx  int

	snap     hopsock.Snapshot
	lastTick time.Time
	prevUp   int64
	prevDown int64
	rateUp   float64
	rateDown float64
}

func newModel(a *app) model {
	sp := spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(sAcc))
	t := table.New(table.WithFocused(true), table.WithHeight(5))
	ts := table.DefaultStyles()
	ts.Header = ts.Header.Foreground(cMuted).Bold(true).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true).BorderForeground(cFaint)
	ts.Selected = ts.Selected.Foreground(lipgloss.Color("#0B1220")).Background(cAccent).Bold(false)
	ts.Cell = ts.Cell.Foreground(cText)
	t.SetStyles(ts)
	h := help.New()
	h.Styles.ShortKey = sAcc
	h.Styles.ShortDesc = sMuted
	h.Styles.ShortSeparator = sMuted

	m := model{
		app:       a,
		spin:      sp,
		tbl:       t,
		vp:        viewport.New(80, 5),
		help:      h,
		follow:    true,
		showDebug: a.cfg.verbose,
		lastTick:  time.Now(),
		launches:  map[*launcher]*launchStatus{},
	}
	if a.launch != nil {
		m.status(a.launch).state = "waiting"
	}
	return m
}

func (m model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.spin.Tick, tick(), waitLog(m.app.logs.ch), connectSSH(m.app)}
	if m.app.cfg.testURL != "" {
		cmds = append(cmds, m.startTest())
	} else if m.app.launch != nil {
		cmds = append(cmds, m.launchCmd(m.app.launch))
	}
	return tea.Batch(cmds...)
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func waitLog(ch <-chan logLine) tea.Cmd {
	return func() tea.Msg { return logMsg(<-ch) }
}

// connectSSH brings SSH sessions up right away so their state shows
// before the first request.
func connectSSH(a *app) tea.Cmd {
	if len(a.chain.SSH()) == 0 {
		return nil
	}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, s := range a.chain.SSH() {
			if err := s.Connect(ctx); err != nil {
				a.logs.Log(hopsock.LevelError, err.Error())
				break // later hops need the earlier ones
			}
		}
		return nil
	}
}

func (m *model) startTest() tea.Cmd {
	m.testing = true
	a := m.app
	return func() tea.Msg {
		info, err := a.preflight(context.Background())
		return testDoneMsg{info, err}
	}
}

func (m model) status(l *launcher) *launchStatus {
	s := m.launches[l]
	if s == nil {
		s = &launchStatus{}
		m.launches[l] = s
	}
	return s
}

func (m model) launchCmd(l *launcher) tea.Cmd {
	m.status(l).state = "running"
	log := m.app.logs.Log
	return func() tea.Msg {
		done, err := l.start(log)
		if err != nil {
			return launchExitMsg{l: l, err: err, didntStart: true}
		}
		return launchStartedMsg{l, done}
	}
}

// openBrowser handles "b": relaunch the -browser one if it's closed,
// otherwise show a picker of installed browsers.
func (m *model) openBrowser() tea.Cmd {
	if l := m.app.launch; l != nil && l.browser && !l.running() {
		return m.launchCmd(l)
	}
	m.pickList = detectBrowsers()
	if len(m.pickList) == 0 {
		m.app.logs.Log(hopsock.LevelError, "no Chromium-based browser found; start with -browser /path/to/browser")
		return nil
	}
	m.picking, m.pickIdx = true, 0
	return nil
}

func (m *model) pickBrowser() tea.Cmd {
	m.picking = false
	b := m.pickList[m.pickIdx]
	if m.manual != nil && m.manual.running() {
		m.app.logs.Log(hopsock.LevelWarn, m.manual.name+" is already open from here; close it first")
		return nil
	}
	if m.testErr != nil {
		m.app.logs.Log(hopsock.LevelWarn, "preflight failed, pages may not load")
	}
	l := browserLauncher(b.Path, m.app.cfg.profile, m.app.proxyAddr)
	m.manual = l
	m.app.manual = append(m.app.manual, l)
	return m.launchCmd(l)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.layout()

	case tea.KeyMsg:
		if m.picking {
			switch {
			case key.Matches(msg, keys.Cancel):
				m.picking = false
			case key.Matches(msg, keys.Pick):
				cmds = append(cmds, m.pickBrowser())
			case key.Matches(msg, keys.Up):
				m.pickIdx = (m.pickIdx - 1 + len(m.pickList)) % len(m.pickList)
			case key.Matches(msg, keys.Down):
				m.pickIdx = (m.pickIdx + 1) % len(m.pickList)
			case msg.String() == "ctrl+c":
				return m, tea.Quit
			}
			break
		}
		switch {
		case key.Matches(msg, keys.Quit):
			return m, tea.Quit
		case key.Matches(msg, keys.Retest):
			if !m.testing && m.app.cfg.testURL != "" {
				cmds = append(cmds, m.startTest())
			}
		case key.Matches(msg, keys.Launch):
			cmds = append(cmds, m.openBrowser())
		case key.Matches(msg, keys.Focus):
			m.focusLog = !m.focusLog
			if m.focusLog {
				m.tbl.Blur()
			} else {
				m.tbl.Focus()
			}
		case key.Matches(msg, keys.Clear):
			m.lines = nil
			m.refreshLog()
		case key.Matches(msg, keys.Debug):
			m.showDebug = !m.showDebug
			m.refreshLog()
		case key.Matches(msg, keys.Follow):
			m.follow = !m.follow
			if m.follow {
				m.vp.GotoBottom()
			}
		default:
			var cmd tea.Cmd
			if m.focusLog {
				m.vp, cmd = m.vp.Update(msg)
				if key.Matches(msg, keys.Up) {
					m.follow = false
				}
				if m.vp.AtBottom() {
					m.follow = true
				}
			} else {
				m.tbl, cmd = m.tbl.Update(msg)
			}
			cmds = append(cmds, cmd)
		}

	case tea.MouseMsg:
		var cmd tea.Cmd
		m.vp, cmd = m.vp.Update(msg)
		cmds = append(cmds, cmd)

	case tickMsg:
		now := time.Time(msg)
		m.snap = m.app.stats.Snapshot()
		if dt := now.Sub(m.lastTick).Seconds(); dt > 0 {
			// light smoothing so the rate doesn't flicker
			m.rateUp = 0.5*m.rateUp + 0.5*float64(m.snap.Up-m.prevUp)/dt
			m.rateDown = 0.5*m.rateDown + 0.5*float64(m.snap.Down-m.prevDown)/dt
		}
		m.prevUp, m.prevDown, m.lastTick = m.snap.Up, m.snap.Down, now
		m.refreshTable()
		cmds = append(cmds, tick())

	case logMsg:
		m.lines = append(m.lines, logLine(msg))
		if len(m.lines) > maxLogLines {
			m.lines = m.lines[len(m.lines)-maxLogLines:]
		}
		m.refreshLog()
		cmds = append(cmds, waitLog(m.app.logs.ch))

	case testDoneMsg:
		m.testing = false
		m.exit, m.testErr = msg.info, msg.err
		if msg.err != nil {
			m.app.logs.Log(hopsock.LevelError, "preflight failed: "+msg.err.Error())
		} else {
			m.app.logs.Log(hopsock.LevelInfo, "preflight ok: exit "+exitText(msg.info))
			if l := m.app.launch; l != nil && m.status(l).state == "waiting" {
				cmds = append(cmds, m.launchCmd(l))
			}
		}

	case launchStartedMsg:
		m.status(msg.l).state = "running"
		l, done := msg.l, msg.done
		cmds = append(cmds, func() tea.Msg { return launchExitMsg{l: l, err: <-done} })

	case launchExitMsg:
		st := m.status(msg.l)
		if msg.didntStart {
			st.state, st.msg = "failed", msg.err.Error()
			m.app.logs.Log(hopsock.LevelError, msg.err.Error())
			break
		}
		st.state, st.msg = "exited", msg.l.name+" exited"+errSuffix(msg.err)
		m.app.logs.Log(hopsock.LevelInfo, st.msg)
		// Only the -browser/-exec process ends the session; browsers opened
		// from the picker don't.
		if msg.l == m.app.launch && !m.app.cfg.stay {
			return m, tea.Quit
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		cmds = append(cmds, cmd)
	}
	return m, tea.Batch(cmds...)
}
