package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"

	"github.com/abdullahwaqar/hopsock"
	"github.com/abdullahwaqar/hopsock/internal/pathx"
)

const panelLines = 4 // route, exit, ssh, launch

func (m *model) layout() {
	w := max(m.width, 40)
	inner := w - 2
	// header(1) + panel(panelLines+2) + stats(1) + gaps(3) + titles(2) + help(1)
	fixed := 1 + panelLines + 2 + 1 + 3 + 2 + 1
	rest := max(m.height-fixed, 6)
	tblH := max(rest*2/5, 3)
	logH := max(rest-tblH, 3)

	cAge, cBytes := 7, 9
	cClient := min(21, max(inner/5, 10))
	cTarget := max(inner-cClient-cAge-2*cBytes-10, 12)
	m.tbl.SetColumns([]table.Column{
		{Title: "TARGET", Width: cTarget},
		{Title: "CLIENT", Width: cClient},
		{Title: "AGE", Width: cAge},
		{Title: "↑ SENT", Width: cBytes},
		{Title: "↓ RECV", Width: cBytes},
	})
	m.tbl.SetWidth(inner)
	m.tbl.SetHeight(tblH)
	m.vp.Width = inner
	m.vp.Height = logH
	m.help.Width = w
	m.refreshTable()
	m.refreshLog()
}

func (m *model) refreshTable() {
	rows := make([]table.Row, 0, len(m.snap.Active))
	for i := len(m.snap.Active) - 1; i >= 0; i-- { // newest first
		c := m.snap.Active[i]
		rows = append(rows, table.Row{c.Target, c.Client, humanDur(time.Since(c.Start)), humanBytes(c.Up), humanBytes(c.Down)})
	}
	m.tbl.SetRows(rows)
}

func (m *model) refreshLog() {
	var b strings.Builder
	width := max(m.vp.Width, 20)
	for _, l := range m.lines {
		if l.level == hopsock.LevelDebug && !m.showDebug {
			continue
		}
		var lv lipgloss.Style
		switch l.level {
		case hopsock.LevelDebug:
			lv = sMuted
		case hopsock.LevelInfo:
			lv = sAcc
		case hopsock.LevelWarn:
			lv = sWarn
		default:
			lv = sErr
		}
		msg := l.msg
		if room := width - 14; room > 0 && lipgloss.Width(msg) > room {
			msg = truncate(msg, room)
		}
		fmt.Fprintf(&b, "%s %s %s\n", sMuted.Render(l.t.Format("15:04:05")), lv.Render(l.level.String()), sText.Render(msg))
	}
	m.vp.SetContent(strings.TrimRight(b.String(), "\n"))
	if m.follow {
		m.vp.GotoBottom()
	}
}

func (m model) View() string {
	if m.width == 0 {
		return "starting…"
	}
	w := m.width
	var out []string

	status := m.statusPill()
	up := sMuted.Render("up " + humanDur(time.Since(m.app.started)))
	left := sBrand.Render("hopsock") + "  " + status
	gap := max(w-lipgloss.Width(left)-lipgloss.Width(up), 1)
	out = append(out, left+strings.Repeat(" ", gap)+up, "")

	inner := w - 4
	lines := []string{
		label("route") + truncate(routeStyled(m.app), inner-8),
		label("exit") + truncate(m.exitLine(), inner-8),
		label("ssh") + truncate(m.sshLine(), inner-8),
		label("launch") + truncate(m.launchLine(), inner-8),
	}
	out = append(out, sPanel.Width(w-2).Render(strings.Join(lines, "\n")))

	s := m.snap
	failed := ""
	if s.Failed > 0 {
		failed = sErr.Render(fmt.Sprintf(" (%d failed)", s.Failed))
	}
	stats := strings.Join([]string{
		sMuted.Render("active ") + sBold.Render(fmt.Sprint(len(s.Active))),
		sMuted.Render("total ") + sBold.Render(fmt.Sprint(s.Total)) + failed,
		sMuted.Render("↑ ") + sBold.Render(humanBytes(s.Up)) + sMuted.Render(" "+humanBytes(int64(m.rateUp))+"/s"),
		sMuted.Render("↓ ") + sBold.Render(humanBytes(s.Down)) + sMuted.Render(" "+humanBytes(int64(m.rateDown))+"/s"),
	}, sMuted.Render("   │   "))
	out = append(out, " "+stats, "")

	tblTitle := "CONNECTIONS"
	logTitle := "LOG"
	if m.focusLog {
		logTitle = sAcc.Render("▸ LOG")
		tblTitle = sTitle.Render(tblTitle)
	} else {
		tblTitle = sAcc.Render("▸ CONNECTIONS")
		logTitle = sTitle.Render(logTitle)
	}
	if !m.follow {
		logTitle += sWarn.Render("  (paused, f to follow)")
	}
	if !m.showDebug {
		logTitle += sMuted.Render("  (v for per-connection lines)")
	}
	block := lipgloss.NewStyle().Height(m.tbl.Height() + 1).PaddingLeft(1)
	switch {
	case m.picking:
		out = append(out, " "+sAcc.Render("▸ OPEN BROWSER THROUGH THE PROXY"), block.Render(m.pickerView()))
	case len(s.Active) == 0:
		empty := sMuted.Render("no open connections, point an app at socks5://" + m.app.proxyAddr)
		out = append(out, " "+tblTitle, block.Render(empty))
	default:
		out = append(out, " "+tblTitle, lipgloss.NewStyle().PaddingLeft(1).Render(m.tbl.View()))
	}
	out = append(out, "", " "+logTitle)
	out = append(out, lipgloss.NewStyle().PaddingLeft(1).Render(m.vp.View()))

	if m.picking {
		out = append(out, " "+m.help.ShortHelpView([]key.Binding{
			key.NewBinding(key.WithKeys("up"), key.WithHelp("↑/↓", "choose")), keys.Pick, keys.Cancel,
		}))
	} else {
		hk := keys
		hk.Retest.SetEnabled(m.app.cfg.testURL != "")
		out = append(out, " "+m.help.View(hk))
	}

	return lipgloss.NewStyle().MaxHeight(m.height).Render(strings.Join(out, "\n"))
}

func (m model) statusPill() string {
	switch {
	case m.testing:
		return m.spin.View() + sAcc.Render(" testing chain")
	case m.testErr != nil:
		return sErr.Render("✕ test failed") + sMuted.Render(" (t to retry)")
	case m.app.cfg.testURL == "" || m.exit != nil:
		return sOK.Render("● ready") + sMuted.Render("  socks5://"+m.app.proxyAddr)
	}
	return sMuted.Render("○ starting")
}

func (m model) exitLine() string {
	switch {
	case m.app.cfg.testURL == "":
		return sMuted.Render("not tested (-test off)")
	case m.testing && m.exit == nil:
		return sMuted.Render("checking " + m.app.cfg.testURL + " …")
	case m.testErr != nil:
		return sErr.Render(m.testErr.Error())
	case m.exit != nil:
		return exitStyled(m.exit)
	}
	return sMuted.Render("pending")
}

func (m model) sshLine() string {
	ss := m.app.chain.SSH()
	if len(ss) == 0 {
		return sMuted.Render("no ssh hops")
	}
	var parts []string
	for _, s := range ss {
		st := s.State()
		name := s.Config.User + "@" + s.Addr
		switch {
		case st.Connected:
			parts = append(parts, sOK.Render("● ")+sText.Render(name)+sMuted.Render(" up "+humanDur(time.Since(st.Since))))
		case st.LastErr != nil:
			parts = append(parts, sErr.Render("✕ ")+sText.Render(name)+sErr.Render(" "+firstLine(st.LastErr.Error())))
		default:
			parts = append(parts, m.spin.View()+" "+sText.Render(name)+sMuted.Render(" connecting"))
		}
	}
	return strings.Join(parts, sMuted.Render("  ·  "))
}

func (m model) launchLine() string {
	var parts []string
	for _, l := range []*launcher{m.app.launch, m.manual} {
		if l == nil {
			continue
		}
		st := m.status(l)
		switch st.state {
		case "waiting":
			parts = append(parts, sMuted.Render("waiting for preflight: ")+sText.Render(l.desc))
		case "running":
			parts = append(parts, sOK.Render("● ")+sText.Render(l.desc))
		case "failed":
			parts = append(parts, sErr.Render(st.msg))
		case "exited":
			parts = append(parts, sMuted.Render(st.msg+" (b to reopen)"))
		default:
			parts = append(parts, sText.Render(l.desc))
		}
	}
	if len(parts) == 0 {
		return sMuted.Render("no browser open, press b to pick one")
	}
	return strings.Join(parts, sMuted.Render("  ·  "))
}

func (m model) pickerView() string {
	width := 0
	for _, br := range m.pickList {
		width = max(width, len(br.Label))
	}
	var b strings.Builder
	for i, br := range m.pickList {
		name := fmt.Sprintf("%-*s", width, br.Label)
		if i == m.pickIdx {
			b.WriteString(sAcc.Render("› ") + sBold.Render(name))
		} else {
			b.WriteString("  " + sText.Render(name))
		}
		b.WriteString("  " + sMuted.Render(br.Path) + "\n")
	}
	prof := "your normal profile (must be closed first)"
	if m.app.cfg.profile != "" {
		prof = "profile " + pathx.ExpandHome(m.app.cfg.profile)
	}
	b.WriteString("\n" + sMuted.Render("opens with "+prof))
	return b.String()
}
