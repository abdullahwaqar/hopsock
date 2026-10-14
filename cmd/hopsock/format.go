package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/abdullahwaqar/hopsock"
)

func label(s string) string {
	return sMuted.Render(fmt.Sprintf("%-7s", s)) + " "
}

func routeText(a *app) string {
	parts := []string{"socks5://" + a.proxyAddr}
	for _, h := range a.chain.Hops {
		parts = append(parts, h.Label)
	}
	return strings.Join(append(parts, "internet"), " → ")
}

func routeStyled(a *app) string {
	arrow := sMuted.Render(" → ")
	parts := []string{sAcc.Render("socks5://" + a.proxyAddr)}
	for _, h := range a.chain.Hops {
		parts = append(parts, sText.Render(h.Label))
	}
	if len(a.chain.Hops) == 0 {
		parts = append(parts, sWarn.Render("direct (no -F hops)"))
	}
	return strings.Join(append(parts, sMuted.Render("internet")), arrow)
}

func exitText(e *hopsock.ExitInfo) string {
	if e == nil {
		return ""
	}
	parts := []string{}
	if e.IP != "" {
		parts = append(parts, e.IP)
	} else {
		parts = append(parts, firstLine(truncate(e.Raw, 80)))
	}
	if e.Location != "" {
		parts = append(parts, e.Location)
	}
	if e.Org != "" {
		parts = append(parts, e.Org)
	}
	parts = append(parts, e.Latency.Round(time.Millisecond).String())
	return strings.Join(parts, " · ")
}

func exitStyled(e *hopsock.ExitInfo) string {
	ip := e.IP
	if ip == "" {
		ip = firstLine(e.Raw)
	}
	s := sBold.Render(ip)
	if e.Location != "" {
		s += sMuted.Render(" · ") + sText.Render(e.Location)
	}
	if e.Org != "" {
		s += sMuted.Render(" · " + e.Org)
	}
	return s + sMuted.Render(" · "+e.Latency.Round(time.Millisecond).String())
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// truncate cuts a (possibly styled) string to n display cells.
func truncate(s string, n int) string {
	if n <= 1 || lipgloss.Width(s) <= n {
		return s
	}
	return lipgloss.NewStyle().MaxWidth(n-1).Render(s) + "…"
}
