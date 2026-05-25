package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/lipgloss"
)

// ──────────────────────────────────────────────
// Styles
// ──────────────────────────────────────────────

var (
	colorRed    = lipgloss.Color("#E84855")
	colorDim    = lipgloss.Color("#555555")
	colorBright = lipgloss.Color("#EFEFEF")
	colorGreen  = lipgloss.Color("#39D353")
	colorYellow = lipgloss.Color("#E3B341")
	colorBlue   = lipgloss.Color("#58A6FF")

	styleBrand = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorRed).
			PaddingRight(1)

	styleDomain = lipgloss.NewStyle().
			Bold(true).
			Foreground(colorBright)

	styleHeaderDim = lipgloss.NewStyle().
			Foreground(colorDim)

	styleHeaderVal = lipgloss.NewStyle().
			Foreground(colorBlue)

	styleProgressBar = lipgloss.NewStyle().
				Foreground(colorRed)

	styleProgressTrack = lipgloss.NewStyle().
				Foreground(colorDim)

	styleSep = lipgloss.NewStyle().
			Foreground(colorDim)

	styleDoneOK  = lipgloss.NewStyle().Foreground(colorGreen).Bold(true)
	styleDoneFail = lipgloss.NewStyle().Foreground(colorRed).Bold(true)
)

// ──────────────────────────────────────────────
// HeaderModel
// ──────────────────────────────────────────────

// HeaderModel holds the state needed to render the fixed header.
// bubbletea manages the full terminal so this region never scrolls.
type HeaderModel struct {
	domain      string
	step        StepUpdate
	elapsed     time.Duration
	done        bool
	doneErr     error
	lastStep    string
}

// NewHeaderModel constructs a HeaderModel for the given domain.
func NewHeaderModel(domain string) HeaderModel {
	return HeaderModel{domain: domain}
}

// SetStep updates progress information.
func (h *HeaderModel) SetStep(s StepUpdate) {
	if h.step.Label != "" {
		h.lastStep = h.step.Label
	}
	h.step = s
}

// SetElapsed updates the elapsed timer display.
func (h *HeaderModel) SetElapsed(d time.Duration) {
	h.elapsed = d
}

// SetDone marks the scan as finished.
func (h *HeaderModel) SetDone(err error) {
	h.done = true
	h.doneErr = err
	if h.step.Label != "" {
		h.lastStep = h.step.Label
	}
}

// Height returns the fixed line count of the header (used to size the viewport).
func (h *HeaderModel) Height() int {
	return 6 // brand + step line + progress bar + separator + last step + blank
}

// View renders the header as a string. bubbletea places this at the top of the
// screen before the viewport, so it is structurally immune to scroll.
func (h HeaderModel) View(sp spinner.Model) string {
	var sb strings.Builder

	// ── Line 1: brand + domain + elapsed + step counter ──────────────────
	brand := styleBrand.Render("sondra")
	domain := styleDomain.Render(h.domain)

	elapsed := styleHeaderDim.Render("elapsed") + " " +
		styleHeaderVal.Render(fmtDuration(h.elapsed))

	var stepCounter string
	if h.step.Total > 0 {
		stepCounter = styleHeaderDim.Render("step") + " " +
			styleHeaderVal.Render(fmt.Sprintf("%d/%d", h.step.Current, h.step.Total))
	}

	line1 := brand + "  " + domain + "    " + elapsed
	if stepCounter != "" {
		line1 += "    " + stepCounter
	}
	sb.WriteString(line1 + "\n")

	// ── Line 2: spinner + current step label ─────────────────────────────
	var line2 string
	if h.done {
		if h.doneErr != nil {
			line2 = styleDoneFail.Render("✗ failed: ") + styleHeaderDim.Render(h.doneErr.Error())
		} else {
			line2 = styleDoneOK.Render("✓ complete")
		}
	} else if h.step.Label != "" {
		line2 = sp.View() + " " + styleHeaderVal.Render(h.step.Label) + styleHeaderDim.Render(" running…")
	} else {
		line2 = styleHeaderDim.Render("initializing…")
	}
	sb.WriteString(line2 + "\n")

	// ── Line 3: progress bar ──────────────────────────────────────────────
	sb.WriteString(renderProgressBar(h.step.Current, h.step.Total, 40) + "\n")

	// ── Line 4: separator ─────────────────────────────────────────────────
	sb.WriteString(styleSep.Render(strings.Repeat("─", 60)) + "\n")

	// ── Line 5: last completed step ───────────────────────────────────────
	if h.lastStep != "" {
		sb.WriteString(styleHeaderDim.Render("last: ") + styleHeaderDim.Render(h.lastStep) + "\n")
	} else {
		sb.WriteString("\n")
	}

	return sb.String()
}

// ──────────────────────────────────────────────
// Progress bar
// ──────────────────────────────────────────────

// renderProgressBar renders a text-based progress bar of fixed width.
func renderProgressBar(current, total, width int) string {
	if total == 0 {
		return styleProgressTrack.Render(strings.Repeat("░", width))
	}

	pct := float64(current) / float64(total)
	filled := int(pct * float64(width))
	if filled > width {
		filled = width
	}
	empty := width - filled

	bar := styleProgressBar.Render(strings.Repeat("█", filled)) +
		styleProgressTrack.Render(strings.Repeat("░", empty))

	pctStr := styleHeaderDim.Render(fmt.Sprintf(" %3.0f%%", pct*100))
	return bar + pctStr
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}
