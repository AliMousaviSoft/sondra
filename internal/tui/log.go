package tui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/lipgloss"
)

// ──────────────────────────────────────────────
// Log types
// ──────────────────────────────────────────────

// LogLevel classifies a log entry.
type LogLevel int

const (
	LogInfo    LogLevel = iota
	LogSuccess          // green — step completed
	LogWarn             // yellow — non-fatal issue
	LogError            // red — fatal or notable failure
	LogDebug            // muted — verbose output
)

// LogEntry is a single structured log line.
type LogEntry struct {
	Time    time.Time
	Level   LogLevel
	Step    string // module name, e.g. "subfinder"
	Message string
}

// NewLog is a convenience constructor.
func NewLog(level LogLevel, step, msg string) LogEntry {
	return LogEntry{
		Time:    time.Now(),
		Level:   level,
		Step:    step,
		Message: msg,
	}
}

func Logf(level LogLevel, step, format string, args ...any) LogEntry {
	return NewLog(level, step, fmt.Sprintf(format, args...))
}

// ──────────────────────────────────────────────
// Rendering
// ──────────────────────────────────────────────

var (
	styleTime = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))

	styleStep = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Width(12).
			Align(lipgloss.Right)

	styleLevelInfo    = lipgloss.NewStyle().Foreground(lipgloss.Color("#7A8FA6"))
	styleLevelSuccess = lipgloss.NewStyle().Foreground(lipgloss.Color("#39D353"))
	styleLevelWarn    = lipgloss.NewStyle().Foreground(lipgloss.Color("#E3B341"))
	styleLevelError   = lipgloss.NewStyle().Foreground(lipgloss.Color("#E84855"))
	styleLevelDebug   = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))

	styleMsg = lipgloss.NewStyle().Foreground(lipgloss.Color("#CCCCCC"))
)

// levelPrefix returns a short colored prefix for the log level.
func levelPrefix(l LogLevel) string {
	switch l {
	case LogSuccess:
		return styleLevelSuccess.Render("✓")
	case LogWarn:
		return styleLevelWarn.Render("!")
	case LogError:
		return styleLevelError.Render("✗")
	case LogDebug:
		return styleLevelDebug.Render("·")
	default:
		return styleLevelInfo.Render("›")
	}
}

// renderLogEntry formats a single LogEntry into a display string.
// Format: HH:MM:SS  step_name  ✓ message
func renderLogEntry(e LogEntry) string {
	ts := styleTime.Render(e.Time.Format("15:04:05"))
	step := styleStep.Render(e.Step)
	prefix := levelPrefix(e.Level)
	msg := styleMsg.Render(e.Message)
	return fmt.Sprintf("%s  %s  %s %s", ts, step, prefix, msg)
}
