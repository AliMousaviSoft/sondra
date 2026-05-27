package tui

import (
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/AliMousaviSoft/sondra/internal/config"
)

type State int

const (
	StateSelecting State = iota
	StateRunning
	StateDone
)

type LogMsg LogEntry

type StepUpdate struct {
	Label   string
	Current int
	Total   int
}

type stepUpdateMsg StepUpdate
type doneMsg struct{ err error }
type tickMsg time.Time

type Runner interface {
	Build(mods config.ModuleFlags)
	RunSync() error
	StepTotal() int
}

type Model struct {
	cfg    *config.Config
	state  State
	width  int
	height int

	header   HeaderModel
	logView  viewport.Model
	selector SelectorModel
	spinner  spinner.Model

	step    StepUpdate
	start   time.Time
	elapsed time.Duration

	logMu      sync.Mutex
	logEntries []LogEntry
	logContent string

	logCh      chan LogEntry
	progressCh chan StepUpdate

	runner  Runner
	doneErr error
}

func NewModel(cfg *config.Config) *Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("#E84855"))

	return &Model{
		cfg:        cfg,
		state:      StateSelecting,
		spinner:    s,
		logCh:      make(chan LogEntry, 512),
		progressCh: make(chan StepUpdate, 64),
		selector:   NewSelectorModel(cfg),
		header:     NewHeaderModel(cfg.Domain),
	}
}

func (m *Model) LogCh() chan<- LogEntry        { return m.logCh }
func (m *Model) ProgressCh() chan<- StepUpdate { return m.progressCh }
func (m *Model) SetRunner(r Runner)            { m.runner = r }

// StartImmediate transitions to running state before the bubbletea loop
// starts. Used when -y is passed to bypass the selector entirely.
func (m *Model) StartImmediate() {
	m.state = StateRunning
	m.start = time.Now()
	// Initialize with safe defaults — will be resized on first WindowSizeMsg.
	m.logView = viewport.New(80, 24)
	m.logView.SetContent("")
}

func (m *Model) Init() tea.Cmd {
	cmds := []tea.Cmd{
		m.spinner.Tick,
		listenLog(m.logCh),
		listenProgress(m.progressCh),
	}
	// Already in running state (via -y): kick off the pipeline immediately.
	if m.state == StateRunning {
		cmds = append(cmds,
			tickCmd(),
			func() tea.Msg {
				err := m.runner.RunSync()
				return doneMsg{err: err}
			},
		)
	}
	return tea.Batch(cmds...)
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.resizeViewport()

	case tea.KeyMsg:
		switch m.state {
		case StateSelecting:
			newSel, cmd, start := m.selector.Update(msg)
			m.selector = newSel
			cmds = append(cmds, cmd)
			if start {
				cmds = append(cmds, m.startScan())
			}
		case StateRunning:
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
		case StateDone:
			return m, tea.Quit
		}

	case LogMsg:
		entry := LogEntry(msg)
		m.logMu.Lock()
		m.logEntries = append(m.logEntries, entry)
		m.logContent += renderLogEntry(entry) + "\n"
		m.logMu.Unlock()
		m.logView.SetContent(m.logContent)
		if m.logView.Height > 0 {
			m.logView.GotoBottom()
		}
		cmds = append(cmds, listenLog(m.logCh))

	case stepUpdateMsg:
		m.step = StepUpdate(msg)
		m.header.SetStep(m.step)
		cmds = append(cmds, listenProgress(m.progressCh))

	case doneMsg:
		m.doneErr = msg.err
		m.state = StateDone
		m.header.SetDone(msg.err)

	case tickMsg:
		if m.state == StateRunning {
			m.elapsed = time.Since(m.start)
			m.header.SetElapsed(m.elapsed)
			cmds = append(cmds, tickCmd())
		}

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *Model) View() string {
	switch m.state {
	case StateSelecting:
		return m.selector.View()

	case StateRunning:
		header := m.header.View(m.spinner)
		headerHeight := lipgloss.Height(header)
		m.logView.Height = m.height - headerHeight
		return header + "\n" + m.logView.View()

	case StateDone:
		header := m.header.View(m.spinner)
		headerHeight := lipgloss.Height(header)
		m.logView.Height = m.height - headerHeight - 3
		return header + "\n" + m.logView.View() + "\n" + m.renderSummary()
	}
	return ""
}

// startScan is called when the user hits Enter in the selector.
func (m *Model) startScan() tea.Cmd {
	m.state = StateRunning
	m.start = time.Now()
	m.logView = viewport.New(m.width, m.height-6)
	m.logView.SetContent("")

	mods := m.selector.SelectedModules()
	m.runner.Build(mods)

	return tea.Batch(
		tickCmd(),
		func() tea.Msg {
			err := m.runner.RunSync()
			return doneMsg{err: err}
		},
	)
}

func (m *Model) resizeViewport() {
	headerHeight := m.header.Height()
	m.logView = viewport.New(m.width, m.height-headerHeight)
	m.logView.SetContent(m.logContent)
	m.logView.GotoBottom()
}

func (m *Model) renderSummary() string {
	style := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#E84855")).
		Padding(0, 2).
		Width(m.width - 4)

	if m.doneErr != nil {
		return style.Render(fmt.Sprintf("  ✗ Scan failed: %v\n  Press any key to exit.", m.doneErr))
	}
	return style.Render(
		fmt.Sprintf("  ✓ Scan complete in %s\n  Press any key to exit.", m.elapsed.Round(time.Second)),
	)
}

func listenLog(ch chan LogEntry) tea.Cmd {
	return func() tea.Msg {
		entry, ok := <-ch
		if !ok {
			return nil
		}
		return LogMsg(entry)
	}
}

func listenProgress(ch chan StepUpdate) tea.Cmd {
	return func() tea.Msg {
		update, ok := <-ch
		if !ok {
			return nil
		}
		return stepUpdateMsg(update)
	}
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}