package tui

import (
	"fmt"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/AliMousaviSoft/sondra/internal/config"
)

// ──────────────────────────────────────────────
// Module item definition
// ──────────────────────────────────────────────

// ModuleItem represents one selectable module in the TUI.
type ModuleItem struct {
	ID          string
	Name        string
	Description string
	// Binary is the tool name checked with exec.LookPath.
	// Empty string means it's a Go lib — always available.
	Binary    string
	Selected  bool
	Available bool // false if Binary is set but not found in PATH
}

// ──────────────────────────────────────────────
// Selector model
// ──────────────────────────────────────────────

// SelectorModel is the interactive checkbox module picker.
type SelectorModel struct {
	items    []ModuleItem
	cursor   int
	cfg      *config.Config
	quitting bool
	starting bool // set to true when user presses Enter/Space to start
}

// NewSelectorModel builds a SelectorModel from the config.
// It probes PATH for each external binary and marks unavailable ones.
func NewSelectorModel(cfg *config.Config) SelectorModel {
	items := defaultModuleItems()

	// Probe availability.
	for i := range items {
		if items[i].Binary == "" {
			items[i].Available = true
		} else {
			_, err := exec.LookPath(items[i].Binary)
			items[i].Available = err == nil
		}
	}

	// Apply preset defaults.
	mods := config.PresetModules(cfg.Preset)
	applyPreset(items, mods)

	return SelectorModel{
		items: items,
		cfg:   cfg,
	}
}

// Update handles keyboard input for the selector.
// Returns (updated model, cmd, startScan bool).
func (s SelectorModel) Update(msg tea.KeyMsg) (SelectorModel, tea.Cmd, bool) {
	switch msg.String() {
	case "up", "k":
		if s.cursor > 0 {
			s.cursor--
		}
	case "down", "j":
		if s.cursor < len(s.items)-1 {
			s.cursor++
		}
	case " ":
		if s.items[s.cursor].Available {
			s.items[s.cursor].Selected = !s.items[s.cursor].Selected
		}
	case "a":
		// Select all available.
		for i := range s.items {
			if s.items[i].Available {
				s.items[i].Selected = true
			}
		}
	case "n":
		// Deselect all.
		for i := range s.items {
			s.items[i].Selected = false
		}
	case "f":
		applyPreset(s.items, config.PresetModules("full"))
	case "1":
    	applyPreset(s.items, config.PresetModules("full"))
	case "2":
		applyPreset(s.items, config.PresetModules("quick"))
	case "3":
		applyPreset(s.items, config.PresetModules("passive"))
	case "4":
		applyPreset(s.items, config.PresetModules("enum"))
	case "5":
		applyPreset(s.items, config.PresetModules("vuln"))
	case "p":
		applyPreset(s.items, config.PresetModules("passive"))
	case "enter":
		s.starting = true
		return s, nil, true
	case "ctrl+c", "q":
		s.quitting = true
		return s, tea.Quit, false
	}
	return s, nil, false
}

// SelectedModules returns a ModuleFlags struct for all selected items.
func (s SelectorModel) SelectedModules() config.ModuleFlags {
	var mods config.ModuleFlags
	for _, item := range s.items {
		if !item.Selected {
			continue
		}
		switch item.ID {
		case "subfinder":
			mods.Subfinder = true
		case "assetfinder":
			mods.Assetfinder = true
		case "crtsh":
			mods.Crtsh = true
		case "alterx":
			mods.Alterx = true
		case "massdns":
			mods.Massdns = true
		case "httpx":
			mods.Httpx = true
		case "takeover":
			mods.Takeover = true
		case "naabu":
			mods.Naabu = true
		case "gowitness":
			mods.Gowitness = true
		case "gau":
			mods.Gau = true
		case "katana":
			mods.Katana = true
		case "nuclei_high":
			mods.NucleiHigh = true
		case "nuclei_medium":
			mods.NucleiMedium = true
		}
	}
	return mods
}

// ──────────────────────────────────────────────
// View
// ──────────────────────────────────────────────

var (
	selectorTitle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#E84855")).
			MarginBottom(1)

	selectorSubtitle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#555555"))

	itemNormal = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC"))

	itemSelected = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#39D353")).
			Bold(true)

	itemUnavailable = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#444444")).
			Strikethrough(true)

	itemCursor = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#E84855")).
			Bold(true)

	itemDesc = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555"))

	keyHint = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#555555"))

	groupLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7A8FA6")).
			Bold(true).
			MarginTop(1)
)

// View renders the module selector screen.
func (s SelectorModel) View() string {
	var sb strings.Builder

	sb.WriteString(selectorTitle.Render("sondra") + "  " +
		selectorSubtitle.Render("select modules  ·  target: "+s.cfg.Domain) + "\n\n")

	groups := []struct {
		label string
		ids   []string
	}{
		{"passive enumeration", []string{"subfinder", "assetfinder", "crtsh"}},
		{"active bruteforce", []string{"alterx", "massdns"}},
		{"http + takeover", []string{"httpx", "takeover", "naabu"}},
		{"crawling + screenshots", []string{"gau", "katana", "gowitness"}},
		{"vulnerability scan", []string{"nuclei_high", "nuclei_medium"}},
	}

	idxMap := make(map[string]int, len(s.items))
	for i, it := range s.items {
		idxMap[it.ID] = i
	}

	for _, g := range groups {
		sb.WriteString(groupLabel.Render("  "+g.label) + "\n")
		for _, id := range g.ids {
			i, ok := idxMap[id]
			if !ok {
				continue
			}
			item := s.items[i]

			cursor := "  "
			if s.cursor == i {
				cursor = itemCursor.Render("▶ ")
			}

			checkbox := "[ ]"
			nameStyle := itemNormal
			if !item.Available {
				checkbox = "[ ]"
				nameStyle = itemUnavailable
			} else if item.Selected {
				checkbox = itemSelected.Render("[✓]")
				nameStyle = itemSelected
			}

			unavailTag := ""
			if !item.Available {
				unavailTag = lipgloss.NewStyle().
					Foreground(lipgloss.Color("#E84855")).
					Render(" (not installed)")
			}

			line := fmt.Sprintf("%s%s %s%s  %s",
				cursor,
				checkbox,
				nameStyle.Render(item.Name),
				unavailTag,
				itemDesc.Render(item.Description),
			)
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}

	// Key hints
	sb.WriteString(keyHint.Render(
		"  space toggle  ·  ↑↓/jk navigate  ·  a all  ·  n none\n" +
			"  1 full  ·  2 quick  ·  3 passive  ·  4 enum  ·  5 vuln  ·  enter start  ·  q quit",
	))

	return sb.String()
}

// ──────────────────────────────────────────────
// Default module list
// ──────────────────────────────────────────────

func defaultModuleItems() []ModuleItem {
	return []ModuleItem{
		{ID: "subfinder", Name: "subfinder", Description: "passive subdomain enum via APIs", Binary: ""},         // Go lib
		{ID: "assetfinder", Name: "assetfinder", Description: "cert transparency + web archives", Binary: "assetfinder"},
		{ID: "crtsh", Name: "crt.sh", Description: "certificate transparency HTTP query", Binary: ""},            // HTTP call
		{ID: "alterx", Name: "alterx", Description: "permutation-based subdomain generation", Binary: "alterx"},
		{ID: "massdns", Name: "massdns", Description: "high-speed DNS brute force", Binary: "massdns"},
		{ID: "httpx", Name: "httpx", Description: "2-phase probe: alive check + enrichment", Binary: ""},        // Go lib
		{ID: "takeover", Name: "nuclei takeover", Description: "subdomain takeover fingerprinting", Binary: "nuclei"},
		{ID: "naabu", Name: "naabu", Description: "port scanner for non-standard ports", Binary: ""},            // Go lib
		{ID: "gau", Name: "gau", Description: "URL collection from Wayback / CommonCrawl", Binary: "gau"},
		{ID: "katana", Name: "katana", Description: "active crawl + JS endpoint extraction", Binary: "katana"},
		{ID: "gowitness", Name: "gowitness", Description: "headless screenshots of live hosts", Binary: "gowitness"},
		{ID: "nuclei_high", Name: "nuclei (crit/high)", Description: "targeted templates: cves, misconfig, exposures", Binary: "nuclei"},
		{ID: "nuclei_medium", Name: "nuclei (medium)", Description: "background scan — runs async until report", Binary: "nuclei"},
	}
}

// applyPreset marks items selected/deselected according to ModuleFlags.
func applyPreset(items []ModuleItem, mods config.ModuleFlags) {
	flagMap := map[string]bool{
		"subfinder":    mods.Subfinder,
		"assetfinder":  mods.Assetfinder,
		"crtsh":        mods.Crtsh,
		"alterx":       mods.Alterx,
		"massdns":      mods.Massdns,
		"httpx":        mods.Httpx,
		"takeover":     mods.Takeover,
		"naabu":        mods.Naabu,
		"gau":          mods.Gau,
		"katana":       mods.Katana,
		"gowitness":    mods.Gowitness,
		"nuclei_high":  mods.NucleiHigh,
		"nuclei_medium": mods.NucleiMedium,
	}
	for i := range items {
		if sel, ok := flagMap[items[i].ID]; ok {
			items[i].Selected = sel && items[i].Available
		}
	}
}
