package tui

import "github.com/charmbracelet/lipgloss"

const asciiArt = `
███████╗ ██████╗ ███╗   ██╗██████╗ ██████╗  █████╗ 
██╔════╝██╔═══██╗████╗  ██║██╔══██╗██╔══██╗██╔══██╗
███████╗██║   ██║██╔██╗ ██║██║  ██║██████╔╝███████║
╚════██║██║   ██║██║╚██╗██║██║  ██║██╔══██╗██╔══██║
███████║╚██████╔╝██║ ╚████║██████╔╝██║  ██║██║  ██║
╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝`

var styleBannerArt = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#E84855")).
	Bold(true)

var styleBannerSub = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#555555"))

var styleBannerVersion = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#58A6FF"))

var styleBannerUpdate = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#39D353")).
	Bold(true)

var styleBannerOutdated = lipgloss.NewStyle().
	Foreground(lipgloss.Color("#E3B341")).
	Bold(true)

// RenderBanner returns the full startup banner string.
func RenderBanner(version, latestVersion string) string {
	art := styleBannerArt.Render(asciiArt)

	ver := styleBannerVersion.Render("v" + version)
	sub := styleBannerSub.Render("  automated bug bounty recon pipeline  ·  ")

	var updateLine string
	if latestVersion == "" {
		updateLine = styleBannerSub.Render("  version check failed")
	} else if version == latestVersion || version == "dev" {
		updateLine = styleBannerUpdate.Render("  ✓ up to date (" + latestVersion + ")")
	} else {
		updateLine = styleBannerOutdated.Render(
			"  ✗ update available: " + latestVersion + " → run: go install github.com/AliMousaviSoft/sondra/cmd/sondra@latest",
		)
	}

	return art + "\n" + sub + ver + "\n" + updateLine + "\n"
}