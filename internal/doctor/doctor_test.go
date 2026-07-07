package doctor

import (
	"testing"

	"github.com/AliMousaviSoft/sondra/internal/config"
)

func TestToolsWellFormed(t *testing.T) {
	for _, tl := range Tools {
		if tl.Kind == Binary {
			if tl.Bin == "" || tl.Install == "" {
				t.Errorf("%s: a binary tool needs both Bin and Install", tl.Name)
			}
		} else if tl.Bin != "" {
			t.Errorf("%s: a built-in tool must not set Bin", tl.Name)
		}
	}
}

func TestCheckBuiltinsAlwaysFound(t *testing.T) {
	for _, r := range Check() {
		if r.Kind == Builtin && !r.Found {
			t.Errorf("built-in %s should always be found", r.Name)
		}
	}
}

func has(bins []string) map[string]bool {
	m := map[string]bool{}
	for _, b := range bins {
		m[b] = true
	}
	return m
}

func TestRequiredBinariesQuick(t *testing.T) {
	got := has(requiredBinaries(config.PresetModules("quick")))
	for _, want := range []string{"dnsx", "httpx", "nuclei"} {
		if !got[want] {
			t.Errorf("quick preset should require %s: %v", want, got)
		}
	}
	if got["naabu"] || got["gau"] {
		t.Errorf("quick preset should not require naabu/gau: %v", got)
	}
}

func TestRequiredBinariesPassiveIsBuiltinPlusAssetfinder(t *testing.T) {
	// passive = subfinder + assetfinder + crtsh; only assetfinder is a binary,
	// and with no httpx/naabu there's no dnsx resolve step.
	got := requiredBinaries(config.PresetModules("passive"))
	if len(got) != 1 || got[0] != "assetfinder" {
		t.Fatalf("passive should require only assetfinder, got %v", got)
	}
}
