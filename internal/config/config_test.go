package config

import "testing"

func TestParseModules(t *testing.T) {
	m, err := ParseModules([]string{"subfinder", "crtsh", "httpx", "nuclei"})
	if err != nil {
		t.Fatalf("ParseModules: %v", err)
	}
	if !m.Subfinder || !m.Crtsh || !m.Httpx {
		t.Fatalf("expected subfinder/crtsh/httpx enabled: %+v", m)
	}
	if !m.NucleiHigh || !m.NucleiMedium {
		t.Fatalf("'nuclei' should enable both high and medium: %+v", m)
	}
	if m.Naabu || m.Gowitness {
		t.Fatalf("unlisted modules must stay off: %+v", m)
	}
}

func TestParseModulesAliasesAndGranular(t *testing.T) {
	m, err := ParseModules([]string{"ports", "screenshots", "nuclei-high", "wayback", "js"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Naabu || !m.Gowitness || !m.NucleiHigh || !m.Gowayback || !m.JSAnalysis {
		t.Fatalf("aliases wrong: %+v", m)
	}
	if m.NucleiMedium {
		t.Fatal("nuclei-high must NOT enable medium")
	}
}

func TestParseModulesUnknown(t *testing.T) {
	if _, err := ParseModules([]string{"subfinder", "bogus"}); err == nil {
		t.Fatal("expected error for unknown module")
	}
}
