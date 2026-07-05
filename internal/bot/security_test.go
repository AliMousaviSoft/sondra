package bot

import "testing"

func TestValidDomain(t *testing.T) {
	valid := []string{"example.com", "sub.example.com", "a.b.c.example.co.uk", "EXAMPLE.COM", "x-y.example.com"}
	for _, d := range valid {
		if !validDomain(d) {
			t.Errorf("expected valid: %q", d)
		}
	}

	// The injection gate: anything that isn't a bare hostname must be rejected.
	invalid := []string{
		"", "localhost", "example", "-flag", "http://example.com",
		"example.com; rm -rf /", "example.com && id", "a b.com", "exa mple.com",
		"example.com/path", "$(whoami).com", "`id`.com", "example..com", ".com",
	}
	for _, d := range invalid {
		if validDomain(d) {
			t.Errorf("expected INVALID (injection risk): %q", d)
		}
	}
}

func TestValidExcludes(t *testing.T) {
	if !validExcludes([]string{"a.example.com", "b.example.com"}) {
		t.Fatal("valid excludes rejected")
	}
	if validExcludes([]string{"a.example.com", "bad; rm"}) {
		t.Fatal("malicious exclude accepted")
	}
}
