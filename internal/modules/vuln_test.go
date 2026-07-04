package modules

import "testing"

func TestParseNucleiLineNested(t *testing.T) {
	line := []byte(`{"template-id":"CVE-2024-1","info":{"name":"Some CVE","severity":"critical"},"host":"h.example.com","matched-at":"https://h.example.com/x"}`)
	f, ok := parseNucleiLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if f.name != "Some CVE" || f.severity != "critical" || f.where != "https://h.example.com/x" {
		t.Fatalf("wrong parse: %+v", f)
	}
}

func TestParseNucleiLineFlat(t *testing.T) {
	line := []byte(`{"template-id":"t","name":"Flat Finding","severity":"high","host":"h.example.com"}`)
	f, ok := parseNucleiLine(line)
	if !ok {
		t.Fatal("expected parse to succeed")
	}
	if f.name != "Flat Finding" || f.severity != "high" || f.where != "h.example.com" {
		t.Fatalf("wrong parse: %+v", f)
	}
}

func TestParseNucleiLineFallbacks(t *testing.T) {
	// No name anywhere but a template-id → use template-id, default severity.
	f, ok := parseNucleiLine([]byte(`{"template-id":"only-id","host":"h"}`))
	if !ok || f.name != "only-id" || f.severity != "unknown" {
		t.Fatalf("fallback parse wrong: %+v ok=%v", f, ok)
	}
	// Non-JSON must be rejected, not panic.
	if _, ok := parseNucleiLine([]byte(`not json`)); ok {
		t.Fatal("garbage line should not parse")
	}
}
