package report

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseNucleiJSONLNestedAndFlat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "findings.jsonl")
	content := `{"template-id":"CVE-1","info":{"name":"Nested CVE","severity":"critical"},"host":"a","matched-at":"https://a/x"}
{"template-id":"t2","name":"Flat One","severity":"high","host":"b","matched-at":"https://b"}
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	got := parseNucleiJSONL(path)
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}
	if got[0].Name != "Nested CVE" || got[0].Severity != "critical" {
		t.Fatalf("nested finding parsed wrong: %+v", got[0])
	}
	if got[1].Name != "Flat One" || got[1].Severity != "high" {
		t.Fatalf("flat finding parsed wrong: %+v", got[1])
	}
}
