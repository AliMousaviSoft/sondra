package bot

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreRoundTrip(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	defer st.close()

	recs := []jobRecord{
		{ID: 3, Kind: "monitor", Transport: "telegram", Dest: "12345", Spec: monitorSpec{
			Domain: "example.com", Preset: "quick", Interval: 6 * time.Hour, OnMode: "findings",
			Modules: []string{"subfinder", "httpx"}, Exclude: []string{"dev.example.com"},
		}},
		{ID: 5, Kind: "monitor", Transport: "discord", Dest: "999", Spec: monitorSpec{
			Domain: "test.com", Preset: "full", Interval: 90 * time.Minute, OnMode: "all",
		}},
	}
	for _, r := range recs {
		if err := st.save(r); err != nil {
			t.Fatalf("save #%d: %v", r.ID, err)
		}
	}

	got, err := st.loadAll()
	if err != nil {
		t.Fatalf("loadAll: %v", err)
	}
	if len(got) != 2 || got[0].ID != 3 || got[1].ID != 5 {
		t.Fatalf("ids/order: %+v", got)
	}

	r0 := got[0]
	if r0.Transport != "telegram" || r0.Dest != "12345" {
		t.Errorf("transport/dest: %+v", r0)
	}
	if r0.Spec.Interval != 6*time.Hour || r0.Spec.OnMode != "findings" {
		t.Errorf("spec scalars: %+v", r0.Spec)
	}
	if len(r0.Spec.Modules) != 2 || r0.Spec.Modules[0] != "subfinder" {
		t.Errorf("modules: %v", r0.Spec.Modules)
	}
	if len(r0.Spec.Exclude) != 1 || r0.Spec.Exclude[0] != "dev.example.com" {
		t.Errorf("exclude: %v", r0.Spec.Exclude)
	}
	// empty modules/exclude must round-trip to nil, not [""]
	if len(got[1].Spec.Modules) != 0 || len(got[1].Spec.Exclude) != 0 {
		t.Errorf("empty csv should decode to nil: %+v", got[1].Spec)
	}

	// save with an existing id upserts rather than duplicating
	r0.Spec.Preset = "vuln"
	if err := st.save(r0); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if err := st.delete(5); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err = st.loadAll()
	if err != nil {
		t.Fatalf("loadAll after delete: %v", err)
	}
	if len(got) != 1 || got[0].ID != 3 || got[0].Spec.Preset != "vuln" {
		t.Fatalf("after upsert+delete: %+v", got)
	}
}

func TestJobsAddWithID(t *testing.T) {
	j := newJobs()
	ctx := context.Background()

	job, _ := j.addWithID(ctx, 5, "monitor", "example.com", "quick")
	if job.ID != 5 {
		t.Fatalf("want resumed id 5, got %d", job.ID)
	}
	// a fresh add must not collide with the resumed id
	if next, _ := j.add(ctx, "scan", "b.com", "quick"); next.ID <= 5 {
		t.Fatalf("counter not advanced past resumed id: got %d", next.ID)
	}
}
