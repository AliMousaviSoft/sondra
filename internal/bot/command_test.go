package bot

import (
	"testing"
	"time"
)

func TestParseScanBasic(t *testing.T) {
	c, err := parseCommand("/scan example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "scan" || c.Domain != "example.com" || c.Preset != "quick" {
		t.Fatalf("got %+v", c)
	}
}

func TestParseScanFullFlags(t *testing.T) {
	c, err := parseCommand("/scan example.com full --modules subfinder,httpx --exclude a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Preset != "full" {
		t.Fatalf("preset: %q", c.Preset)
	}
	if len(c.Modules) != 2 || c.Modules[0] != "subfinder" || c.Modules[1] != "httpx" {
		t.Fatalf("modules: %v", c.Modules)
	}
	if len(c.Exclude) != 1 || c.Exclude[0] != "a.example.com" {
		t.Fatalf("exclude: %v", c.Exclude)
	}
}

func TestParseInlineFlagForm(t *testing.T) {
	c, err := parseCommand("/scan example.com --modules=subfinder,crtsh")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Modules) != 2 {
		t.Fatalf("inline --modules= not parsed: %v", c.Modules)
	}
}

func TestParseMonitor(t *testing.T) {
	c, err := parseCommand("/monitor example.com --interval 2h --on findings")
	if err != nil {
		t.Fatal(err)
	}
	if c.Interval != 2*time.Hour {
		t.Fatalf("interval: %v", c.Interval)
	}
	if c.OnMode != "findings" {
		t.Fatalf("on: %q", c.OnMode)
	}
}

func TestParseStripsBotSuffix(t *testing.T) {
	c, err := parseCommand("/scan@SondraBot example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "scan" || c.Domain != "example.com" {
		t.Fatalf("@botname not stripped: %+v", c)
	}
}

func TestParseStopArg(t *testing.T) {
	c, err := parseCommand("/stop 3")
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "stop" || c.Arg != "3" {
		t.Fatalf("got %+v", c)
	}
}

func TestParseUnknownFlagErrors(t *testing.T) {
	if _, err := parseCommand("/scan example.com --bogus"); err == nil {
		t.Fatal("expected error for unknown flag")
	}
}

func TestParseBadInterval(t *testing.T) {
	if _, err := parseCommand("/monitor example.com --interval notaduration"); err == nil {
		t.Fatal("expected error for bad interval")
	}
}
