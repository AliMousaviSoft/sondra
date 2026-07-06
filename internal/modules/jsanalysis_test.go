package modules

import "testing"

func TestExtractEndpoints(t *testing.T) {
	js := `
		fetch("/api/v2/users?active=true");
		var u = 'https://api.example.com/v1/orders';
		axios.get("/internal/debug/config");
		img.src = "/logo.png";
		style = "/theme/app.css";
	`
	got := map[string]bool{}
	for _, e := range ExtractEndpoints(js) {
		got[e] = true
	}
	for _, want := range []string{
		"/api/v2/users?active=true",
		"https://api.example.com/v1/orders",
		"/internal/debug/config",
	} {
		if !got[want] {
			t.Errorf("missing endpoint %q; got %v", want, got)
		}
	}
	if got["/logo.png"] || got["/theme/app.css"] {
		t.Errorf("static assets should be filtered; got %v", got)
	}
}

func TestExtractSecrets(t *testing.T) {
	js := `
		const awsKey = "AKIAIOSFODNN7EXAMPLE";
		var g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";
		apiKey: "abcd1234efgh5678ijkl",
		var greeting = "hello world this is fine";
	`
	found := map[string]string{}
	for _, s := range ExtractSecrets(js) {
		found[s.Type] = s.Value
	}
	if found["AWS Access Key"] != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("AWS key: %v", found)
	}
	if _, ok := found["Google API Key"]; !ok {
		t.Errorf("Google API key not detected: %v", found)
	}
	if found["Generic API Key"] != "abcd1234efgh5678ijkl" {
		t.Errorf("generic api key: %v", found)
	}
}

func TestExtractSecretsNoFalsePositives(t *testing.T) {
	js := `var msg = "welcome to the dashboard"; let n = 42; const path = "/home";`
	if s := ExtractSecrets(js); len(s) != 0 {
		t.Errorf("expected no secrets, got %+v", s)
	}
}
