package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunManifest(t *testing.T) {
	t.Setenv("PP_APP_NAME", "PatchPilot Test")
	t.Setenv("PP_APP_URL", "https://app.example.com")
	t.Setenv("PP_WEBHOOK_URL", "https://app.example.com/webhook")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runManifest(&stdout, &stderr)
	if code != 0 {
		t.Fatalf("runManifest code = %d, stderr = %s", code, stderr.String())
	}
	text := stdout.String()
	if !strings.Contains(text, `"name": "PatchPilot Test"`) {
		t.Fatalf("manifest did not include app name: %s", text)
	}
	if !strings.Contains(text, `"default_events": [`) {
		t.Fatalf("manifest missing events: %s", text)
	}
}

func TestRunDoctor(t *testing.T) {
	temp := t.TempDir()
	binDir := filepath.Join(temp, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	createBinary := func(name string) {
		path := filepath.Join(binDir, name)
		content := "#!/bin/sh\nexit 0\n"
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatalf("write fake binary %s: %v", name, err)
		}
	}
	createBinary("cvefix")
	createBinary("syft")
	createBinary("grype")

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_WEBHOOK_SECRET", "secret")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_WORKDIR", filepath.Join(temp, "work"))
	t.Setenv("PP_CVEFIX_BINARY", "cvefix")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor(&stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctor code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "doctor: all checks passed") {
		t.Fatalf("doctor output did not report success: %s", stdout.String())
	}
}
