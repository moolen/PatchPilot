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
	if strings.Contains(text, `"issues": "write"`) {
		t.Fatalf("manifest should not include issues permission: %s", text)
	}
	if strings.Contains(text, `"checks": "write"`) {
		t.Fatalf("manifest should not include checks permission: %s", text)
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
	createBinary("patchpilot")
	createBinary("syft")
	createBinary("grype")
	createBinary("git")
	createBinary("go")
	createBinary("node")
	createBinary("npm")

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_WORKDIR", filepath.Join(temp, "work"))
	t.Setenv("PP_PATCHPILOT_BINARY", "patchpilot")

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

func TestRunDoctorContainerMode(t *testing.T) {
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
	createBinary("docker")
	createBinary("git")

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_WORKDIR", filepath.Join(temp, "work"))
	t.Setenv("PP_JOB_RUNNER", "container")
	t.Setenv("PP_JOB_CONTAINER_RUNTIME", "docker")
	t.Setenv("PP_JOB_CONTAINER_IMAGE", "ghcr.io/moolen/patchpilot-job:latest")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor(&stdout, &stderr)
	if code != 0 {
		t.Fatalf("runDoctor code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "doctor: job container runtime: OK") {
		t.Fatalf("doctor output did not validate container runtime: %s", stdout.String())
	}
}
