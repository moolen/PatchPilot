package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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
	if !strings.Contains(text, `"issues": "write"`) {
		t.Fatalf("manifest should include issues permission: %s", text)
	}
	if !strings.Contains(text, `"checks": "read"`) {
		t.Fatalf("manifest should include checks read permission: %s", text)
	}
	if !strings.Contains(text, `"actions": "write"`) {
		t.Fatalf("manifest should include actions write permission: %s", text)
	}
	if !strings.Contains(text, `"statuses": "read"`) {
		t.Fatalf("manifest should include statuses read permission: %s", text)
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
	createBinary("docker")
	createBinary("go")
	createBinary("node")
	createBinary("npm")
	createBinary("cargo")

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_WORKDIR", filepath.Join(temp, "work"))
	t.Setenv("PP_PATCHPILOT_BINARY", "patchpilot")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor(&stdout, &stderr, nil)
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
	code := runDoctor(&stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("runDoctor code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "doctor: job container runtime: OK") {
		t.Fatalf("doctor output did not validate container runtime: %s", stdout.String())
	}
}

func TestRunDoctorTokenMode(t *testing.T) {
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
	createBinary("docker")
	createBinary("go")
	createBinary("node")
	createBinary("npm")
	createBinary("cargo")

	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PP_GITHUB_AUTH_MODE", "token")
	t.Setenv("PP_GITHUB_TOKEN", "ghp_test")
	t.Setenv("PP_GITHUB_TOKEN_REPOSITORIES", "acme/demo")
	t.Setenv("PP_WORKDIR", filepath.Join(temp, "work"))
	t.Setenv("PP_PATCHPILOT_BINARY", "patchpilot")

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runDoctor(&stdout, &stderr, nil)
	if code != 0 {
		t.Fatalf("runDoctor code = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "doctor: github token auth: OK") {
		t.Fatalf("doctor output did not validate token auth: %s", stdout.String())
	}
}

func TestRunCommandDefinesRequirePolicyFileFlag(t *testing.T) {
	command := newRootCommand(io.Discard, io.Discard)
	command.SetArgs([]string{"run", "--require-policy-file", "--help"})

	if err := command.Execute(); err != nil {
		t.Fatalf("execute returned error: %v", err)
	}
}

func TestRunCommandDefinesForceReconcileOnStartFlag(t *testing.T) {
	command := newRunCommand()
	if command.Flags().Lookup("force-reconcile-on-start") == nil {
		t.Fatalf("force-reconcile-on-start flag is not defined")
	}
}

func TestRunCommandDefinesRuntimeConfigFlags(t *testing.T) {
	command := newRunCommand()
	for _, flag := range []string{
		"github-auth-mode",
		"app-id",
		"private-key-path",
		"github-token-repositories",
		"runtime-config-file",
		"patchpilot-policy",
		"patchpilot-policy-mode",
		"job-runner",
		"enable-auto-merge",
		"scheduler-tick",
		"github-retry-max-attempts",
	} {
		if command.Flags().Lookup(flag) == nil {
			t.Fatalf("%s flag is not defined", flag)
		}
	}
}

func TestRuntimeConfigFlagOverrides(t *testing.T) {
	options := runOptions{}
	command := &cobra.Command{Use: "test"}
	addRuntimeConfigFlags(command, &options)

	if err := command.ParseFlags([]string{
		"--app-id", "321",
		"--enable-auto-merge=true",
		"--runtime-config-file", "/tmp/runtime.yaml",
		"--patchpilot-policy", "/etc/patchpilot/central.yaml",
		"--patchpilot-policy-mode", "override",
		"--scheduler-tick", "2h",
		"--force-reconcile-on-start=false",
	}); err != nil {
		t.Fatalf("parse flags: %v", err)
	}

	overrides := options.envOverrides(command)
	if overrides["PP_APP_ID"] != "321" {
		t.Fatalf("PP_APP_ID override = %q", overrides["PP_APP_ID"])
	}
	if overrides["PP_ENABLE_AUTO_MERGE"] != "true" {
		t.Fatalf("PP_ENABLE_AUTO_MERGE override = %q", overrides["PP_ENABLE_AUTO_MERGE"])
	}
	if overrides["PP_GITHUB_APP_CONFIG_FILE"] != "/tmp/runtime.yaml" {
		t.Fatalf("PP_GITHUB_APP_CONFIG_FILE override = %q", overrides["PP_GITHUB_APP_CONFIG_FILE"])
	}
	if overrides["PP_PATCHPILOT_POLICY"] != "/etc/patchpilot/central.yaml" {
		t.Fatalf("PP_PATCHPILOT_POLICY override = %q", overrides["PP_PATCHPILOT_POLICY"])
	}
	if overrides["PP_PATCHPILOT_POLICY_MODE"] != "override" {
		t.Fatalf("PP_PATCHPILOT_POLICY_MODE override = %q", overrides["PP_PATCHPILOT_POLICY_MODE"])
	}
	if overrides["PP_SCHEDULER_TICK"] != "2h" {
		t.Fatalf("PP_SCHEDULER_TICK override = %q", overrides["PP_SCHEDULER_TICK"])
	}
	if overrides["PP_FORCE_RECONCILE_ON_START"] != "false" {
		t.Fatalf("PP_FORCE_RECONCILE_ON_START override = %q", overrides["PP_FORCE_RECONCILE_ON_START"])
	}
}
