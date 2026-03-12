package verifycheck

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiscoverModuleDirsFindsRepoModules(t *testing.T) {
	repo := t.TempDir()
	for _, dir := range []string{".", "services/api", "tools/worker"} {
		moduleDir := filepath.Join(repo, dir)
		if err := os.MkdirAll(moduleDir, 0o755); err != nil {
			t.Fatalf("mkdir module dir %s: %v", moduleDir, err)
		}
		if err := os.WriteFile(filepath.Join(moduleDir, "go.mod"), []byte(`module example.com/test

go 1.22
`), 0o644); err != nil {
			t.Fatalf("write go.mod in %s: %v", moduleDir, err)
		}
	}
	for _, dir := range []string{"vendor/dep", ".git/hooks", ".patchpilot/cache"} {
		skipDir := filepath.Join(repo, dir)
		if err := os.MkdirAll(skipDir, 0o755); err != nil {
			t.Fatalf("mkdir skipped dir %s: %v", skipDir, err)
		}
		if err := os.WriteFile(filepath.Join(skipDir, "go.mod"), []byte(`module ignored

go 1.22
`), 0o644); err != nil {
			t.Fatalf("write skipped go.mod in %s: %v", skipDir, err)
		}
	}

	dirs, err := DiscoverModuleDirs(repo)
	if err != nil {
		t.Fatalf("discover module dirs: %v", err)
	}
	want := []string{".", filepath.Clean("services/api"), filepath.Clean("tools/worker")}
	if !reflect.DeepEqual(dirs, want) {
		t.Fatalf("unexpected dirs: got %#v want %#v", dirs, want)
	}
}

func TestDiscoverModuleDirsWithOptionsSkipsConfiguredPaths(t *testing.T) {
	repo := t.TempDir()
	for _, dir := range []string{"services/api", "examples/demo"} {
		moduleDir := filepath.Join(repo, dir)
		if err := os.MkdirAll(moduleDir, 0o755); err != nil {
			t.Fatalf("mkdir module dir %s: %v", moduleDir, err)
		}
		if err := os.WriteFile(filepath.Join(moduleDir, "go.mod"), []byte("module example.com/test\n\ngo 1.22\n"), 0o644); err != nil {
			t.Fatalf("write go.mod in %s: %v", moduleDir, err)
		}
	}

	dirs, err := DiscoverModuleDirsWithOptions(repo, DiscoverOptions{SkipPaths: []string{"examples/**"}})
	if err != nil {
		t.Fatalf("discover module dirs: %v", err)
	}
	want := []string{filepath.Clean("services/api")}
	if !reflect.DeepEqual(dirs, want) {
		t.Fatalf("unexpected dirs: got %#v want %#v", dirs, want)
	}
}

func TestCompareOnlyReportsNewFailures(t *testing.T) {
	baseline := Report{Modules: []ModuleResult{{Dir: "a", Checks: []CheckResult{{Name: "build", Status: StatusOK}, {Name: "vet", Status: StatusFailed}}}}}
	after := Report{Modules: []ModuleResult{{Dir: "a", Checks: []CheckResult{{Name: "build", Status: StatusFailed}, {Name: "vet", Status: StatusFailed}}}}}
	regressions := Compare(baseline, after)
	if len(regressions) != 1 {
		t.Fatalf("expected 1 regression, got %#v", regressions)
	}
	if regressions[0].Check != "build" {
		t.Fatalf("unexpected regression: %#v", regressions[0])
	}
}

func TestRunStandardRecordsRelativeDirsAndStatuses(t *testing.T) {
	orig := runGoCheckFunc
	defer func() { runGoCheckFunc = orig }()

	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "a")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}

	calls := []string{}
	runGoCheckFunc = func(ctx context.Context, dir string, args ...string) error {
		calls = append(calls, dir+":"+args[0])
		switch args[0] {
		case "build":
			return nil
		case "test":
			return errors.New("compile failed")
		default:
			return context.DeadlineExceeded
		}
	}

	report := RunStandard(context.Background(), repo, []string{moduleDir})
	if len(report.Modules) != 1 || len(report.Modules[0].Checks) != 2 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Modules[0].Dir != "a" {
		t.Fatalf("expected relative module dir, got %#v", report.Modules[0])
	}
	checks := report.Modules[0].Checks
	if checks[0].Status != StatusOK || checks[1].Status != StatusFailed {
		t.Fatalf("unexpected check statuses: %#v", checks)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %#v", calls)
	}
}

func TestRunStandardRejectsDirsOutsideRepo(t *testing.T) {
	orig := runGoCheckFunc
	defer func() { runGoCheckFunc = orig }()
	called := false
	runGoCheckFunc = func(ctx context.Context, dir string, args ...string) error {
		called = true
		return nil
	}

	repo := t.TempDir()
	outside := t.TempDir()
	report := RunStandard(context.Background(), repo, []string{outside})
	if called {
		t.Fatalf("expected no go commands for out-of-repo module")
	}
	if len(report.Modules) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	for _, check := range report.Modules[0].Checks {
		if check.Status != StatusFailed || !strings.Contains(check.Error, "escapes repo") {
			t.Fatalf("unexpected invalid-module check: %#v", check)
		}
	}
}

func TestSummarizeCountsStatuses(t *testing.T) {
	report := Report{
		Modules:     []ModuleResult{{Dir: "a", Checks: []CheckResult{{Name: "build", Status: StatusOK}, {Name: "test", Status: StatusFailed}, {Name: "vet", Status: StatusTimeout}}}},
		Regressions: []Regression{{Dir: "a", Check: "test"}},
	}
	summary := Summarize(report)
	if summary.Modules != 1 || summary.Checks != 3 || summary.OK != 1 || summary.Failed != 1 || summary.Timeouts != 1 || summary.Regressions != 1 {
		t.Fatalf("unexpected summary: %#v", summary)
	}
}

func TestRunStandardCapturesTimeoutFromContext(t *testing.T) {
	orig := runGoCheckFunc
	defer func() { runGoCheckFunc = orig }()

	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "a")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}

	runGoCheckFunc = func(ctx context.Context, dir string, args ...string) error {
		<-ctx.Done()
		return ctx.Err()
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	report := RunStandard(ctx, repo, []string{moduleDir})
	for _, check := range report.Modules[0].Checks {
		if check.Status != StatusTimeout {
			t.Fatalf("expected timeout, got %#v", report)
		}
	}
}

func TestRunStandardRunsCargoMetadataCheck(t *testing.T) {
	orig := runCargoMetadataCheckFunc
	defer func() { runCargoMetadataCheckFunc = orig }()

	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "rust")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moduleDir, "Cargo.toml"), []byte("[package]\nname = \"demo\"\nversion = \"0.1.0\"\n"), 0o644); err != nil {
		t.Fatalf("write Cargo.toml: %v", err)
	}

	calls := 0
	runCargoMetadataCheckFunc = func(ctx context.Context, dir string) error {
		calls++
		if dir != moduleDir {
			t.Fatalf("unexpected cargo dir: %s", dir)
		}
		return nil
	}

	report := RunStandard(context.Background(), repo, nil)
	if len(report.Modules) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Modules[0].Dir != filepath.Clean("rust") {
		t.Fatalf("unexpected module dir: %#v", report.Modules[0])
	}
	if len(report.Modules[0].Checks) != 1 || report.Modules[0].Checks[0].Name != "cargo-manifest-parse" || report.Modules[0].Checks[0].Status != StatusOK {
		t.Fatalf("unexpected cargo checks: %#v", report.Modules[0].Checks)
	}
	if calls != 1 {
		t.Fatalf("expected one cargo metadata call, got %d", calls)
	}
}

func TestRunGoCheckCompileTestsDoesNotExecuteTestMain(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "go.mod"), []byte("module example.com/test\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, "main_test.go"), []byte(`package test

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	_ = os.WriteFile("ran-testmain", []byte("yes"), 0o644)
	os.Exit(m.Run())
}
`), 0o644); err != nil {
		t.Fatalf("write test file: %v", err)
	}

	if err := runGoCheck(context.Background(), repo, "test", "-exec=true", "-run", "^$", "./..."); err != nil {
		t.Fatalf("runGoCheck compile-tests: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "ran-testmain")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected TestMain not to execute, stat err=%v", err)
	}
}

func TestRunWithCommandsAppendIncludesCustomChecks(t *testing.T) {
	origGo := runGoCheckFunc
	origShell := runShellCheckFunc
	defer func() {
		runGoCheckFunc = origGo
		runShellCheckFunc = origShell
	}()

	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "a")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}

	goCalls := 0
	runGoCheckFunc = func(ctx context.Context, dir string, args ...string) error {
		goCalls++
		return nil
	}
	shellCalls := 0
	runShellCheckFunc = func(ctx context.Context, dir, command string) error {
		shellCalls++
		if command != "make verify" {
			t.Fatalf("unexpected custom command: %q", command)
		}
		return nil
	}

	report := RunWithCommands(context.Background(), repo, []string{moduleDir}, "append", []CommandSpec{{Name: "policy-verify", Command: "make verify"}})
	if report.Mode != "standard+custom" {
		t.Fatalf("expected standard+custom mode, got %q", report.Mode)
	}
	if len(report.Modules) != 1 || len(report.Modules[0].Checks) != 3 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if goCalls != 2 || shellCalls != 1 {
		t.Fatalf("unexpected call counts: go=%d shell=%d", goCalls, shellCalls)
	}
}

func TestRunWithCommandsReplaceOnlyRunsCustomChecks(t *testing.T) {
	origGo := runGoCheckFunc
	origShell := runShellCheckFunc
	defer func() {
		runGoCheckFunc = origGo
		runShellCheckFunc = origShell
	}()

	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "a")
	if err := os.MkdirAll(moduleDir, 0o755); err != nil {
		t.Fatalf("mkdir module: %v", err)
	}

	runGoCheckFunc = func(ctx context.Context, dir string, args ...string) error {
		t.Fatalf("did not expect go checks in replace mode")
		return nil
	}
	runShellCheckFunc = func(ctx context.Context, dir, command string) error {
		return nil
	}

	report := RunWithCommands(context.Background(), repo, []string{moduleDir}, "replace", []CommandSpec{{Name: "policy-verify", Command: "make verify"}})
	if report.Mode != "custom" {
		t.Fatalf("expected custom mode, got %q", report.Mode)
	}
	if len(report.Modules) != 1 || len(report.Modules[0].Checks) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	if report.Modules[0].Checks[0].Name != "policy-verify" {
		t.Fatalf("unexpected check name: %#v", report.Modules[0].Checks[0])
	}
}

func TestRunStandardDiscoversNonGoManifests(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "package.json"), []byte("{\n  \"name\": \"demo\"\n}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}

	report := RunStandard(context.Background(), repo, nil)
	if len(report.Modules) != 1 {
		t.Fatalf("expected one discovered target, got %#v", report)
	}
	if report.Modules[0].Dir != "." {
		t.Fatalf("expected root dir target, got %#v", report.Modules[0])
	}
	if len(report.Modules[0].Checks) != 1 || report.Modules[0].Checks[0].Name != "npm-manifest-parse" {
		t.Fatalf("unexpected non-go checks: %#v", report.Modules[0].Checks)
	}
	if report.Modules[0].Checks[0].Status != StatusOK {
		t.Fatalf("expected manifest parse to pass: %#v", report.Modules[0].Checks[0])
	}
}

func TestRunStandardReportsInvalidRequirementsFile(t *testing.T) {
	repo := t.TempDir()
	if err := os.WriteFile(filepath.Join(repo, "requirements.txt"), []byte("not a requirement line\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	report := RunStandard(context.Background(), repo, nil)
	if len(report.Modules) != 1 || len(report.Modules[0].Checks) != 1 {
		t.Fatalf("unexpected report: %#v", report)
	}
	check := report.Modules[0].Checks[0]
	if check.Name != "pip-requirements-parse" {
		t.Fatalf("unexpected check: %#v", check)
	}
	if check.Status != StatusFailed {
		t.Fatalf("expected requirements parse failure, got %#v", check)
	}
}
