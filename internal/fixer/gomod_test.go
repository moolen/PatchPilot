package fixer

import (
	"context"
	"errors"
	"github.com/moolen/patchpilot/internal/vuln"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPatchGoModUpdatesDirectRequirements(t *testing.T) {
	tempDir := t.TempDir()
	goModPath := filepath.Join(tempDir, "go.mod")
	content := `module example.com/test

go 1.24.0

require (
	github.com/foo/bar v1.2.0
	github.com/keep/me v1.0.0
)
`
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	patches, unresolved, changed, err := patchGoMod(goModPath, map[string]string{
		"github.com/foo/bar":    "v1.2.3",
		"github.com/transitive": "v2.0.0",
	})
	if err != nil {
		t.Fatalf("patchGoMod returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected go.mod to change")
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
	if patches[0].Package != "github.com/foo/bar" || patches[0].To != "v1.2.3" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}
	if got := unresolved["github.com/transitive"]; got != "v2.0.0" {
		t.Fatalf("expected unresolved transitive requirement to remain, got %q", got)
	}

	updated, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read updated go.mod: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "github.com/foo/bar v1.2.3") {
		t.Fatalf("updated go.mod missing upgraded dependency:\n%s", text)
	}
	if strings.Contains(text, "github.com/foo/bar v1.2.0") {
		t.Fatalf("updated go.mod still contains old version:\n%s", text)
	}
}

func TestListModulesRetriesAfterTidy(t *testing.T) {
	origList := runGoListModulesFunc
	origTidy := runGoModTidyFunc
	defer func() {
		runGoListModulesFunc = origList
		runGoModTidyFunc = origTidy
	}()

	calls := 0
	tidied := 0
	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		calls++
		if calls == 1 {
			return nil, errors.New("updates to go.mod needed")
		}
		return []byte("example.com/root v0.0.0\ngithub.com/foo/bar v1.2.3\n"), nil
	}
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidied++
		return nil
	}

	modules, err := listModules(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("listModules returned error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("expected 2 list calls, got %d", calls)
	}
	if tidied != 1 {
		t.Fatalf("expected 1 tidy call, got %d", tidied)
	}
	if modules["github.com/foo/bar"] != "v1.2.3" {
		t.Fatalf("unexpected modules map: %#v", modules)
	}
}

func TestPatchTransitiveModulesUsesBuildListAndGoGet(t *testing.T) {
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	origTidy := runGoModTidyFunc
	defer func() {
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
		runGoModTidyFunc = origTidy
	}()

	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		return []byte(strings.Join([]string{
			"example.com/root v0.0.0",
			"github.com/needs/upgrade v1.0.0",
			"github.com/already/new v1.5.0",
			"",
		}, "\n")), nil
	}
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		return nil
	}

	var gotGets []string
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		gotGets = append(gotGets, dir+"|"+modulePath+"@"+version)
		return nil
	}

	goModPath := filepath.Join(t.TempDir(), "go.mod")
	patches, changed, err := patchTransitiveModules(context.Background(), goModPath, map[string]string{
		"github.com/needs/upgrade": "v1.2.0",
		"github.com/already/new":   "v1.4.0",
		"github.com/not/present":   "v9.9.9",
	})
	if err != nil {
		t.Fatalf("patchTransitiveModules returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected transitive patch to report changed")
	}

	wantGets := []string{filepath.Dir(goModPath) + "|github.com/needs/upgrade@v1.2.0"}
	if !reflect.DeepEqual(gotGets, wantGets) {
		t.Fatalf("unexpected go get calls: got %#v want %#v", gotGets, wantGets)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %d", len(patches))
	}
	if patches[0].Manager != "goget" || patches[0].Package != "github.com/needs/upgrade" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}
}

func TestPatchTransitiveModulesSkipsNonFatalGoModErrors(t *testing.T) {
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	defer func() {
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
	}()

	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		return nil, errors.New("go: errors parsing go.mod:\ngo.mod:41:2: require example.com/mod: version \"v3.0.0\" invalid: should be v0 or v1, not v3")
	}

	calledGet := false
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		calledGet = true
		return nil
	}

	goModPath := filepath.Join(t.TempDir(), "go.mod")
	patches, changed, err := patchTransitiveModules(context.Background(), goModPath, map[string]string{
		"github.com/needs/upgrade": "v1.2.0",
	})
	if err != nil {
		t.Fatalf("patchTransitiveModules returned error: %v", err)
	}
	if changed {
		t.Fatalf("expected no transitive change when go.mod is non-fatally invalid")
	}
	if len(patches) != 0 {
		t.Fatalf("expected no patches, got %#v", patches)
	}
	if calledGet {
		t.Fatalf("expected go get to be skipped")
	}
}

func TestApplyGoModuleFixesKeepsDirectPatchesWhenTidyIsNonFatal(t *testing.T) {
	origTidy := runGoModTidyFunc
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	defer func() {
		runGoModTidyFunc = origTidy
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
	}()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir .patchpilot: %v", err)
	}
	goModPath := filepath.Join(repo, "go.mod")
	content := `module example.com/test

go 1.24.0

require github.com/foo/bar v1.2.0
`
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	tidyCalls := 0
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidyCalls++
		return errors.New("go: errors parsing go.mod:\ngo.mod:41:2: require example.com/mod: version \"v3.0.0\" invalid: should be v0 or v1, not v3")
	}
	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		return []byte("example.com/test v0.0.0\n"), nil
	}
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		return nil
	}

	patches, err := ApplyGoModuleFixes(context.Background(), repo, []vuln.Finding{{
		Package:      "github.com/foo/bar",
		FixedVersion: "v1.2.3",
		Ecosystem:    "golang",
		Locations:    []string{goModPath},
	}})
	if err != nil {
		t.Fatalf("ApplyGoModuleFixes returned error: %v", err)
	}
	if tidyCalls != 1 {
		t.Fatalf("expected 1 tidy call, got %d", tidyCalls)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %#v", patches)
	}
	if patches[0].Package != "github.com/foo/bar" || patches[0].To != "v1.2.3" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}

	updated, err := os.ReadFile(goModPath)
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	if !strings.Contains(string(updated), "github.com/foo/bar v1.2.3") {
		t.Fatalf("expected upgraded dependency, got:\n%s", string(updated))
	}
}

func TestRunGoCommandPreservesParseErrors(t *testing.T) {
	fakeBin := t.TempDir()
	script := filepath.Join(fakeBin, "go")
	scriptContent := "#!/bin/sh\necho 'go: errors parsing go.mod:' 1>&2\necho 'go.mod:41:2: require example.com/mod: version \"v3.0.0\" invalid: should be v0 or v1, not v3' 1>&2\nexit 1\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+oldPath)

	dir := t.TempDir()
	err := runGoCommand(context.Background(), dir, "mod", "tidy")
	if err == nil {
		t.Fatalf("expected error")
	}
	if !isNonFatalGoModuleStateError(err) {
		t.Fatalf("expected non-fatal go.mod parse error, got: %v", err)
	}
}

func TestGoCommandEnvUsesRepoStateDir(t *testing.T) {
	repo := t.TempDir()
	moduleDir := filepath.Join(repo, "nested", "module")
	stateDir := filepath.Join(repo, ".patchpilot")
	for _, dir := range []string{moduleDir, stateDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	env, err := goCommandEnv(moduleDir)
	if err != nil {
		t.Fatalf("goCommandEnv returned error: %v", err)
	}

	lookup := map[string]string{}
	for _, entry := range env {
		key, value, ok := strings.Cut(entry, "=")
		if ok {
			lookup[key] = value
		}
	}

	for _, key := range []string{"GOMODCACHE", "GOPATH", "GOCACHE", "TMPDIR", "GOTMPDIR"} {
		value := lookup[key]
		if !strings.HasPrefix(value, stateDir) {
			t.Fatalf("expected %s to live under %s, got %q", key, stateDir, value)
		}
		if info, err := os.Stat(value); err != nil || !info.IsDir() {
			t.Fatalf("expected %s directory to exist at %q: %v", key, value, err)
		}
	}
}

func TestApplyGoModuleFixesKeepsDirectPatchesWhenRevisionIsUnknown(t *testing.T) {
	origTidy := runGoModTidyFunc
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	defer func() {
		runGoModTidyFunc = origTidy
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
	}()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir .patchpilot: %v", err)
	}
	goModPath := filepath.Join(repo, "go.mod")
	content := `module example.com/test

go 1.24.0

require github.com/foo/bar v1.2.0
`
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	tidyCalls := 0
	unknownRevisionErr := errors.New("go: k8s.io/kubernetes@v1.32.10 requires\n\tk8s.io/cri-client@v0.0.0: reading k8s.io/cri-client/go.mod at revision v0.0.0: unknown revision v0.0.0")
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidyCalls++
		return unknownRevisionErr
	}
	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		return nil, unknownRevisionErr
	}
	calledGet := false
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		calledGet = true
		return nil
	}

	patches, err := ApplyGoModuleFixes(context.Background(), repo, []vuln.Finding{
		{
			Package:      "github.com/foo/bar",
			FixedVersion: "v1.2.3",
			Ecosystem:    "golang",
			Locations:    []string{goModPath},
		},
		{
			Package:      "github.com/transitive/only",
			FixedVersion: "v2.0.0",
			Ecosystem:    "golang",
			Locations:    []string{goModPath},
		},
	})
	if err != nil {
		t.Fatalf("ApplyGoModuleFixes returned error: %v", err)
	}
	if tidyCalls != 2 {
		t.Fatalf("expected 2 tidy calls, got %d", tidyCalls)
	}
	if calledGet {
		t.Fatalf("expected go get to be skipped")
	}
	if len(patches) != 1 {
		t.Fatalf("expected only direct patch to remain, got %#v", patches)
	}
	if patches[0].Package != "github.com/foo/bar" || patches[0].To != "v1.2.3" {
		t.Fatalf("unexpected patch: %+v", patches[0])
	}
}

func TestApplyGoModuleFixesRefreshesVendorForModifiedModules(t *testing.T) {
	origTidy := runGoModTidyFunc
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	origVendor := runGoModVendorFunc
	defer func() {
		runGoModTidyFunc = origTidy
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
		runGoModVendorFunc = origVendor
	}()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir .patchpilot: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "vendor"), 0o755); err != nil {
		t.Fatalf("mkdir vendor: %v", err)
	}
	goModPath := filepath.Join(repo, "go.mod")
	content := `module example.com/test

go 1.24.0

require github.com/foo/bar v1.2.0
`
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	tidyCalls := 0
	vendorCalls := 0
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidyCalls++
		return nil
	}
	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		return []byte("example.com/test v0.0.0\n"), nil
	}
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		return nil
	}
	runGoModVendorFunc = func(ctx context.Context, dir string) error {
		vendorCalls++
		return nil
	}

	patches, err := ApplyGoModuleFixes(context.Background(), repo, []vuln.Finding{{
		Package:      "github.com/foo/bar",
		FixedVersion: "v1.2.3",
		Ecosystem:    "golang",
		Locations:    []string{goModPath},
	}})
	if err != nil {
		t.Fatalf("ApplyGoModuleFixes returned error: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %#v", patches)
	}
	if tidyCalls != 1 {
		t.Fatalf("expected 1 tidy call, got %d", tidyCalls)
	}
	if vendorCalls != 1 {
		t.Fatalf("expected 1 vendor call, got %d", vendorCalls)
	}
}

func TestRunGoListModulesUsesModuleMode(t *testing.T) {
	fakeBin := t.TempDir()
	script := filepath.Join(fakeBin, "go")
	argsPath := filepath.Join(fakeBin, "args.txt")
	scriptContent := "#!/bin/sh\nprintf '%s\n' \"$@\" > \"" + argsPath + "\"\necho 'example.com/test v0.0.0'\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+oldPath)

	dir := t.TempDir()
	output, err := runGoListModules(context.Background(), dir)
	if err != nil {
		t.Fatalf("runGoListModules returned error: %v", err)
	}
	if !strings.Contains(string(output), "example.com/test v0.0.0") {
		t.Fatalf("unexpected output: %s", string(output))
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	if !strings.Contains(string(args), "-mod=mod") {
		t.Fatalf("expected -mod=mod in args, got:\n%s", string(args))
	}
}

func TestRunGoModTidyUsesErrorTolerantMode(t *testing.T) {
	fakeBin := t.TempDir()
	script := filepath.Join(fakeBin, "go")
	argsPath := filepath.Join(fakeBin, "args.txt")
	scriptContent := "#!/bin/sh\nprintf '%s\n' \"$@\" > \"" + argsPath + "\"\n"
	if err := os.WriteFile(script, []byte(scriptContent), 0o755); err != nil {
		t.Fatalf("write fake go: %v", err)
	}

	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", fakeBin+string(os.PathListSeparator)+oldPath)

	if err := runGoModTidy(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("runGoModTidy returned error: %v", err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatalf("read args: %v", err)
	}
	text := string(args)
	if !strings.Contains(text, "mod") || !strings.Contains(text, "tidy") || !strings.Contains(text, "-e") {
		t.Fatalf("expected go mod tidy -e args, got:\n%s", text)
	}
}

func TestApplyGoModuleFixesDropsTransitivePatchesThatDoNotStick(t *testing.T) {
	origTidy := runGoModTidyFunc
	origList := runGoListModulesFunc
	origGet := runGoGetFunc
	defer func() {
		runGoModTidyFunc = origTidy
		runGoListModulesFunc = origList
		runGoGetFunc = origGet
	}()

	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir .patchpilot: %v", err)
	}
	goModPath := filepath.Join(repo, "go.mod")
	content := `module example.com/test

go 1.24.0
`
	if err := os.WriteFile(goModPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	tidyCalls := 0
	runGoModTidyFunc = func(ctx context.Context, dir string) error {
		tidyCalls++
		return nil
	}
	listCalls := 0
	runGoListModulesFunc = func(ctx context.Context, dir string) ([]byte, error) {
		listCalls++
		if listCalls == 1 {
			return []byte("example.com/test v0.0.0\ngolang.org/x/net v0.0.0-20200707034311-ab3426394381\n"), nil
		}
		return []byte("example.com/test v0.0.0\ngolang.org/x/net v0.9.0\n"), nil
	}
	goGetCalls := 0
	runGoGetFunc = func(ctx context.Context, dir, modulePath, version string) error {
		goGetCalls++
		return nil
	}

	patches, err := ApplyGoModuleFixes(context.Background(), repo, []vuln.Finding{{
		Package:      "golang.org/x/net",
		FixedVersion: "v0.38.0",
		Ecosystem:    "golang",
		Locations:    []string{goModPath},
	}})
	if err != nil {
		t.Fatalf("ApplyGoModuleFixes returned error: %v", err)
	}
	if goGetCalls != 1 {
		t.Fatalf("expected 1 go get call, got %d", goGetCalls)
	}
	if tidyCalls != 1 {
		t.Fatalf("expected 1 final tidy call, got %d", tidyCalls)
	}
	if listCalls != 2 {
		t.Fatalf("expected 2 list calls, got %d", listCalls)
	}
	if len(patches) != 0 {
		t.Fatalf("expected ineffective transitive patch to be dropped, got %#v", patches)
	}
}
