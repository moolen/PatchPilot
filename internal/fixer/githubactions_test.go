package fixer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/moolen/patchpilot/internal/vuln"
)

func TestCollectGitHubActionRequirements(t *testing.T) {
	workflow := "/repo/.github/workflows/ci.yml"
	reqs := collectGitHubActionRequirements([]string{workflow}, []vuln.Finding{
		{Package: "actions/checkout", FixedVersion: "v4.2.3", Ecosystem: "github-actions", Locations: []string{workflow}},
		{Package: "actions/checkout", FixedVersion: "v4.2.2", Ecosystem: "github-actions", Locations: []string{workflow}},
		{Package: "actions/setup-go", FixedVersion: "v5.0.1", Ecosystem: "github-actions", Locations: []string{workflow}},
	})
	need := reqs[workflow]
	if got := need.FixedVersions["actions/checkout"]; got != "v4.2.2" {
		t.Fatalf("unexpected checkout fixed version: %#v", need.FixedVersions)
	}
	if got := need.FixedVersions["actions/setup-go"]; got != "v5.0.1" {
		t.Fatalf("unexpected setup-go fixed version: %#v", need.FixedVersions)
	}
}

func TestPatchGitHubWorkflowUpdatesSemverRefs(t *testing.T) {
	tempDir := t.TempDir()
	workflowPath := filepath.Join(tempDir, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	content := "name: ci\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4.0.0\n      - uses: actions/setup-go@v5.0.0\n"
	if err := os.WriteFile(workflowPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	patches, changed, err := patchGitHubWorkflow(context.Background(), workflowPath, gitHubActionNeeds{
		FixedVersions: map[string]string{
			"actions/checkout": "v4.2.2",
			"actions/setup-go": "v5.0.1",
		},
	}, newGitHubActionRefResolver())
	if err != nil {
		t.Fatalf("patchGitHubWorkflow returned error: %v", err)
	}
	if !changed {
		t.Fatalf("expected workflow to change")
	}
	if len(patches) != 2 {
		t.Fatalf("expected 2 patches, got %#v", patches)
	}

	updated, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	text := string(updated)
	if !strings.Contains(text, "actions/checkout@v4.2.2") || !strings.Contains(text, "actions/setup-go@v5.0.1") {
		t.Fatalf("unexpected updated workflow:\n%s", text)
	}
}

func TestPatchGitHubWorkflowUpdatesReusableWorkflowAndSHAPins(t *testing.T) {
	orig := runGitLSRemoteFunc
	defer func() { runGitLSRemoteFunc = orig }()
	runGitLSRemoteFunc = func(ctx context.Context, repository string) ([]byte, error) {
		if repository != "acme/platform" {
			t.Fatalf("unexpected repository: %q", repository)
		}
		return []byte(strings.Join([]string{
			"1111111111111111111111111111111111111111\trefs/tags/v2.3.4",
			"2222222222222222222222222222222222222222\trefs/tags/v2.3.4^{}",
			"",
		}, "\n")), nil
	}

	tempDir := t.TempDir()
	workflowPath := filepath.Join(tempDir, ".github", "workflows", "release.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	content := "jobs:\n  reuse:\n    uses: acme/platform/.github/workflows/release.yml@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
	if err := os.WriteFile(workflowPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	patches, changed, err := patchGitHubWorkflow(context.Background(), workflowPath, gitHubActionNeeds{
		FixedVersions: map[string]string{
			"acme/platform/.github/workflows/release.yml": "v2.3.4",
		},
	}, newGitHubActionRefResolver())
	if err != nil {
		t.Fatalf("patchGitHubWorkflow returned error: %v", err)
	}
	if !changed || len(patches) != 1 {
		t.Fatalf("unexpected patch result: changed=%v patches=%#v", changed, patches)
	}
	if patches[0].To != "2222222222222222222222222222222222222222" {
		t.Fatalf("unexpected patch: %#v", patches[0])
	}

	updated, err := os.ReadFile(workflowPath)
	if err != nil {
		t.Fatalf("read workflow: %v", err)
	}
	if !strings.Contains(string(updated), "@2222222222222222222222222222222222222222") {
		t.Fatalf("unexpected updated workflow:\n%s", string(updated))
	}
}

func TestPatchGitHubWorkflowLeavesLocalAndDockerRefsAlone(t *testing.T) {
	tempDir := t.TempDir()
	workflowPath := filepath.Join(tempDir, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	content := "jobs:\n  build:\n    steps:\n      - uses: ./actions/local\n      - uses: docker://alpine:3.20\n"
	if err := os.WriteFile(workflowPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	patches, changed, err := patchGitHubWorkflow(context.Background(), workflowPath, gitHubActionNeeds{
		FixedVersions: map[string]string{"./actions/local": "v2.0.0"},
	}, newGitHubActionRefResolver())
	if err != nil {
		t.Fatalf("patchGitHubWorkflow returned error: %v", err)
	}
	if changed || len(patches) != 0 {
		t.Fatalf("expected no changes, got changed=%v patches=%#v", changed, patches)
	}
}

func TestGitHubActionResolverFailsWhenTagMissing(t *testing.T) {
	orig := runGitLSRemoteFunc
	defer func() { runGitLSRemoteFunc = orig }()
	runGitLSRemoteFunc = func(ctx context.Context, repository string) ([]byte, error) {
		return []byte("1111111111111111111111111111111111111111\trefs/tags/v1.0.0\n"), nil
	}

	_, err := newGitHubActionRefResolver().Resolve(context.Background(), gitHubActionRef{
		PackagePath: "actions/checkout",
		Repository:  "actions/checkout",
		Ref:         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}, "v4.2.2")
	if err == nil {
		t.Fatal("expected missing tag resolution error")
	}
}

func TestApplyGitHubActionsFixesWithOptions(t *testing.T) {
	orig := runGitLSRemoteFunc
	defer func() { runGitLSRemoteFunc = orig }()
	runGitLSRemoteFunc = func(ctx context.Context, repository string) ([]byte, error) {
		if repository != "actions/checkout" {
			return nil, errors.New("unexpected repository")
		}
		return []byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\trefs/tags/v4.2.2\n"), nil
	}

	repo := t.TempDir()
	workflowPath := filepath.Join(repo, ".github", "workflows", "ci.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatalf("mkdir workflow dir: %v", err)
	}
	if err := os.WriteFile(workflowPath, []byte("jobs:\n  build:\n    steps:\n      - uses: actions/checkout@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"), 0o644); err != nil {
		t.Fatalf("write workflow: %v", err)
	}

	patches, err := ApplyGitHubActionsFixesWithOptions(context.Background(), repo, []vuln.Finding{
		{
			Package:      "actions/checkout",
			FixedVersion: "v4.2.2",
			Ecosystem:    "github-actions",
			Locations:    []string{workflowPath},
		},
	}, FileOptions{})
	if err != nil {
		t.Fatalf("ApplyGitHubActionsFixesWithOptions returned error: %v", err)
	}
	if len(patches) != 1 {
		t.Fatalf("expected 1 patch, got %#v", patches)
	}
	if patches[0].Manager != "github_actions" {
		t.Fatalf("unexpected patch manager: %#v", patches[0])
	}
}

func TestParseGitLSRemoteTagsPrefersAnnotatedTagTargets(t *testing.T) {
	got := parseGitLSRemoteTags([]byte(strings.Join([]string{
		"1111111111111111111111111111111111111111\trefs/tags/v4.2.2",
		"2222222222222222222222222222222222222222\trefs/tags/v4.2.2^{}",
		"",
	}, "\n")))
	want := map[string]string{"v4.2.2": "2222222222222222222222222222222222222222"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected parsed tags: got %#v want %#v", got, want)
	}
}
