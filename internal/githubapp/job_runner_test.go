package githubapp

import (
	"strings"
	"testing"
)

func TestContainerPatchPilotRunnerInvocation(t *testing.T) {
	repoPath := t.TempDir()
	runner := containerPatchPilotRunner{
		runtime: "docker",
		image:   "ghcr.io/moolen/patchpilot-job:latest",
		binary:  "/usr/local/bin/patchpilot",
		network: "none",
	}

	name, args, err := runner.invocation(repoPath, []string{"scan", "--dir", repoPath, "--untrusted-repo-policy"})
	if err != nil {
		t.Fatalf("invocation returned error: %v", err)
	}
	if name != "docker" {
		t.Fatalf("name = %q, want docker", name)
	}

	joined := strings.Join(args, " ")
	for _, expected := range []string{
		"run --rm",
		"--workdir " + containerWorkspacePath,
		"--network none",
		"--cap-drop=ALL",
		"--security-opt no-new-privileges",
		"--read-only",
		"--tmpfs /tmp:rw,noexec,nosuid,nodev",
		"-e HOME=/tmp",
		"-e TMPDIR=/tmp",
		"-v " + repoPath + ":" + containerWorkspacePath + ":rw",
		"ghcr.io/moolen/patchpilot-job:latest",
		"/usr/local/bin/patchpilot scan --dir " + containerWorkspacePath + " --untrusted-repo-policy",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected invocation to contain %q, got %q", expected, joined)
		}
	}
}

func TestRewritePatchPilotArgsForContainer(t *testing.T) {
	repoPath := t.TempDir()

	args := rewritePatchPilotArgsForContainer(repoPath, []string{
		"fix",
		"--dir=" + repoPath,
		"--enable-agent=false",
		"--dir",
		repoPath,
		"--other",
	})

	joined := strings.Join(args, " ")
	if strings.Count(joined, containerWorkspacePath) != 2 {
		t.Fatalf("expected two rewritten repo paths, got %q", joined)
	}
	if strings.Contains(joined, repoPath) {
		t.Fatalf("expected host repo path to be rewritten, got %q", joined)
	}
}
