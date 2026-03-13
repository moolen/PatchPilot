package githubapp

import (
	"strings"
	"testing"
)

func TestAppendPatchPilotPolicyArgs(t *testing.T) {
	args := appendPatchPilotPolicyArgs([]string{"scan", "--dir", "/repo"}, Config{
		PatchPilotPolicyPath: "/etc/patchpilot/central.yaml",
		PatchPilotPolicyMode: "override",
	})
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "--policy /etc/patchpilot/central.yaml") {
		t.Fatalf("expected central policy arg, got %q", joined)
	}
	if !strings.Contains(joined, "--policy-mode override") {
		t.Fatalf("expected policy mode arg, got %q", joined)
	}
}

func TestAppendPatchPilotPolicyArgsNoPath(t *testing.T) {
	base := []string{"scan", "--dir", "/repo"}
	args := appendPatchPilotPolicyArgs(base, Config{})
	if len(args) != len(base) {
		t.Fatalf("unexpected args length: %d", len(args))
	}
}
