package githubapp

import (
	"context"
	"strings"
	"testing"
)

func TestRunCommandScrubsSensitiveHostEnv(t *testing.T) {
	t.Setenv("PP_PRIVATE_KEY_PEM", "super-secret-private-key")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-secret")
	t.Setenv("GOPRIVATE", "example.com/private")

	stdout, stderr, err := runCommand(
		context.Background(),
		t.TempDir(),
		map[string]string{"PATCHPILOT_TEST_EXTRA": "extra-ok"},
		"sh",
		"-c",
		`printf '%s|%s|%s|%s' "${PP_PRIVATE_KEY_PEM:-}" "${AWS_SECRET_ACCESS_KEY:-}" "${GOPRIVATE:-}" "${PATCHPILOT_TEST_EXTRA:-}"`,
	)
	if err != nil {
		t.Fatalf("runCommand returned error: %v\nstderr=%s", err, stderr)
	}

	parts := strings.Split(stdout, "|")
	if len(parts) != 4 {
		t.Fatalf("unexpected output %q", stdout)
	}
	if parts[0] != "" {
		t.Fatalf("expected PP_PRIVATE_KEY_PEM to be scrubbed, got %q", parts[0])
	}
	if parts[1] != "" {
		t.Fatalf("expected AWS_SECRET_ACCESS_KEY to be scrubbed, got %q", parts[1])
	}
	if parts[2] != "example.com/private" {
		t.Fatalf("expected GOPRIVATE to survive allowlist, got %q", parts[2])
	}
	if parts[3] != "extra-ok" {
		t.Fatalf("expected extra env override to be preserved, got %q", parts[3])
	}
}
