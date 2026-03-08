package report

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/moolen/patchpilot/verifycheck"
)

func TestWriteAndReadVerificationBaseline(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(repo+"/.cvefix", 0o755); err != nil {
		t.Fatalf("mkdir .cvefix: %v", err)
	}
	input := verifycheck.Report{Mode: verifycheck.ModeStandard, Modules: []verifycheck.ModuleResult{{Dir: "/repo/a"}}}
	if err := WriteVerificationBaseline(repo, input); err != nil {
		t.Fatalf("WriteVerificationBaseline returned error: %v", err)
	}
	got, err := ReadVerificationBaseline(repo)
	if err != nil {
		t.Fatalf("ReadVerificationBaseline returned error: %v", err)
	}
	if got.Mode != input.Mode || len(got.Modules) != 1 || got.Modules[0].Dir != "/repo/a" {
		t.Fatalf("unexpected verification report: %#v", got)
	}
}

func TestWriteVerificationCreatesStateDir(t *testing.T) {
	repo := t.TempDir()
	input := verifycheck.Report{Mode: verifycheck.ModeStandard}
	if err := WriteVerification(repo, input); err != nil {
		t.Fatalf("WriteVerification returned error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".cvefix", verificationFile)); err != nil {
		t.Fatalf("expected verification file to exist: %v", err)
	}
}
