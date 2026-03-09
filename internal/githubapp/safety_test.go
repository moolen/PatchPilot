package githubapp

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathBlocked(t *testing.T) {
	if !pathBlocked(".github/workflows/ci.yml", []string{".github/**"}) {
		t.Fatalf("expected .github path to be blocked")
	}
	if !pathBlocked("secrets/token.txt", []string{"secrets/*.txt"}) {
		t.Fatalf("expected secrets glob to match")
	}
	if pathBlocked("cmd/main.go", []string{"secrets/*.txt"}) {
		t.Fatalf("unexpected blocked path")
	}
}

func TestEvaluateSafetyBlocksOnVerificationRegression(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".patchpilot", "summary.json"), []byte(`{"before":2,"fixed":1,"after":1}`), 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".patchpilot", "verification.json"), []byte(`{"mode":"standard","modules":[],"regressions":[{"dir":".","check":"build","baseline_status":"ok","after_status":"failed"}]}`), 0o644); err != nil {
		t.Fatalf("write verification: %v", err)
	}

	service := &Service{cfg: Config{MaxRiskScore: 10}}
	assessment, err := service.evaluateSafety(repo, []string{"go.mod"})
	if err != nil {
		t.Fatalf("evaluateSafety: %v", err)
	}
	if !assessment.Blocked {
		t.Fatalf("expected assessment to be blocked")
	}
	if assessment.VerificationRegressions != 1 {
		t.Fatalf("VerificationRegressions = %d, want 1", assessment.VerificationRegressions)
	}
}

func TestEvaluateSafetyBlocksOnRiskThreshold(t *testing.T) {
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".patchpilot"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".patchpilot", "summary.json"), []byte(`{"before":10,"fixed":0,"after":10}`), 0o644); err != nil {
		t.Fatalf("write summary: %v", err)
	}

	service := &Service{cfg: Config{MaxRiskScore: 5}}
	assessment, err := service.evaluateSafety(repo, []string{"go.mod", "go.sum"})
	if err != nil {
		t.Fatalf("evaluateSafety: %v", err)
	}
	if !assessment.Blocked {
		t.Fatalf("expected risk threshold to block")
	}
}
