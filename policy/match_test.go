package policy

import (
	"path/filepath"
	"testing"
)

func TestShouldSkipPath(t *testing.T) {
	repo := t.TempDir()
	cases := []struct {
		patterns []string
		path     string
		want     bool
	}{
		{patterns: []string{"vendor"}, path: filepath.Join(repo, "vendor", "x"), want: true},
		{patterns: []string{"cmd/*/fixtures"}, path: filepath.Join(repo, "cmd", "scan", "fixtures"), want: true},
		{patterns: []string{"internal/**"}, path: filepath.Join(repo, "internal", "a", "b"), want: true},
		{patterns: []string{"docs"}, path: filepath.Join(repo, "cmd", "scan"), want: false},
	}

	for _, test := range cases {
		if got := ShouldSkipPath(repo, test.path, test.patterns); got != test.want {
			t.Fatalf("ShouldSkipPath(%q, %q) got %v want %v", test.patterns, test.path, got, test.want)
		}
	}
}

func TestLocationMatches(t *testing.T) {
	repo := t.TempDir()
	location := filepath.Join(repo, "images", "Dockerfile")
	if !LocationMatches(repo, location, "images/Dockerfile") {
		t.Fatalf("expected location to match exact relative path")
	}
	if !LocationMatches(repo, location, "images/*") {
		t.Fatalf("expected location to match glob")
	}
	if LocationMatches(repo, location, "charts/**") {
		t.Fatalf("did not expect location to match unrelated path")
	}
}
