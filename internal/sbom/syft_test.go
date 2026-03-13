package sbom

import (
	"context"
	"errors"
	"testing"
)

func TestValidateSBOMOutput(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "valid json",
			input:   []byte(`{"bomFormat":"CycloneDX","version":1}`),
			wantErr: false,
		},
		{
			name:    "empty output",
			input:   []byte(" \n\t"),
			wantErr: true,
		},
		{
			name:    "invalid json",
			input:   []byte(`{"bomFormat":`),
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSBOMOutput(tc.input)
			if tc.wantErr && err == nil {
				t.Fatalf("expected an error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestBuildExcludesIncludesDefaultsAndCustomPaths(t *testing.T) {
	excludes := buildExcludes([]string{"vendor", "**/.cache/**", "./vendor", "  "})
	has := func(value string) bool {
		for _, item := range excludes {
			if item == value {
				return true
			}
		}
		return false
	}

	for _, expected := range []string{"./.git", "./vendor", "**/.terraform/**", "**/.cache/**"} {
		if !has(expected) {
			t.Fatalf("expected %q in excludes: %#v", expected, excludes)
		}
	}
}

func TestDeriveDirectorySourceName(t *testing.T) {
	tests := []struct {
		name   string
		repo   string
		source string
		want   string
	}{
		{
			name:   "uses repo basename when available",
			repo:   "/tmp/my-repo",
			source: "dir:/other/path",
			want:   "my-repo",
		},
		{
			name:   "falls back to dir source basename",
			repo:   "",
			source: "dir:/workspace/fallback-repo",
			want:   "fallback-repo",
		},
		{
			name:   "has stable fallback when input is unusable",
			repo:   " ",
			source: "dir:",
			want:   "source-dir",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveDirectorySourceName(tc.repo, tc.source)
			if got != tc.want {
				t.Fatalf("unexpected source name: got %q want %q", got, tc.want)
			}
		})
	}
}

func TestDeriveDirectorySourceVersion(t *testing.T) {
	original := readGitHead
	defer func() {
		readGitHead = original
	}()

	type result struct {
		head string
		err  error
	}
	tests := []struct {
		name    string
		repo    string
		source  string
		outputs map[string]result
		want    string
	}{
		{
			name:   "uses repo head first",
			repo:   "/repo",
			source: "dir:/source",
			outputs: map[string]result{
				"/repo":   {head: "repo-sha"},
				"/source": {head: "source-sha"},
			},
			want: "repo-sha",
		},
		{
			name:   "falls back to source path head",
			repo:   "/repo",
			source: "dir:/source",
			outputs: map[string]result{
				"/repo":   {err: errors.New("not a git repo")},
				"/source": {head: "source-sha"},
			},
			want: "source-sha",
		},
		{
			name:   "returns empty when no git head available",
			repo:   "/repo",
			source: "dir:/source",
			outputs: map[string]result{
				"/repo":   {err: errors.New("not a git repo")},
				"/source": {err: errors.New("not a git repo")},
			},
			want: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			readGitHead = func(_ context.Context, dir string) (string, error) {
				out, ok := tc.outputs[dir]
				if !ok {
					return "", errors.New("unexpected directory")
				}
				return out.head, out.err
			}

			got := deriveDirectorySourceVersion(context.Background(), tc.repo, tc.source)
			if got != tc.want {
				t.Fatalf("unexpected source version: got %q want %q", got, tc.want)
			}
		})
	}
}
