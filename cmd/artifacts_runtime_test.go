package cmd

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/moolen/patchpilot/internal/policy"
)

func TestLoadExternalImageSpecsFromMappingFileExactRepoMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oci-mappings.yaml")
	content := `oci:
  mappings:
    - repo: Acme/Demo
      images:
        - source: ghcr.io/acme/demo
          dockerfiles:
            - Dockerfile
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	images, err := loadExternalImageSpecsFromMappingFile(path, "acme/demo")
	if err != nil {
		t.Fatalf("loadExternalImageSpecsFromMappingFile returned error: %v", err)
	}
	if len(images) != 1 {
		t.Fatalf("expected one image, got %#v", images)
	}
	if images[0].Source != "ghcr.io/acme/demo" {
		t.Fatalf("unexpected source: %q", images[0].Source)
	}
}

func TestLoadExternalImageSpecsFromMappingFileRejectsWildcardRepo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oci-mappings.yaml")
	content := `oci:
  mappings:
    - repo: acme/*
      images:
        - source: ghcr.io/acme/demo
          dockerfiles:
            - Dockerfile
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}

	if _, err := loadExternalImageSpecsFromMappingFile(path, "acme/demo"); err == nil {
		t.Fatal("expected wildcard validation error")
	}
}

func TestMergeExternalImageSpecsRepoPolicyOverridesMappingFile(t *testing.T) {
	base := []policy.OCIExternalImageSpec{
		{
			Source:      "ghcr.io/acme/demo",
			Dockerfiles: []string{"Dockerfile"},
			Tag:         "latest-semver",
		},
	}
	overlay := []policy.OCIExternalImageSpec{
		{
			Source:      "ghcr.io/acme/demo",
			Dockerfiles: []string{"containers/Dockerfile"},
			Tag:         "v1.2.3",
		},
	}

	merged := mergeExternalImageSpecs(base, overlay)
	if len(merged) != 1 {
		t.Fatalf("expected one merged spec, got %#v", merged)
	}
	if merged[0].Origin != "repo-policy" {
		t.Fatalf("expected repo-policy origin, got %q", merged[0].Origin)
	}
	if len(merged[0].Spec.Dockerfiles) != 1 || merged[0].Spec.Dockerfiles[0] != "containers/Dockerfile" {
		t.Fatalf("expected overlay dockerfiles to win, got %#v", merged[0].Spec.Dockerfiles)
	}
	if merged[0].Spec.Tag != "v1.2.3" {
		t.Fatalf("expected overlay tag to win, got %q", merged[0].Spec.Tag)
	}
}

func TestMergedExternalImageSpecCapacity(t *testing.T) {
	tests := []struct {
		name       string
		baseLen    int
		overlayLen int
		want       int
	}{
		{
			name:       "combined length fits",
			baseLen:    2,
			overlayLen: 3,
			want:       5,
		},
		{
			name:       "combined length overflows",
			baseLen:    math.MaxInt - 1,
			overlayLen: 2,
			want:       math.MaxInt - 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := mergedExternalImageSpecCapacity(test.baseLen, test.overlayLen); got != test.want {
				t.Fatalf("mergedExternalImageSpecCapacity(%d, %d) = %d, want %d", test.baseLen, test.overlayLen, got, test.want)
			}
		})
	}
}

func TestResolveExternalImageScanTargetsRequiresRepositoryKeyWhenMappingFileIsSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oci-mappings.yaml")
	content := `oci:
  mappings:
    - repo: acme/demo
      images:
        - source: ghcr.io/acme/demo
          dockerfiles:
            - Dockerfile
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write mapping file: %v", err)
	}
	if _, err := resolveExternalImageScanTargets(t.TempDir(), nil, artifactScanOptions{
		MappingFile: path,
	}); err == nil {
		t.Fatal("expected repository key validation error")
	}
}
