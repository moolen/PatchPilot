package sbom

import "testing"

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
