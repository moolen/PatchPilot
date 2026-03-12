//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type regressionSnapshot struct {
	ExitCode int `json:"exit_code"`
	Summary  struct {
		Before int `json:"before"`
		Fixed  int `json:"fixed"`
		After  int `json:"after"`
	} `json:"summary"`
	FailureCode string `json:"failure_code,omitempty"`
}

func TestRegressionSnapshots(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)

	testCases := []struct {
		name         string
		snapshot     string
		files        map[string]string
		policy       string
		registryTags []registryTagFixture
	}{
		{
			name:     "go-direct",
			snapshot: "go-direct.json",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
		},
		{
			name:     "docker-os-disabled",
			snapshot: "docker-os-disabled.json",
			files: map[string]string{
				"Dockerfile": "# patchpilot:deb-openssl\nFROM debian\nRUN echo baseline\n",
			},
		},
		{
			name:     "policy-blocked",
			snapshot: "policy-blocked.json",
			files: map[string]string{
				"Dockerfile": "# patchpilot:base-golang\nFROM golang:1.21.0-alpine\nRUN echo baseline\n",
			},
			policy: "version: 1\noci:\n  policies:\n    - name: blocked\n      source: golang\n      tags:\n        allow:\n          - '^1\\.21\\.[0-9]+-alpine$'\n        semver:\n          - range:\n              - '>=1.22.0 <2.0.0'\n",
			registryTags: []registryTagFixture{
				{
					Registry:   "docker.io",
					Repository: "library/golang",
					Tags:       []string{"1.21.0-alpine", "1.21.1-alpine"},
				},
			},
		},
		{
			name:     "npm-direct",
			snapshot: "npm-direct.json",
			files: map[string]string{
				"package.json": "{\n  \"name\": \"svc\",\n  \"dependencies\": {\n    \"left-pad\": \"1.1.0\"\n  }\n}\n",
			},
		},
		{
			name:     "pip-direct",
			snapshot: "pip-direct.json",
			files: map[string]string{
				"requirements.txt": "requests==2.31.0\n",
			},
		},
		{
			name:     "maven-direct",
			snapshot: "maven-direct.json",
			files: map[string]string{
				"pom.xml": "<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-io</artifactId><version>2.14.0</version></dependency></dependencies></project>\n",
			},
		},
		{
			name:     "go-vendor-verification-regression",
			snapshot: "go-vendor-verification-regression.json",
			files: map[string]string{
				"go.mod":                                 "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
				".scenario/fail-vendor-when-lib-updated": "1\n",
			},
			policy: "version: 1\nverification:\n  commands:\n    - name: vendor\n      run: go mod vendor\n",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repo := newScenarioRepo(t, testCase.files)
			if testCase.policy != "" {
				writeFile(t, repo, ".patchpilot.yaml", testCase.policy)
			}
			scenarioEnv := cloneEnv(env)
			if len(testCase.registryTags) > 0 {
				scenarioEnv = withRegistryTagCache(t, scenarioEnv, testCase.registryTags...)
			}
			result := runBinary(t, scenarioEnv, "--dir", repo, "fix", "--enable-agent=false")

			snapshot := loadRegressionSnapshot(t, testCase.snapshot)
			if result.exitCode != snapshot.ExitCode {
				t.Fatalf("unexpected exit code: got %d want %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, snapshot.ExitCode, result.stdout, result.stderr)
			}

			if snapshot.ExitCode != 21 {
				summary := readSummary(t, repo)
				if summary.Before != snapshot.Summary.Before || summary.Fixed != snapshot.Summary.Fixed || summary.After != snapshot.Summary.After {
					t.Fatalf("unexpected summary counts: got before=%d fixed=%d after=%d want before=%d fixed=%d after=%d",
						summary.Before, summary.Fixed, summary.After,
						snapshot.Summary.Before, snapshot.Summary.Fixed, snapshot.Summary.After,
					)
				}
			}

			record := readRunRecord(t, repo)
			if snapshot.FailureCode == "" {
				if _, ok := record["failure"]; ok {
					t.Fatalf("expected no failure in run record, got %#v", record["failure"])
				}
				return
			}
			failure, ok := record["failure"].(map[string]any)
			if !ok {
				t.Fatalf("expected failure object in run record, got %#v", record["failure"])
			}
			if got := failure["code"]; got != snapshot.FailureCode {
				t.Fatalf("unexpected failure code: got %v want %q", got, snapshot.FailureCode)
			}
		})
	}
}

func loadRegressionSnapshot(t *testing.T, name string) regressionSnapshot {
	t.Helper()
	path := filepath.Join("testdata", "regressions", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read snapshot %s: %v", name, err)
	}
	var snapshot regressionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		t.Fatalf("decode snapshot %s: %v", name, err)
	}
	return snapshot
}
