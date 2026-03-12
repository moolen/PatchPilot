//go:build integration

package integration

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

var (
	integrationBinary          string
	integrationFakeAgentBinary string
	integrationRoot            string
)

type commandResult struct {
	stdout   string
	stderr   string
	exitCode int
}

type registryTagFixture struct {
	Registry   string
	Repository string
	Tags       []string
}

type summarySnapshot struct {
	Before       int `json:"before"`
	Fixed        int `json:"fixed"`
	After        int `json:"after"`
	Verification *struct {
		Mode        string `json:"mode"`
		Regressions int    `json:"regressions"`
	} `json:"verification,omitempty"`
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve working directory: %v\n", err)
		os.Exit(1)
	}
	integrationRoot = filepath.Clean(filepath.Join(wd, ".."))

	buildDir, err := os.MkdirTemp(integrationRoot, ".patchpilot-integration-build-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create build dir: %v\n", err)
		os.Exit(1)
	}
	integrationBinary = filepath.Join(buildDir, "patchpilot")
	if err := buildIntegrationBinary(integrationBinary, "./cmd/patchpilot"); err != nil {
		fmt.Fprintf(os.Stderr, "build patchpilot binary: %v\n", err)
		os.Exit(1)
	}
	integrationFakeAgentBinary = filepath.Join(buildDir, "fake-agent")
	if err := buildIntegrationBinaryWithTags(integrationFakeAgentBinary, "./integration", "fakeagentfixture"); err != nil {
		fmt.Fprintf(os.Stderr, "build fake agent binary: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	_ = os.RemoveAll(buildDir)
	os.Exit(code)
}

func buildIntegrationBinary(outputPath, packagePath string) error {
	return buildIntegrationBinaryWithTags(outputPath, packagePath)
}

func buildIntegrationBinaryWithTags(outputPath, packagePath string, tags ...string) error {
	args := []string{"build"}
	if len(tags) > 0 {
		args = append(args, "-tags", strings.Join(tags, ","))
	}
	args = append(args, "-o", outputPath, packagePath)

	buildCommand := exec.Command("go", args...)
	buildCommand.Dir = integrationRoot
	buildOutput, err := buildCommand.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, string(buildOutput))
	}
	return nil
}

func TestFixScenarios(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)

	testCases := []struct {
		name              string
		files             map[string]string
		policy            string
		registryTags      []registryTagFixture
		expectedExitCode  int
		expectSummary     *summarySnapshot
		expectNoSummary   bool
		expectContains    map[string]string
		expectNotContains map[string]string
		extraAssertions   func(t *testing.T, repo string)
	}{
		{
			name: "go direct patch",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"go.mod": "github.com/example/lib v1.2.3",
			},
		},
		{
			name: "npm dependency patch",
			files: map[string]string{
				"package.json": "{\n  \"name\": \"svc\",\n  \"dependencies\": {\n    \"left-pad\": \"1.1.0\"\n  }\n}\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"package.json": "\"left-pad\": \"1.3.0\"",
			},
		},
		{
			name: "pip dependency patch",
			files: map[string]string{
				"requirements.txt": "requests==2.31.0\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"requirements.txt": "requests>=2.32.4",
			},
		},
		{
			name: "maven dependency patch",
			files: map[string]string{
				"pom.xml": "<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-io</artifactId><version>2.14.0</version></dependency></dependencies></project>\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"pom.xml": "<version>2.15.1</version>",
			},
		},
		{
			name: "cargo dependency patch",
			files: map[string]string{
				"Cargo.toml": "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.190\"\n",
				"Cargo.lock": "version = 3\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.190\"\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"Cargo.toml": "serde = \"1.0.197\"",
				"Cargo.lock": "version = \"1.0.197\"",
			},
		},
		{
			name: "already fixed no changes",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.2.3\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
		},
		{
			name: "exclude CVE in policy",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			policy:           "version: 1\nexclude:\n  cves:\n    - GHSA-go-lib\n",
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
			expectContains: map[string]string{
				"go.mod": "github.com/example/lib v1.0.0",
			},
		},
		{
			name: "skip paths policy",
			files: map[string]string{
				"examples/legacy/go.mod": "module example.com/legacy\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			policy:           "version: 1\nscan:\n  skip_paths:\n    - examples/**\n",
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
			expectContains: map[string]string{
				"examples/legacy/go.mod": "github.com/example/lib v1.0.0",
			},
		},
		{
			name: "docker deb patch",
			files: map[string]string{
				"Dockerfile": "# patchpilot:deb-openssl\nFROM debian\nRUN echo baseline\n",
			},
			expectedExitCode: 23,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 0, After: 1},
			expectNotContains: map[string]string{
				"Dockerfile": "apt-get install --only-upgrade",
			},
		},
		{
			name: "docker apk patch",
			files: map[string]string{
				"Dockerfile": "# patchpilot:apk-busybox\nFROM alpine\nRUN echo baseline\n",
			},
			expectedExitCode: 23,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 0, After: 1},
			expectNotContains: map[string]string{
				"Dockerfile": "apk upgrade --no-cache",
			},
		},
		{
			name: "docker base image patch",
			files: map[string]string{
				"Dockerfile": "# patchpilot:base-golang\nFROM golang:1.21.0-alpine\nRUN echo baseline\n",
			},
			policy: "version: 1\noci:\n  policies:\n    - name: golang-alpine\n      source: golang\n      tags:\n        allow:\n          - '^1\\.21\\.[0-9]+-alpine$'\n        semver:\n          - range:\n              - '>=1.21.1 <1.22.0'\n",
			registryTags: []registryTagFixture{
				{
					Registry:   "docker.io",
					Repository: "library/golang",
					Tags:       []string{"1.21.0-alpine", "1.21.1-alpine", "1.22.0-alpine"},
				},
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"Dockerfile": "FROM golang:1.21.1-alpine",
			},
		},
		{
			name: "os package findings require agent",
			files: map[string]string{
				"Dockerfile": "# patchpilot:deb-openssl\nFROM debian\nRUN echo baseline\n",
			},
			expectedExitCode: 23,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 0, After: 1},
			expectNotContains: map[string]string{
				"Dockerfile": "apt-get install --only-upgrade",
			},
		},
		{
			name: "oci policy blocks base image update",
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
			expectedExitCode: 23,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 0, After: 1},
			expectContains: map[string]string{
				"Dockerfile": "FROM golang:1.21.0-alpine",
			},
		},
		{
			name: "verification regression after patch",
			files: map[string]string{
				"go.mod":                                "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
				".scenario/fail-build-when-lib-updated": "1\n",
			},
			expectedExitCode: 22,
			expectSummary: &summarySnapshot{
				Before: 1,
				Fixed:  0,
				After:  1,
				Verification: &struct {
					Mode        string `json:"mode"`
					Regressions int    `json:"regressions"`
				}{Mode: "standard", Regressions: 2},
			},
			extraAssertions: func(t *testing.T, repo string) {
				assertSummaryFindingReason(t, repo, "GHSA-go-lib", false, "verification regressed after patch")
			},
		},
		{
			name: "verification policy config ignored",
			files: map[string]string{
				"go.mod":                                 "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
				".scenario/fail-vendor-when-lib-updated": "1\n",
			},
			policy:           "version: 1\nverification:\n  commands:\n    - name: vendor\n      run: go mod vendor\n",
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 1, Fixed: 1, After: 0},
			expectContains: map[string]string{
				"go.mod": "github.com/example/lib v1.2.3",
			},
		},
		{
			name: "post execution hook failure is fatal",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.2.3\n",
			},
			policy:           "version: 1\npost_execution:\n  commands:\n    - name: break\n      run: exit 9\n      when: always\n      fail_on_error: true\n",
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
		},
		{
			name: "post execution hook failure ignored",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.2.3\n",
			},
			policy:           "version: 1\npost_execution:\n  commands:\n    - name: best-effort\n      run: exit 3\n      when: always\n      fail_on_error: false\n",
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
		},
		{
			name: "findings without fix versions are ignored",
			files: map[string]string{
				"go.mod":             "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.2.3\n",
				".scenario/nofix-go": "1\n",
			},
			expectedExitCode: 0,
			expectSummary:    &summarySnapshot{Before: 0, Fixed: 0, After: 0},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repo := newScenarioRepo(t, testCase.files)
			if strings.TrimSpace(testCase.policy) != "" {
				writeFile(t, repo, ".patchpilot.yaml", testCase.policy)
			}

			scenarioEnv := cloneEnv(env)
			if len(testCase.registryTags) > 0 {
				scenarioEnv = withRegistryTagCache(t, scenarioEnv, testCase.registryTags...)
			}
			result := runBinary(t, scenarioEnv, "--dir", repo, "fix", "--enable-agent=false")
			if result.exitCode != testCase.expectedExitCode {
				t.Fatalf("unexpected exit code: got %d want %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, testCase.expectedExitCode, result.stdout, result.stderr)
			}

			summaryPath := filepath.Join(repo, ".patchpilot", "summary.json")
			_, summaryErr := os.Stat(summaryPath)
			if !testCase.expectNoSummary {
				if summaryErr != nil {
					t.Fatalf("expected summary.json to exist: %v\nstdout:\n%s\nstderr:\n%s", summaryErr, result.stdout, result.stderr)
				}
			} else if !errors.Is(summaryErr, os.ErrNotExist) {
				t.Fatalf("expected summary.json to be absent, stat error: %v", summaryErr)
			}

			if testCase.expectSummary != nil {
				summary := readSummary(t, repo)
				if summary.Before != testCase.expectSummary.Before || summary.Fixed != testCase.expectSummary.Fixed || summary.After != testCase.expectSummary.After {
					t.Fatalf("unexpected summary counts: got before=%d fixed=%d after=%d want before=%d fixed=%d after=%d", summary.Before, summary.Fixed, summary.After, testCase.expectSummary.Before, testCase.expectSummary.Fixed, testCase.expectSummary.After)
				}
				if testCase.expectSummary.Verification != nil {
					if summary.Verification == nil {
						t.Fatalf("expected verification summary, got nil")
					}
					if summary.Verification.Mode != testCase.expectSummary.Verification.Mode || summary.Verification.Regressions != testCase.expectSummary.Verification.Regressions {
						t.Fatalf("unexpected verification summary: got %#v want mode=%q regressions=%d", summary.Verification, testCase.expectSummary.Verification.Mode, testCase.expectSummary.Verification.Regressions)
					}
				}
			}

			for path, substring := range testCase.expectContains {
				content := readFile(t, repo, path)
				if !strings.Contains(content, substring) {
					t.Fatalf("expected %s to contain %q, got:\n%s", path, substring, content)
				}
			}
			for path, substring := range testCase.expectNotContains {
				content := readFile(t, repo, path)
				if strings.Contains(content, substring) {
					t.Fatalf("expected %s not to contain %q, got:\n%s", path, substring, content)
				}
			}
			if testCase.extraAssertions != nil {
				testCase.extraAssertions(t, repo)
			}
		})
	}
}

func TestScanScenarios(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)

	testCases := []struct {
		name             string
		files            map[string]string
		policy           string
		expectedExitCode int
		expectFindings   int
	}{
		{
			name: "scan exits 23 when vulnerabilities remain",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			expectedExitCode: 23,
			expectFindings:   1,
		},
		{
			name: "scan succeeds when excluded by policy",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			policy:           "version: 1\nexclude:\n  cves:\n    - GHSA-go-lib\n",
			expectedExitCode: 0,
			expectFindings:   0,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repo := newScenarioRepo(t, testCase.files)
			if strings.TrimSpace(testCase.policy) != "" {
				writeFile(t, repo, ".patchpilot.yaml", testCase.policy)
			}

			result := runBinary(t, env, "--dir", repo, "scan")
			if result.exitCode != testCase.expectedExitCode {
				t.Fatalf("unexpected exit code: got %d want %d\nstdout:\n%s\nstderr:\n%s", result.exitCode, testCase.expectedExitCode, result.stdout, result.stderr)
			}

			findings := readFindingsCount(t, repo)
			if findings != testCase.expectFindings {
				t.Fatalf("unexpected finding count: got %d want %d", findings, testCase.expectFindings)
			}
		})
	}
}

func TestVerifyScenarios(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)

	t.Run("verify returns 22 after verification regression", func(t *testing.T) {
		repo := newScenarioRepo(t, map[string]string{
			"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
		})

		fixResult := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
		if fixResult.exitCode != 0 {
			t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", fixResult.exitCode, fixResult.stdout, fixResult.stderr)
		}

		writeFile(t, repo, ".scenario/fail-build", "1\n")
		verifyResult := runBinary(t, env, "--dir", repo, "verify")
		if verifyResult.exitCode != 22 {
			t.Fatalf("expected verify exit code 22, got %d\nstdout:\n%s\nstderr:\n%s", verifyResult.exitCode, verifyResult.stdout, verifyResult.stderr)
		}
	})

	t.Run("verify returns 23 when vulnerabilities remain", func(t *testing.T) {
		repo := newScenarioRepo(t, map[string]string{
			"Dockerfile": "# patchpilot:deb-openssl\nFROM debian\nRUN echo baseline\n",
		})

		fixResult := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
		if fixResult.exitCode != 23 {
			t.Fatalf("expected fix exit code 23, got %d\nstdout:\n%s\nstderr:\n%s", fixResult.exitCode, fixResult.stdout, fixResult.stderr)
		}

		verifyResult := runBinary(t, env, "--dir", repo, "verify")
		if verifyResult.exitCode != 23 {
			t.Fatalf("expected verify exit code 23, got %d\nstdout:\n%s\nstderr:\n%s", verifyResult.exitCode, verifyResult.stdout, verifyResult.stderr)
		}
	})

	t.Run("verify succeeds when repo stays fixed", func(t *testing.T) {
		repo := newScenarioRepo(t, map[string]string{
			"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
		})

		fixResult := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
		if fixResult.exitCode != 0 {
			t.Fatalf("expected fix to succeed, got %d\nstdout:\n%s\nstderr:\n%s", fixResult.exitCode, fixResult.stdout, fixResult.stderr)
		}

		verifyResult := runBinary(t, env, "--dir", repo, "verify")
		if verifyResult.exitCode != 0 {
			t.Fatalf("expected verify to succeed, got %d\nstdout:\n%s\nstderr:\n%s", verifyResult.exitCode, verifyResult.stdout, verifyResult.stderr)
		}
	})
}

func runBinary(t *testing.T, env map[string]string, args ...string) commandResult {
	t.Helper()
	command := exec.Command(integrationBinary, args...)
	command.Dir = integrationRoot
	command.Env = mergedEnv(env)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	result := commandResult{stdout: stdout.String(), stderr: stderr.String()}
	if err == nil {
		result.exitCode = 0
		return result
	}

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.exitCode = exitErr.ExitCode()
		return result
	}
	t.Fatalf("run %v: %v", args, err)
	return result
}

func mergedEnv(overrides map[string]string) []string {
	values := map[string]string{}
	for _, entry := range os.Environ() {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		values[key] = value
	}
	for key, value := range overrides {
		values[key] = value
	}

	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	result := make([]string, 0, len(keys))
	for _, key := range keys {
		result = append(result, key+"="+values[key])
	}
	return result
}

func cloneEnv(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func withRegistryTagCache(t *testing.T, baseEnv map[string]string, fixtures ...registryTagFixture) map[string]string {
	t.Helper()
	env := cloneEnv(baseEnv)
	cacheDir := t.TempDir()
	for _, fixture := range fixtures {
		sum := sha256.Sum256([]byte(fixture.Registry + "/" + fixture.Repository))
		path := filepath.Join(cacheDir, hex.EncodeToString(sum[:])+".json")
		entry := struct {
			FetchedAt time.Time `json:"fetched_at"`
			Tags      []string  `json:"tags"`
		}{
			FetchedAt: time.Now().UTC(),
			Tags:      append([]string(nil), fixture.Tags...),
		}
		data, err := json.MarshalIndent(entry, "", "  ")
		if err != nil {
			t.Fatalf("marshal registry cache entry: %v", err)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatalf("write registry cache entry: %v", err)
		}
	}
	env["PATCHPILOT_REGISTRY_CACHE_DIR"] = cacheDir
	return env
}

func integrationEnv(toolsDir string) map[string]string {
	return map[string]string{
		"PATH":                                toolsDir + string(os.PathListSeparator) + os.Getenv("PATH"),
		"PATCHPILOT_DISABLE_GO_RUNTIME_BUMPS": "1",
	}
}

func newScenarioRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	repo := t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".scenario"), 0o755); err != nil {
		t.Fatalf("create scenario dir: %v", err)
	}
	for path, content := range files {
		writeFile(t, repo, path, content)
	}
	return repo
}

func writeFile(t *testing.T, root, path, content string) {
	t.Helper()
	fullPath := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		t.Fatalf("create parent dir for %s: %v", path, err)
	}
	if err := os.WriteFile(fullPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, root, path string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}

func readSummary(t *testing.T, repo string) summarySnapshot {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, ".patchpilot", "summary.json"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary summarySnapshot
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("decode summary: %v", err)
	}
	return summary
}

func assertSummaryFindingReason(t *testing.T, repo, vulnerabilityID string, fixed bool, reason string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, ".patchpilot", "summary.json"))
	if err != nil {
		t.Fatalf("read summary: %v", err)
	}
	var summary struct {
		Findings []struct {
			VulnerabilityID string `json:"vulnerability_id"`
			Fixed           bool   `json:"fixed"`
			Reason          string `json:"reason"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(data, &summary); err != nil {
		t.Fatalf("decode summary findings: %v", err)
	}
	for _, finding := range summary.Findings {
		if finding.VulnerabilityID != vulnerabilityID {
			continue
		}
		if finding.Fixed != fixed || finding.Reason != reason {
			t.Fatalf("unexpected finding result for %s: %#v", vulnerabilityID, finding)
		}
		return
	}
	t.Fatalf("missing finding result for %s in summary", vulnerabilityID)
}

func readFindingsCount(t *testing.T, repo string) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, ".patchpilot", "findings.json"))
	if err != nil {
		t.Fatalf("read findings: %v", err)
	}
	var report struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("decode findings: %v", err)
	}
	return len(report.Findings)
}

func installFakeTools(t *testing.T) string {
	t.Helper()
	binDir := t.TempDir()
	for name, script := range map[string]string{
		"syft":  fakeSyftScript,
		"grype": fakeGrypeScript,
		"go":    fakeGoScript,
		"cargo": fakeCargoScript,
	} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}
	return binDir
}

const fakeSyftScript = `#!/bin/sh
set -eu
printf '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1}\n'
`

const fakeGrypeScript = `#!/bin/sh
set -eu

repo=""
for arg in "$@"; do
  case "$arg" in
    sbom:*)
      sbom_path="${arg#sbom:}"
      case "$sbom_path" in
        */.patchpilot/sbom.json)
          repo="${sbom_path%/.patchpilot/sbom.json}"
          ;;
      esac
      ;;
  esac
done
if [ -z "$repo" ]; then
  repo=$(pwd)
fi

normalize_version() {
  version=$(printf '%s' "$1" | sed -E 's/^[^0-9]*//')
  version="${version#v}"
  version="${version%%-*}"
  printf '%s' "$version"
}

version_lt() {
  left=$(normalize_version "$1")
  right=$(normalize_version "$2")
  if [ -z "$left" ]; then
    return 0
  fi
  if [ "$left" = "$right" ]; then
    return 1
  fi
  first=$(printf '%s\n%s\n' "$left" "$right" | sort -V | head -n 1)
  [ "$first" = "$left" ]
}

module_version_from_gomod() {
  mod_path="$1"
  target="$2"
  awk -v target="$target" '
    $1 == "require" && $2 == target { print $3; exit }
    $1 == target { print $2; exit }
  ' "$mod_path"
}

append_match() {
  if [ -s "$matches_file" ]; then
    printf ',\n' >>"$matches_file"
  fi
  printf '%s' "$1" >>"$matches_file"
}

matches_file=$(mktemp)
cleanup() {
  rm -f "$matches_file"
}
trap cleanup EXIT INT TERM
: >"$matches_file"

while IFS= read -r mod_path; do
  [ -n "$mod_path" ] || continue
  rel="${mod_path#$repo/}"
  version=$(module_version_from_gomod "$mod_path" "github.com/example/lib")
  if version_lt "$version" "v1.2.3"; then
    [ -n "$version" ] || version="v0.0.0"
    append_match "{\"artifact\":{\"name\":\"github.com/example/lib\",\"version\":\"$version\",\"type\":\"go-module\",\"language\":\"go\",\"purl\":\"pkg:golang/github.com/example/lib@$version\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-go-lib\",\"namespace\":\"github:language:go\",\"fix\":{\"versions\":[\"v1.2.3\"],\"state\":\"fixed\"}}}"
  fi
done <<EOF
$(find "$repo" -type f -name go.mod | sort)
EOF

if [ -f "$repo/.scenario/nofix-go" ]; then
  append_match "{\"artifact\":{\"name\":\"github.com/example/nofix\",\"version\":\"v0.1.0\",\"type\":\"go-module\",\"language\":\"go\",\"purl\":\"pkg:golang/github.com/example/nofix@v0.1.0\",\"locations\":[{\"path\":\"/go.mod\"}]},\"vulnerability\":{\"id\":\"GHSA-no-fix\",\"namespace\":\"github:language:go\",\"fix\":{\"versions\":[],\"state\":\"not-fixed\"}}}"
fi

npm_version_from_manifest() {
  manifest="$1"
  package="$2"
  awk -v pkg="$package" '
    {
      if ($0 ~ "\"" pkg "\"[[:space:]]*:") {
        line=$0
        sub(/.*:[[:space:]]*"/, "", line)
        sub(/".*/, "", line)
        print line
        exit
      }
    }
  ' "$manifest"
}

while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  rel="${manifest#$repo/}"
  version=$(npm_version_from_manifest "$manifest" "left-pad")
  if version_lt "$version" "1.3.0"; then
    [ -n "$version" ] || version="0.0.0"
    append_match "{\"artifact\":{\"name\":\"left-pad\",\"version\":\"$version\",\"type\":\"npm\",\"language\":\"javascript\",\"purl\":\"pkg:npm/left-pad@$version\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-npm-left-pad\",\"namespace\":\"github:language:javascript\",\"fix\":{\"versions\":[\"1.3.0\"],\"state\":\"fixed\"}}}"
  fi
done <<EOF
$(find "$repo" -type f -name package.json | sort)
EOF

while IFS= read -r reqfile; do
  [ -n "$reqfile" ] || continue
  rel="${reqfile#$repo/}"
  version=$(awk '
    tolower($1) ~ /^requests/ {
      line=$0
      sub(/.*==/, "", line)
      sub(/[[:space:]#].*/, "", line)
      print line
      exit
    }
  ' "$reqfile")
  if version_lt "$version" "2.32.4"; then
    [ -n "$version" ] || version="0.0.0"
    append_match "{\"artifact\":{\"name\":\"requests\",\"version\":\"$version\",\"type\":\"python\",\"language\":\"python\",\"purl\":\"pkg:pypi/requests@$version\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-pip-requests\",\"namespace\":\"github:language:python\",\"fix\":{\"versions\":[\"2.32.4\"],\"state\":\"fixed\"}}}"
  fi
done <<EOF
$(find "$repo" -type f \( -name requirements.txt -o -name 'requirements*.txt' \) | sort)
EOF

while IFS= read -r pom; do
  [ -n "$pom" ] || continue
  rel="${pom#$repo/}"
  version=$(awk '
    /<dependency>/ { in_dep = 1; artifact = ""; version = "" }
    in_dep && /<artifactId>[[:space:]]*commons-io[[:space:]]*<\/artifactId>/ { artifact = "commons-io" }
    in_dep && /<version>/ {
      line=$0
      sub(/.*<version>[[:space:]]*/, "", line)
      sub(/[[:space:]]*<\/version>.*/, "", line)
      version = line
    }
    /<\/dependency>/ {
      if (in_dep && artifact == "commons-io" && version != "") {
        print version
        exit
      }
      in_dep = 0
    }
  ' "$pom")
  if version_lt "$version" "2.15.1"; then
    [ -n "$version" ] || version="0.0.0"
    append_match "{\"artifact\":{\"name\":\"commons-io\",\"version\":\"$version\",\"type\":\"maven\",\"language\":\"java\",\"purl\":\"pkg:maven/org.apache.commons/commons-io@$version\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-maven-commons-io\",\"namespace\":\"github:language:java\",\"fix\":{\"versions\":[\"2.15.1\"],\"state\":\"fixed\"}}}"
  fi
done <<EOF
$(find "$repo" -type f -name pom.xml | sort)
EOF

cargo_version_from_manifest() {
  manifest="$1"
  package="$2"
  awk -v pkg="$package" '
    $0 ~ "^" pkg "[[:space:]]*=" {
      line=$0
      sub(/.*=[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$manifest"
}

while IFS= read -r manifest; do
  [ -n "$manifest" ] || continue
  rel="${manifest#$repo/}"
  version=$(cargo_version_from_manifest "$manifest" "serde")
  if version_lt "$version" "1.0.197"; then
    [ -n "$version" ] || version="0.0.0"
    append_match "{\"artifact\":{\"name\":\"serde\",\"version\":\"$version\",\"type\":\"rust-crate\",\"language\":\"rust\",\"purl\":\"pkg:cargo/serde@$version\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-cargo-serde\",\"namespace\":\"github:language:rust\",\"fix\":{\"versions\":[\"1.0.197\"],\"state\":\"fixed\"}}}"
  fi
done <<EOF
$(find "$repo" -type f -name Cargo.toml | sort)
EOF

while IFS= read -r dockerfile; do
  [ -n "$dockerfile" ] || continue
  rel="${dockerfile#$repo/}"

  if grep -q "patchpilot:deb-openssl" "$dockerfile"; then
    if ! grep -Eq "apt-get upgrade|apt-get install --only-upgrade" "$dockerfile"; then
      append_match "{\"artifact\":{\"name\":\"openssl\",\"version\":\"1.0.0\",\"type\":\"deb\",\"language\":\"\",\"purl\":\"pkg:deb/debian/openssl@1.0.0\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"CVE-deb-openssl\",\"namespace\":\"debian:distro:debian:12\",\"fix\":{\"versions\":[\"1.0.3\"],\"state\":\"fixed\"}}}"
    fi
  fi

  if grep -q "patchpilot:apk-busybox" "$dockerfile"; then
    if ! grep -Eq "apk upgrade" "$dockerfile"; then
      append_match "{\"artifact\":{\"name\":\"busybox\",\"version\":\"1.0.0\",\"type\":\"apk\",\"language\":\"\",\"purl\":\"pkg:apk/alpine/busybox@1.0.0\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"CVE-apk-busybox\",\"namespace\":\"alpine:distro:alpine:3.19\",\"fix\":{\"versions\":[\"1.0.2\"],\"state\":\"fixed\"}}}"
    fi
  fi

  if grep -q "patchpilot:base-golang" "$dockerfile"; then
    from_line=$(grep -E '^[[:space:]]*FROM[[:space:]]+' "$dockerfile" | head -n 1 || true)
    image=$(printf '%s' "$from_line" | awk '{print $2}')
    image_no_digest="${image%@*}"
    tag="${image_no_digest##*:}"
    if [ "$tag" = "$image_no_digest" ]; then
      tag=""
    fi
    if version_lt "$tag" "1.21.1"; then
      [ -n "$tag" ] || tag="0.0.0"
      append_match "{\"artifact\":{\"name\":\"golang\",\"version\":\"$tag\",\"type\":\"go-module\",\"language\":\"go\",\"purl\":\"pkg:golang/golang@$tag\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-base-golang\",\"namespace\":\"github:language:go\",\"fix\":{\"versions\":[\"1.21.1\"],\"state\":\"fixed\"}}}"
    fi
  fi

done <<EOF
$(find "$repo" -type f \( -name Dockerfile -o -name 'Dockerfile.*' -o -name '*.Dockerfile' \) | sort)
EOF

while IFS= read -r workflow; do
  [ -n "$workflow" ] || continue
  rel="${workflow#$repo/}"

  checkout_ref=$(sed -n 's/.*uses:[[:space:]]*actions\/checkout@\([^[:space:]#"]*\).*/\1/p' "$workflow" | head -n 1 || true)
  if [ -n "$checkout_ref" ]; then
    if [ "${#checkout_ref}" -eq 40 ]; then
      if [ "$checkout_ref" != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" ]; then
        append_match "{\"artifact\":{\"name\":\"actions/checkout\",\"version\":\"$checkout_ref\",\"type\":\"github-action\",\"language\":\"\",\"purl\":\"pkg:github/actions/checkout@$checkout_ref\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-actions-checkout\",\"namespace\":\"github:language:github-action\",\"fix\":{\"versions\":[\"v4.2.2\"],\"state\":\"fixed\"}}}"
      fi
    elif version_lt "$checkout_ref" "v4.2.2"; then
      append_match "{\"artifact\":{\"name\":\"actions/checkout\",\"version\":\"$checkout_ref\",\"type\":\"github-action\",\"language\":\"\",\"purl\":\"pkg:github/actions/checkout@$checkout_ref\",\"locations\":[{\"path\":\"/$rel\"}]},\"vulnerability\":{\"id\":\"GHSA-actions-checkout\",\"namespace\":\"github:language:github-action\",\"fix\":{\"versions\":[\"v4.2.2\"],\"state\":\"fixed\"}}}"
    fi
  fi
done <<EOF
$(find "$repo/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null | sort)
EOF

printf '{\n  "matches": [\n'
if [ -s "$matches_file" ]; then
  cat "$matches_file"
fi
printf '\n  ]\n}\n'
`

const fakeGoScript = `#!/bin/sh
set -eu

normalize_version() {
  version="${1#v}"
  version="${version%%-*}"
  printf '%s' "$version"
}

version_gte() {
  left=$(normalize_version "$1")
  right=$(normalize_version "$2")
  if [ -z "$left" ]; then
    return 1
  fi
  if [ "$left" = "$right" ]; then
    return 0
  fi
  first=$(printf '%s\n%s\n' "$left" "$right" | sort -V | head -n 1)
  [ "$first" = "$right" ]
}

find_repo_root() {
  dir="$PWD"
  while [ "$dir" != "/" ]; do
    if [ -d "$dir/.scenario" ]; then
      printf '%s' "$dir"
      return
    fi
    dir=$(dirname "$dir")
  done
  printf '%s' "$PWD"
}

repo_root=$(find_repo_root)

module_version_from_gomod() {
  mod_path="$1"
  target="$2"
  awk -v target="$target" '
    $1 == "require" && $2 == target { print $3; exit }
    $1 == target { print $2; exit }
  ' "$mod_path"
}

should_fail_build_checks() {
  if [ -f "$repo_root/.scenario/fail-build" ]; then
    return 0
  fi
  if [ -f "$repo_root/.scenario/fail-build-when-lib-updated" ] && [ -f "go.mod" ]; then
    version=$(module_version_from_gomod "go.mod" "github.com/example/lib")
    if version_gte "$version" "v1.2.3"; then
      return 0
    fi
  fi
  return 1
}

should_fail_vendor() {
  if [ -f "$repo_root/.scenario/fail-vendor" ]; then
    return 0
  fi
  if [ -f "$repo_root/.scenario/fail-vendor-when-lib-updated" ] && [ -f "go.mod" ]; then
    version=$(module_version_from_gomod "go.mod" "github.com/example/lib")
    if version_gte "$version" "v1.2.3"; then
      return 0
    fi
  fi
  return 1
}

emit_module_list() {
  if [ ! -f "go.mod" ]; then
    echo "go.mod not found" >&2
    exit 1
  fi

  root_module=$(awk '$1 == "module" { print $2; exit }' go.mod)
  [ -n "$root_module" ] || root_module="example.com/root"
  printf '%s v0.0.0\n' "$root_module"

  awk '
    $1 == "require" && $2 == "(" { in_block = 1; next }
    in_block && $1 == ")" { in_block = 0; next }
    $1 == "require" && NF >= 3 { print $2 " " $3; next }
    in_block && NF >= 2 { print $1 " " $2 }
  ' go.mod

  if [ -f "$repo_root/.scenario/extra-build-list" ]; then
    cat "$repo_root/.scenario/extra-build-list"
  fi
}

update_gomod_requirement() {
  entry="$1"
  module_path="${entry%@*}"
  module_version="${entry#*@}"

  if [ "$module_path" = "$entry" ] || [ -z "$module_version" ]; then
    echo "invalid go get target: $entry" >&2
    exit 1
  fi
  if [ ! -f "go.mod" ]; then
    echo "go.mod not found" >&2
    exit 1
  fi

  tmp=$(mktemp)
  if awk -v module_path="$module_path" '$1 == module_path { found = 1 } END { exit(found ? 0 : 1) }' go.mod; then
    awk -v module_path="$module_path" -v module_version="$module_version" '
      $1 == module_path { print $1 " " module_version; next }
      { print }
    ' go.mod >"$tmp"
  else
    cat go.mod >"$tmp"
    printf '\nrequire %s %s\n' "$module_path" "$module_version" >>"$tmp"
  fi
  mv "$tmp" go.mod
}

if [ "$#" -eq 0 ]; then
  exit 0
fi

case "$1" in
  build|test|vet)
    if should_fail_build_checks; then
      echo "simulated verification failure" >&2
      exit 1
    fi
    exit 0
    ;;
  list)
    if [ "${2:-}" = "-m" ] && [ "${3:-}" = "all" ]; then
      emit_module_list
      exit 0
    fi
    ;;
  get)
    update_gomod_requirement "${2:-}"
    exit 0
    ;;
  mod)
    case "${2:-}" in
      tidy)
        if [ -f "$repo_root/.scenario/fail-tidy" ]; then
          echo "simulated go mod tidy failure" >&2
          exit 1
        fi
        exit 0
        ;;
      vendor)
        if should_fail_vendor; then
          echo "simulated go mod vendor failure" >&2
          exit 1
        fi
        exit 0
        ;;
    esac
    ;;
esac

exit 0
`

const fakeCargoScript = `#!/bin/sh
set -eu

command="$1"
shift

manifest_path=""
package_name=""
precise_version=""
locked=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest-path)
      manifest_path="$2"
      shift 2
      ;;
    -p)
      package_name="$2"
      shift 2
      ;;
    --precise)
      precise_version="$2"
      shift 2
      ;;
    --locked)
      locked=1
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [ -z "$manifest_path" ]; then
  manifest_path="$(pwd)/Cargo.toml"
fi

manifest_dir=$(dirname "$manifest_path")

find_lockfile() {
  dir="$1"
  while :; do
    if [ -f "$dir/Cargo.lock" ]; then
      printf '%s\n' "$dir/Cargo.lock"
      return 0
    fi
    parent=$(dirname "$dir")
    if [ "$parent" = "$dir" ]; then
      break
    fi
    dir="$parent"
  done
  return 1
}

crate_version_from_manifest() {
  manifest="$1"
  package="$2"
  awk -v pkg="$package" '
    $0 ~ "^" pkg "[[:space:]]*=" {
      line=$0
      sub(/.*=[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$manifest"
}

crate_version_from_lockfile() {
  lockfile="$1"
  package="$2"
  awk -v pkg="$package" '
    /^\[\[package\]\]/ { in_pkg = 1; name = "" }
    in_pkg && /^name = / {
      line=$0
      sub(/^name = "/, "", line)
      sub(/".*/, "", line)
      name = line
    }
    in_pkg && /^version = / && name == pkg {
      line=$0
      sub(/^version = "/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$lockfile"
}

replace_lockfile_version() {
  lockfile="$1"
  package="$2"
  version="$3"
  awk -v pkg="$package" -v version="$version" '
    /^\[\[package\]\]/ { in_pkg = 1; name = "" }
    in_pkg && /^name = / {
      line=$0
      sub(/^name = "/, "", line)
      sub(/".*/, "", line)
      name = line
      print
      next
    }
    in_pkg && /^version = / && name == pkg {
      print "version = \"" version "\""
      next
    }
    { print }
  ' "$lockfile" >"$lockfile.tmp"
  mv "$lockfile.tmp" "$lockfile"
}

case "$command" in
  update)
    if lockfile=$(find_lockfile "$manifest_dir"); then
      replace_lockfile_version "$lockfile" "$package_name" "$precise_version"
    fi
    ;;
  metadata)
    if [ "$locked" -eq 1 ] && lockfile=$(find_lockfile "$manifest_dir"); then
      manifest_version=$(crate_version_from_manifest "$manifest_path" "serde")
      lock_version=$(crate_version_from_lockfile "$lockfile" "serde")
      if [ -n "$manifest_version" ] && [ -n "$lock_version" ] && [ "$manifest_version" != "$lock_version" ]; then
        echo "lockfile out of date for serde" >&2
        exit 1
      fi
    fi
    printf '{"packages":[],"workspace_members":[]}\n'
    ;;
  *)
    echo "unsupported cargo command: $command" >&2
    exit 1
    ;;
esac
`
