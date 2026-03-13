//go:build integration

package integration

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFixIdempotency(t *testing.T) {
	toolsDir := installFakeTools(t)
	env := integrationEnv(toolsDir)

	testCases := []struct {
		name             string
		files            map[string]string
		expectedExitCode int
		expectedAfter    int
		expectedStatus   string
	}{
		{
			name: "go module idempotent",
			files: map[string]string{
				"go.mod": "module example.com/service\n\ngo 1.22\n\nrequire github.com/example/lib v1.0.0\n",
			},
			expectedExitCode: 0,
			expectedAfter:    0,
			expectedStatus:   "success",
		},
		{
			name: "docker idempotent",
			files: map[string]string{
				"Dockerfile": "# patchpilot:deb-openssl\nFROM debian\nRUN echo baseline\n",
			},
			expectedExitCode: 0,
			expectedAfter:    1,
			expectedStatus:   "success",
		},
		{
			name: "npm idempotent",
			files: map[string]string{
				"package.json": "{\n  \"name\": \"svc\",\n  \"dependencies\": {\n    \"left-pad\": \"1.1.0\"\n  }\n}\n",
			},
			expectedExitCode: 0,
			expectedAfter:    0,
			expectedStatus:   "success",
		},
		{
			name: "pip idempotent",
			files: map[string]string{
				"requirements.txt": "requests==2.31.0\n",
			},
			expectedExitCode: 0,
			expectedAfter:    0,
			expectedStatus:   "success",
		},
		{
			name: "maven idempotent",
			files: map[string]string{
				"pom.xml": "<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-io</artifactId><version>2.14.0</version></dependency></dependencies></project>\n",
			},
			expectedExitCode: 0,
			expectedAfter:    0,
			expectedStatus:   "success",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			repo := newScenarioRepo(t, testCase.files)

			first := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
			if first.exitCode != testCase.expectedExitCode {
				t.Fatalf("first fix failed: got %d want %d\nstdout:\n%s\nstderr:\n%s", first.exitCode, testCase.expectedExitCode, first.stdout, first.stderr)
			}

			beforeSecond, err := trackedFileHashes(repo)
			if err != nil {
				t.Fatalf("hash tracked files before second run: %v", err)
			}

			second := runBinary(t, env, "--dir", repo, "fix", "--enable-agent=false")
			if second.exitCode != testCase.expectedExitCode {
				t.Fatalf("second fix failed: got %d want %d\nstdout:\n%s\nstderr:\n%s", second.exitCode, testCase.expectedExitCode, second.stdout, second.stderr)
			}

			afterSecond, err := trackedFileHashes(repo)
			if err != nil {
				t.Fatalf("hash tracked files after second run: %v", err)
			}
			if !mapsEqual(beforeSecond, afterSecond) {
				t.Fatalf("expected second run to be no-op\nbefore=%v\nafter=%v", beforeSecond, afterSecond)
			}

			summary := readSummary(t, repo)
			if summary.Fixed != 0 || summary.After != testCase.expectedAfter {
				t.Fatalf("expected second run summary to report no further fixes, got %+v", summary)
			}

			runRecord := readRunRecord(t, repo)
			if runRecord["status"] != testCase.expectedStatus {
				t.Fatalf("unexpected run record status: got %#v want %q", runRecord["status"], testCase.expectedStatus)
			}
		})
	}
}

func trackedFileHashes(repo string) (map[string]string, error) {
	result := map[string]string{}
	err := filepath.WalkDir(repo, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".patchpilot", ".scenario":
				return filepath.SkipDir
			}
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		rel, err := filepath.Rel(repo, path)
		if err != nil {
			return err
		}
		result[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	return result, err
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func readRunRecord(t *testing.T, repo string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, ".patchpilot", "run.json"))
	if err != nil {
		t.Fatalf("read run record: %v", err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode run record: %v", err)
	}
	return record
}
