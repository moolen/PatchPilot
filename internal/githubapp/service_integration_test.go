package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSchedulerCycleCreatesPRAndSkipsUntilNextDueRun(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)

	service.runSchedulerCycle(context.Background())
	created, edited := fakeAPI.counts()
	if created != 1 || edited != 0 {
		t.Fatalf("unexpected PR counts after first cycle: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count after first cycle = %d, want 1", count)
	}

	service.runSchedulerCycle(context.Background())
	created, edited = fakeAPI.counts()
	if created != 1 || edited != 0 {
		t.Fatalf("unexpected PR counts after second cycle: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count after second cycle = %d, want 1", count)
	}
}

func TestSchedulerCycleForceReconcileProcessesRepositoryWhenNotDue(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	now := time.Now().UTC()
	repoKey := normalizeRepoName(owner + "/" + repo)
	if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		state.ScheduleKey = "* * * * *|UTC"
		state.NextRunAt = now.Add(time.Hour)
	}, now); err != nil {
		t.Fatalf("seed scheduler state: %v", err)
	}

	service.runSchedulerCycle(context.Background())
	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("unexpected PR counts before force reconcile: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 0 {
		t.Fatalf("scan count before force reconcile = %d, want 0", count)
	}

	service.runSchedulerCycleWithOptions(context.Background(), schedulerCycleOptions{ForceReconcile: true})
	created, edited = fakeAPI.counts()
	if created != 1 || edited != 0 {
		t.Fatalf("unexpected PR counts after force reconcile: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count after force reconcile = %d, want 1", count)
	}
}

func TestSchedulerCycleRespectsDisabledSchedule(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: disabled\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("expected no PR activity, got created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 0 {
		t.Fatalf("scan count = %d, want 0", count)
	}
}

func TestSchedulerCycleSkipsRepositoryWithoutPolicyFileWhenRequired(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.cfg.RequirePolicyFile = true
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("expected no PR activity, got created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 0 {
		t.Fatalf("scan count = %d, want 0", count)
	}
}

func TestSchedulerCycleIgnoresPatchpilotArtifacts(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, true)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("artifact-only run should not create PRs: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count = %d, want 1", count)
	}
}

func TestSchedulerCycleClosesTrackedArtifactOnlyRemediationPR(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	oldPRNumber := fakeAPI.addOpenPR(remediationPRTitle, "patchpilot/auto-fix-existing", "master", []string{".patchpilot/generated.txt"})
	oldPR, ok := fakeAPI.pullRequest(oldPRNumber)
	if !ok {
		t.Fatalf("expected seeded pull request")
	}
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	repoKey := normalizeRepoName(owner + "/" + repo)
	now := time.Now().UTC()
	if err := service.updateRepositoryState(repoKey, func(state *scheduledRepositoryState) {
		state.OpenPR = &trackedRemediationPRState{
			Number:     oldPR.Number,
			URL:        oldPR.HTMLURL,
			Branch:     oldPR.Head,
			HeadSHA:    oldPR.HeadSHA,
			CreatedAt:  oldPR.CreatedAt,
			LastSeenAt: now,
		}
	}, now); err != nil {
		t.Fatalf("seed tracked pull request state: %v", err)
	}

	service.runSchedulerCycle(context.Background())

	closedPR, ok := fakeAPI.pullRequest(oldPRNumber)
	if !ok {
		t.Fatalf("expected original pull request to remain addressable")
	}
	if closedPR.State != "closed" {
		t.Fatalf("expected artifact-only remediation PR to be closed, got state=%q", closedPR.State)
	}
	created, _ := fakeAPI.counts()
	if created != 1 {
		t.Fatalf("expected replacement remediation PR to be created, got created=%d", created)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count = %d, want 1", count)
	}

	state := service.state.Get(repoKey)
	if state.OpenPR == nil {
		t.Fatalf("expected replacement remediation PR to be tracked")
	}
	if state.OpenPR.Number == oldPRNumber {
		t.Fatalf("expected a new remediation PR number, still tracking %d", oldPRNumber)
	}
	newPR, ok := fakeAPI.pullRequest(state.OpenPR.Number)
	if !ok {
		t.Fatalf("expected replacement pull request %d", state.OpenPR.Number)
	}
	if newPR.State != "open" {
		t.Fatalf("expected replacement pull request to stay open, got state=%q", newPR.State)
	}
}

func TestSchedulerCycleRequiresRepositoryOptInLabel(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.topics = []string{"team-a"}
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.cfg.RepositoryLabelSelectors = []string{"patchpilot"}
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("expected no PR activity, got created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 0 {
		t.Fatalf("scan count = %d, want 0", count)
	}
}

func TestSchedulerCycleProcessesRepositoryWhenOptInLabelMatches(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.topics = []string{"patchpilot", "team-a"}
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.cfg.RepositoryLabelSelectors = []string{"patch*"}
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 1 || edited != 0 {
		t.Fatalf("unexpected PR counts: created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 1 {
		t.Fatalf("scan count = %d, want 1", count)
	}
}

func TestSchedulerCycleIgnoreLabelOverridesOptInLabel(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.topics = []string{"patchpilot", "patchpilot-ignore"}
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)
	service.cfg.RepositoryLabelSelectors = []string{"patchpilot"}
	service.cfg.RepositoryIgnoreLabelSelectors = []string{"*-ignore"}
	service.runSchedulerCycle(context.Background())

	created, edited := fakeAPI.counts()
	if created != 0 || edited != 0 {
		t.Fatalf("expected no PR activity, got created=%d edited=%d", created, edited)
	}
	if count := readInvocationCount(t, scanCountPath); count != 0 {
		t.Fatalf("scan count = %d, want 0", count)
	}
}

func TestSchedulerCycleReconcilesMergedPullRequestMetrics(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	patchpilotPath := setupSchedulerFakePatchPilot(t, temp, scanCountPath, false)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)

	service.runSchedulerCycle(context.Background())

	state := service.state.Get(normalizeRepoName(owner + "/" + repo))
	if state.OpenPR == nil || state.OpenPR.Number != 1 {
		t.Fatalf("expected tracked remediation PR, got %#v", state.OpenPR)
	}
	assertGaugeValue(t, service.metrics, "patchpilot_open_remediation_pull_requests", nil, 1)
	assertGaugeValue(t, service.metrics, "patchpilot_fixable_findings_total", nil, 1)

	fakeAPI.closeMergedPR(1, time.Now().UTC())

	service.runSchedulerCycle(context.Background())

	state = service.state.Get(normalizeRepoName(owner + "/" + repo))
	if state.OpenPR != nil {
		t.Fatalf("expected tracked remediation PR to be cleared, got %#v", state.OpenPR)
	}
	assertGaugeValue(t, service.metrics, "patchpilot_open_remediation_pull_requests", nil, 0)
	assertHistogramCount(t, service.metrics, "patchpilot_remediation_time_to_merge_seconds", nil, 1)
}

func TestSchedulerCyclePassesOCIMappingFileToScanAndFix(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	scanCountPath := filepath.Join(temp, "scan-count.txt")
	invocationsPath := filepath.Join(temp, "patchpilot-invocations.log")
	patchpilotPath := setupSchedulerFakePatchPilotWithInvocationLog(t, temp, scanCountPath, false, invocationsPath)

	fakeAPI := newFakeSchedulerGitHubAPI(owner, repo)
	fakeAPI.policyContent = "version: 1\nscan:\n  cron: \"* * * * *\"\n  timezone: UTC\n"
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	service := newSchedulerTestService(t, temp, remoteRoot, patchpilotPath, server.URL)

	runtimeConfigPath := filepath.Join(temp, "runtime-oci.yaml")
	runtimeConfig := "oci:\n" +
		"  mappings:\n" +
		"    - repo: " + owner + "/" + repo + "\n" +
		"      images:\n" +
		"        - source: ghcr.io/acme/demo\n" +
		"          dockerfiles:\n" +
		"            - Dockerfile\n"
	if err := os.WriteFile(runtimeConfigPath, []byte(runtimeConfig), 0o644); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}
	loadedRuntimeConfig, err := LoadAppRuntimeConfig(runtimeConfigPath)
	if err != nil {
		t.Fatalf("load runtime config: %v", err)
	}
	service.setRuntimeConfig(loadedRuntimeConfig)

	service.runSchedulerCycle(context.Background())

	invocations, err := os.ReadFile(invocationsPath)
	if err != nil {
		t.Fatalf("read invocation log: %v", err)
	}
	hasOCIFlag := func(command string) bool {
		for _, line := range strings.Split(strings.TrimSpace(string(invocations)), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, command+" ") && strings.Contains(trimmed, "--oci-mapping-file") {
				return true
			}
		}
		return false
	}
	if !hasOCIFlag("scan") {
		t.Fatalf("expected scan invocation with --oci-mapping-file, got:\n%s", string(invocations))
	}
	if !hasOCIFlag("fix") {
		t.Fatalf("expected fix invocation with --oci-mapping-file, got:\n%s", string(invocations))
	}
}

func newSchedulerTestService(t *testing.T, temp, remoteRoot, patchpilotPath, serverURL string) *Service {
	t.Helper()

	cfg := Config{
		AppID:              1,
		PrivateKeyPEM:      generateTestPrivateKeyPEM(t),
		ListenAddr:         ":0",
		WorkDir:            filepath.Join(temp, "work"),
		PatchPilotBinary:   patchpilotPath,
		GitHubBaseWebURL:   "file://" + remoteRoot,
		GitHubAPIBaseURL:   serverURL + "/api/v3/",
		GitHubUploadAPIURL: serverURL + "/api/uploads/",
		SchedulerTick:      time.Hour,
		RepoRunTimeout:     20 * time.Minute,
	}

	service, err := NewService(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func generateTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return string(encoded)
}

func setupSchedulerFakePatchPilot(t *testing.T, root, scanCountPath string, artifactOnly bool) string {
	return setupSchedulerFakePatchPilotWithInvocationLog(t, root, scanCountPath, artifactOnly, "")
}

func setupSchedulerFakePatchPilotWithInvocationLog(t *testing.T, root, scanCountPath string, artifactOnly bool, invocationLogPath string) string {
	t.Helper()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}

	path := filepath.Join(binDir, "patchpilot")
	fixBody := "echo \"patched $(date +%s)\" >> \"$dir/README.md\"\n"
	scanFindings := "{\"findings\":[{\"vulnerability_id\":\"GHSA-1\",\"package\":\"golang\",\"fixed_version\":\"1.27.0\",\"ecosystem\":\"deb\",\"locations\":[\"Dockerfile\"]}]}"
	if artifactOnly {
		fixBody = "mkdir -p \"$dir/.patchpilot\"\necho \"artifact-only\" > \"$dir/.patchpilot/generated.txt\"\n"
		scanFindings = "{\"findings\":[{\"vulnerability_id\":\"GHSA-1\",\"package\":\"artifact-only\",\"fixed_version\":\"1.0.1\",\"ecosystem\":\"generic\",\"locations\":[\".patchpilot/generated.txt\"]}]}"
	}

	script := "#!/bin/sh\nset -eu\n" +
		"command=\"$1\"\nshift\n" +
		func() string {
			if strings.TrimSpace(invocationLogPath) == "" {
				return ""
			}
			return "echo \"$command $*\" >> \"" + invocationLogPath + "\"\n"
		}() +
		"dir=\"\"\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --dir) dir=\"$2\"; shift 2 ;;\n" +
		"    *) shift ;;\n" +
		"  esac\n" +
		"done\n" +
		"case \"$command\" in\n" +
		"  scan)\n" +
		"    count=$(cat \"" + scanCountPath + "\" 2>/dev/null || echo 0)\n" +
		"    count=$((count + 1))\n" +
		"    echo \"$count\" > \"" + scanCountPath + "\"\n" +
		"    mkdir -p \"$dir/.patchpilot\"\n" +
		"    echo '" + scanFindings + "' > \"$dir/.patchpilot/findings.json\"\n" +
		"    exit 23\n" +
		"    ;;\n" +
		"  fix)\n" +
		fixBody +
		"    mkdir -p \"$dir/.patchpilot\"\n" +
		"    echo '{\"before\":1,\"fixed\":1,\"after\":0}' > \"$dir/.patchpilot/summary.json\"\n" +
		"    exit 0\n" +
		"    ;;\n" +
		"  *)\n" +
		"    echo \"unsupported command: $command\" >&2\n" +
		"    exit 1\n" +
		"    ;;\n" +
		"esac\n"

	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake patchpilot: %v", err)
	}
	return path
}

func setupRemoteRepo(t *testing.T, root string) (string, string, string) {
	t.Helper()
	owner := "acme"
	repo := "demo"
	remoteRoot := filepath.Join(root, "remotes")
	remotePath := filepath.Join(remoteRoot, owner, repo+".git")
	if err := os.MkdirAll(filepath.Dir(remotePath), 0o755); err != nil {
		t.Fatalf("mkdir remote parent: %v", err)
	}

	runCommandOrFail(t, root, "git", "init", "--bare", remotePath)

	seedPath := filepath.Join(root, "seed")
	runCommandOrFail(t, root, "git", "init", "-b", "master", seedPath)
	if err := os.WriteFile(filepath.Join(seedPath, "README.md"), []byte("seed\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	if err := os.WriteFile(filepath.Join(seedPath, "go.mod"), []byte("module example.com/demo\n\ngo 1.26.1\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(seedPath, "Dockerfile"), []byte("FROM golang:1.26.1\n"), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	runCommandOrFail(t, seedPath, "git", "add", "-A")
	runCommandOrFail(t, seedPath, "git", "-c", "user.name=Tester", "-c", "user.email=test@example.com", "commit", "-m", "seed")
	runCommandOrFail(t, seedPath, "git", "remote", "add", "origin", remotePath)
	runCommandOrFail(t, seedPath, "git", "push", "-u", "origin", "master")

	return remoteRoot, owner, repo
}

func runCommandOrFail(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = dir
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %s %s\n%s\n%v", name, strings.Join(args, " "), string(output), err)
	}
}

func readInvocationCount(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read invocation count: %v", err)
	}
	count, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("parse invocation count: %v", err)
	}
	return count
}

type fakeSchedulerGitHubAPI struct {
	mu sync.Mutex

	owner         string
	repo          string
	topics        []string
	policyContent string
	prs           map[int]fakePR
	nextPRNumber  int
	createdPRs    int
	editedPRs     int
}

type fakePR struct {
	Number    int
	Title     string
	Head      string
	HeadSHA   string
	Base      string
	Body      string
	Files     []string
	NodeID    string
	HTMLURL   string
	State     string
	CreatedAt time.Time
	MergedAt  time.Time
}

func newFakeSchedulerGitHubAPI(owner, repo string) *fakeSchedulerGitHubAPI {
	return &fakeSchedulerGitHubAPI{
		owner:        owner,
		repo:         repo,
		prs:          map[int]fakePR{},
		nextPRNumber: 1,
	}
}

func (api *fakeSchedulerGitHubAPI) counts() (int, int) {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.createdPRs, api.editedPRs
}

func (api *fakeSchedulerGitHubAPI) closeMergedPR(number int, mergedAt time.Time) {
	api.mu.Lock()
	defer api.mu.Unlock()

	pr := api.prs[number]
	pr.State = "closed"
	pr.MergedAt = mergedAt.UTC()
	api.prs[number] = pr
}

func (api *fakeSchedulerGitHubAPI) addOpenPR(title, head, base string, files []string) int {
	api.mu.Lock()
	defer api.mu.Unlock()

	prNumber := api.nextPRNumber
	api.nextPRNumber++
	api.prs[prNumber] = fakePR{
		Number:    prNumber,
		Title:     title,
		Head:      head,
		HeadSHA:   "fake-head-sha",
		Base:      base,
		Files:     append([]string(nil), files...),
		NodeID:    "PR_node_" + strconv.Itoa(prNumber),
		HTMLURL:   "https://example.com/" + api.owner + "/" + api.repo + "/pull/" + strconv.Itoa(prNumber),
		State:     "open",
		CreatedAt: time.Now().UTC(),
	}
	return prNumber
}

func (api *fakeSchedulerGitHubAPI) pullRequest(number int) (fakePR, bool) {
	api.mu.Lock()
	defer api.mu.Unlock()

	pr, ok := api.prs[number]
	return pr, ok
}

func (api *fakeSchedulerGitHubAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path

	if path == "/api/v3/app/installations" && request.Method == http.MethodGet {
		writeJSON(writer, []map[string]interface{}{
			{
				"id": 99,
				"account": map[string]interface{}{
					"login": api.owner,
				},
			},
		})
		return
	}

	if path == "/api/v3/app/installations/99/access_tokens" && request.Method == http.MethodPost {
		writeJSON(writer, map[string]interface{}{"token": "fake-installation-token"})
		return
	}

	if path == "/api/v3/installation/repositories" && request.Method == http.MethodGet {
		writeJSON(writer, map[string]interface{}{
			"total_count": 1,
			"repositories": []map[string]interface{}{
				{
					"name":           api.repo,
					"full_name":      api.owner + "/" + api.repo,
					"default_branch": "master",
					"owner": map[string]interface{}{
						"login": api.owner,
						"name":  api.owner,
					},
				},
			},
		})
		return
	}

	if path == "/api/v3/repos/"+api.owner+"/"+api.repo+"/topics" && request.Method == http.MethodGet {
		writeJSON(writer, map[string]interface{}{
			"names": api.topics,
		})
		return
	}

	if path == "/api/v3/repos/"+api.owner+"/"+api.repo+"/contents/.patchpilot.yaml" && request.Method == http.MethodGet {
		if strings.TrimSpace(api.policyContent) == "" {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}
		writeJSON(writer, map[string]interface{}{
			"type":     "file",
			"encoding": "base64",
			"path":     ".patchpilot.yaml",
			"content":  base64.StdEncoding.EncodeToString([]byte(api.policyContent)),
		})
		return
	}

	basePullsPath := "/api/v3/repos/" + api.owner + "/" + api.repo + "/pulls"
	if strings.HasPrefix(path, "/api/v3/repos/"+api.owner+"/"+api.repo+"/commits/") && strings.HasSuffix(path, "/status") && request.Method == http.MethodGet {
		writeJSON(writer, map[string]interface{}{
			"state":    "success",
			"statuses": []map[string]interface{}{},
		})
		return
	}
	if strings.HasPrefix(path, "/api/v3/repos/"+api.owner+"/"+api.repo+"/commits/") && strings.HasSuffix(path, "/check-runs") && request.Method == http.MethodGet {
		writeJSON(writer, map[string]interface{}{
			"total_count": 0,
			"check_runs":  []map[string]interface{}{},
		})
		return
	}
	if path == basePullsPath && request.Method == http.MethodGet {
		api.mu.Lock()
		defer api.mu.Unlock()
		response := make([]map[string]interface{}, 0, len(api.prs))
		for _, pr := range api.prs {
			if pr.State != "open" {
				continue
			}
			response = append(response, pullRequestPayload(pr))
		}
		writeJSON(writer, response)
		return
	}

	if strings.HasPrefix(path, basePullsPath+"/") && request.Method == http.MethodGet {
		numberText := strings.TrimPrefix(path, basePullsPath+"/")
		if strings.HasSuffix(numberText, "/files") {
			numberText = strings.TrimSuffix(numberText, "/files")
			number, err := strconv.Atoi(numberText)
			if err != nil {
				http.Error(writer, err.Error(), http.StatusBadRequest)
				return
			}

			api.mu.Lock()
			pr, ok := api.prs[number]
			api.mu.Unlock()
			if !ok {
				http.Error(writer, "not found", http.StatusNotFound)
				return
			}

			files := make([]map[string]interface{}, 0, len(pr.Files))
			for _, file := range pr.Files {
				files = append(files, map[string]interface{}{"filename": file})
			}
			writeJSON(writer, files)
			return
		}
		number, err := strconv.Atoi(numberText)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		api.mu.Lock()
		pr, ok := api.prs[number]
		api.mu.Unlock()
		if !ok {
			http.Error(writer, "not found", http.StatusNotFound)
			return
		}

		writeJSON(writer, pullRequestPayload(pr))
		return
	}

	if path == basePullsPath && request.Method == http.MethodPost {
		var payload struct {
			Title string `json:"title"`
			Head  string `json:"head"`
			Base  string `json:"base"`
			Body  string `json:"body"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		api.mu.Lock()
		prNumber := api.nextPRNumber
		api.nextPRNumber++
		createdAt := time.Now().UTC()
		pr := fakePR{
			Number:    prNumber,
			Title:     payload.Title,
			Head:      payload.Head,
			HeadSHA:   "fake-head-sha",
			Base:      payload.Base,
			Body:      payload.Body,
			Files:     []string{"README.md"},
			NodeID:    "PR_node_" + strconv.Itoa(prNumber),
			HTMLURL:   "https://example.com/" + api.owner + "/" + api.repo + "/pull/" + strconv.Itoa(prNumber),
			State:     "open",
			CreatedAt: createdAt,
		}
		api.prs[prNumber] = pr
		api.createdPRs++
		api.mu.Unlock()

		writeJSON(writer, pullRequestPayload(pr))
		return
	}

	if strings.HasPrefix(path, basePullsPath+"/") && request.Method == http.MethodPatch {
		numberText := strings.TrimPrefix(path, basePullsPath+"/")
		number, err := strconv.Atoi(numberText)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		var payload struct {
			Title *string `json:"title"`
			Body  *string `json:"body"`
			State *string `json:"state"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		api.mu.Lock()
		pr := api.prs[number]
		if payload.Title != nil {
			pr.Title = *payload.Title
		}
		if payload.Body != nil {
			pr.Body = *payload.Body
		}
		if payload.State != nil {
			pr.State = *payload.State
		}
		api.prs[number] = pr
		if payload.Title != nil || payload.Body != nil {
			api.editedPRs++
		}
		api.mu.Unlock()

		writeJSON(writer, pullRequestPayload(pr))
		return
	}

	if strings.HasPrefix(path, "/api/v3/repos/"+api.owner+"/"+api.repo+"/git/refs/heads/") && request.Method == http.MethodDelete {
		writer.WriteHeader(http.StatusNoContent)
		return
	}

	http.Error(writer, "not found", http.StatusNotFound)
}

func pullRequestPayload(pr fakePR) map[string]interface{} {
	payload := map[string]interface{}{
		"number":     pr.Number,
		"title":      pr.Title,
		"body":       pr.Body,
		"html_url":   pr.HTMLURL,
		"node_id":    pr.NodeID,
		"state":      pr.State,
		"created_at": pr.CreatedAt.Format(time.RFC3339),
		"head": map[string]interface{}{
			"ref": pr.Head,
			"sha": pr.HeadSHA,
		},
		"base": map[string]interface{}{
			"ref": pr.Base,
		},
	}
	if !pr.MergedAt.IsZero() {
		payload["merged_at"] = pr.MergedAt.Format(time.RFC3339)
	}
	return payload
}

func writeJSON(writer http.ResponseWriter, payload interface{}) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(payload)
}
