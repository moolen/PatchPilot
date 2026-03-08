package githubapp

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
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

func TestHandleWebhookIssueCommentE2E_DedupAndUpsert(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	cvefixPath := setupFakeCVEFix(t, temp, "README.md")

	fakeAPI := newFakeGitHubAPI(owner, repo)
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	cfg := Config{
		AppID:              1,
		WebhookSecret:      "secret",
		PrivateKeyPEM:      generateTestPrivateKeyPEM(t),
		ListenAddr:         ":0",
		WorkDir:            filepath.Join(temp, "work"),
		CVEFixBinary:       cvefixPath,
		GitHubBaseWebURL:   "file://" + remoteRoot,
		GitHubAPIBaseURL:   server.URL + "/api/v3/",
		GitHubUploadAPIURL: server.URL + "/api/uploads/",
		EnableAutoMerge:    true,
		DeliveryDedupTTL:   24 * time.Hour,
		MaxRiskScore:       30,
	}

	service, err := NewService(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	service.async = false

	payload := []byte(`{
		"action":"created",
		"comment":{"id":101,"body":"/cvefix fix --auto-merge"},
		"issue":{"number":1},
		"repository":{"name":"demo","full_name":"acme/demo","default_branch":"master","owner":{"login":"acme","name":"Acme"}},
		"sender":{"login":"alice"},
		"installation":{"id":99}
	}`)

	nextCommentPayload := []byte(`{
		"action":"created",
		"comment":{"id":102,"body":"/cvefix fix --auto-merge"},
		"issue":{"number":1},
		"repository":{"name":"demo","full_name":"acme/demo","default_branch":"master","owner":{"login":"acme","name":"Acme"}},
		"sender":{"login":"alice"},
		"installation":{"id":99}
	}`)

	if code := sendWebhook(t, service, "issue_comment", payload, cfg.WebhookSecret, "delivery-1"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}

	created, edited, autoMergeCalls := fakeAPI.counts()
	if created != 1 {
		t.Fatalf("created PRs = %d, want 1", created)
	}
	if edited != 0 {
		t.Fatalf("edited PRs = %d, want 0", edited)
	}
	if autoMergeCalls != 1 {
		t.Fatalf("auto-merge calls = %d, want 1", autoMergeCalls)
	}

	if code := sendWebhook(t, service, "issue_comment", payload, cfg.WebhookSecret, "delivery-1"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}
	created, edited, autoMergeCalls = fakeAPI.counts()
	if created != 1 || edited != 0 || autoMergeCalls != 1 {
		t.Fatalf("duplicate delivery should not process again: created=%d edited=%d auto_merge=%d", created, edited, autoMergeCalls)
	}

	if code := sendWebhook(t, service, "issue_comment", payload, cfg.WebhookSecret, "delivery-2"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}
	created, edited, autoMergeCalls = fakeAPI.counts()
	if created != 1 || edited != 0 || autoMergeCalls != 1 {
		t.Fatalf("duplicate run key should not process again: created=%d edited=%d auto_merge=%d", created, edited, autoMergeCalls)
	}

	if code := sendWebhook(t, service, "issue_comment", nextCommentPayload, cfg.WebhookSecret, "delivery-3"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}
	created, edited, autoMergeCalls = fakeAPI.counts()
	if created != 1 {
		t.Fatalf("expected PR upsert, created PRs = %d, want 1", created)
	}
	if edited != 1 {
		t.Fatalf("expected PR upsert edit, edited PRs = %d, want 1", edited)
	}
	if autoMergeCalls != 2 {
		t.Fatalf("auto-merge calls = %d, want 2", autoMergeCalls)
	}
}

func TestHandleWebhookPushE2E_RunIdempotencyKey(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	cvefixPath := setupFakeCVEFix(t, temp, "README.md")

	fakeAPI := newFakeGitHubAPI(owner, repo)
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	cfg := Config{
		AppID:              1,
		WebhookSecret:      "secret",
		PrivateKeyPEM:      generateTestPrivateKeyPEM(t),
		ListenAddr:         ":0",
		WorkDir:            filepath.Join(temp, "work"),
		CVEFixBinary:       cvefixPath,
		EnablePushAutofix:  true,
		GitHubBaseWebURL:   "file://" + remoteRoot,
		GitHubAPIBaseURL:   server.URL + "/api/v3/",
		GitHubUploadAPIURL: server.URL + "/api/uploads/",
		RunDedupTTL:        time.Hour,
		DeliveryDedupTTL:   24 * time.Hour,
		MaxRiskScore:       30,
	}

	service, err := NewService(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	service.async = false

	payload := []byte(`{
		"deleted":false,
		"ref":"refs/heads/master",
		"after":"abc123",
		"repository":{"name":"demo","full_name":"acme/demo","default_branch":"master","owner":{"login":"acme","name":"Acme"}},
		"sender":{"login":"alice"},
		"installation":{"id":99}
	}`)

	if code := sendWebhook(t, service, "push", payload, cfg.WebhookSecret, "push-1"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}
	if code := sendWebhook(t, service, "push", payload, cfg.WebhookSecret, "push-2"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}

	created, edited, _ := fakeAPI.counts()
	if created != 1 || edited != 0 {
		t.Fatalf("expected single PR creation due to run idempotency, created=%d edited=%d", created, edited)
	}
}

func TestHandleWebhookPushE2EBlockedBySafety(t *testing.T) {
	temp := t.TempDir()
	remoteRoot, owner, repo := setupRemoteRepo(t, temp)
	cvefixPath := setupFakeCVEFix(t, temp, "README.md")

	fakeAPI := newFakeGitHubAPI(owner, repo)
	server := httptest.NewServer(fakeAPI)
	defer server.Close()

	cfg := Config{
		AppID:              1,
		WebhookSecret:      "secret",
		PrivateKeyPEM:      generateTestPrivateKeyPEM(t),
		ListenAddr:         ":0",
		WorkDir:            filepath.Join(temp, "work"),
		CVEFixBinary:       cvefixPath,
		EnablePushAutofix:  true,
		GitHubBaseWebURL:   "file://" + remoteRoot,
		GitHubAPIBaseURL:   server.URL + "/api/v3/",
		GitHubUploadAPIURL: server.URL + "/api/uploads/",
		DisallowedPaths:    []string{"README.md"},
		DeliveryDedupTTL:   24 * time.Hour,
		MaxRiskScore:       30,
	}

	service, err := NewService(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	service.async = false

	payload := []byte(`{
		"deleted":false,
		"ref":"refs/heads/master",
		"repository":{"name":"demo","full_name":"acme/demo","default_branch":"master","owner":{"login":"acme","name":"Acme"}},
		"sender":{"login":"alice"},
		"installation":{"id":99}
	}`)

	if code := sendWebhook(t, service, "push", payload, cfg.WebhookSecret, "push-1"); code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", code, http.StatusAccepted)
	}

	created, _, _ := fakeAPI.counts()
	if created != 0 {
		t.Fatalf("expected no PRs due to safety gate, created=%d", created)
	}
}

func sendWebhook(t *testing.T, service *Service, event string, payload []byte, secret, deliveryID string) int {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	request.Header.Set("X-GitHub-Event", event)
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	request.Header.Set("X-Hub-Signature-256", signedPayload(secret, payload))
	request.Header.Set("X-Hub-Signature", signedPayloadSHA1(secret, payload))
	request.Header.Set("Content-Type", "application/json")

	writer := httptest.NewRecorder()
	service.HandleWebhook(writer, request)
	return writer.Code
}

func signedPayload(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func signedPayloadSHA1(secret string, payload []byte) string {
	mac := hmac.New(sha1.New, []byte(secret))
	_, _ = mac.Write(payload)
	return "sha1=" + hex.EncodeToString(mac.Sum(nil))
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

func setupFakeCVEFix(t *testing.T, root, targetFile string) string {
	t.Helper()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	path := filepath.Join(binDir, "cvefix")
	script := "#!/bin/sh\nset -eu\n" +
		"dir=\"\"\n" +
		"while [ \"$#\" -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --dir) dir=\"$2\"; shift 2 ;;\n" +
		"    *) shift ;;\n" +
		"  esac\n" +
		"done\n" +
		"echo \"patched $(date +%s)\" >> \"$dir/" + targetFile + "\"\n" +
		"mkdir -p \"$dir/.cvefix\"\n" +
		"cat <<'EOF' > \"$dir/.cvefix/summary.json\"\n" +
		"{\"before\":1,\"fixed\":1,\"after\":0}\n" +
		"EOF\n" +
		"cat <<'EOF' > \"$dir/.cvefix/verification.json\"\n" +
		"{\"mode\":\"standard\",\"modules\":[],\"regressions\":[]}\n" +
		"EOF\n" +
		"exit 0\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake cvefix: %v", err)
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

type fakeGitHubAPI struct {
	mu sync.Mutex

	owner string
	repo  string

	createdPRs     int
	editedPRs      int
	autoMergeCalls int
	comments       []string
	prs            map[int]fakePR
	nextPRNumber   int
}

type fakePR struct {
	Number  int
	Title   string
	Head    string
	Base    string
	Body    string
	NodeID  string
	HTMLURL string
	State   string
}

func newFakeGitHubAPI(owner, repo string) *fakeGitHubAPI {
	return &fakeGitHubAPI{
		owner:        owner,
		repo:         repo,
		prs:          map[int]fakePR{},
		nextPRNumber: 1,
	}
}

func (api *fakeGitHubAPI) counts() (int, int, int) {
	api.mu.Lock()
	defer api.mu.Unlock()
	return api.createdPRs, api.editedPRs, api.autoMergeCalls
}

func (api *fakeGitHubAPI) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	path := request.URL.Path

	if request.Method == http.MethodPost && strings.HasPrefix(path, "/api/v3/app/installations/") && strings.HasSuffix(path, "/access_tokens") {
		writeJSON(writer, map[string]interface{}{"token": "fake-installation-token"})
		return
	}

	basePullsPath := "/api/v3/repos/" + api.owner + "/" + api.repo + "/pulls"
	if path == basePullsPath && request.Method == http.MethodGet {
		api.mu.Lock()
		defer api.mu.Unlock()
		response := make([]map[string]interface{}, 0, len(api.prs))
		for _, pr := range api.prs {
			if pr.State != "open" {
				continue
			}
			response = append(response, map[string]interface{}{
				"number":   pr.Number,
				"title":    pr.Title,
				"body":     pr.Body,
				"html_url": pr.HTMLURL,
				"node_id":  pr.NodeID,
				"head": map[string]interface{}{
					"ref": pr.Head,
				},
				"base": map[string]interface{}{
					"ref": pr.Base,
				},
			})
		}
		writeJSON(writer, response)
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
		pr := fakePR{
			Number:  prNumber,
			Title:   payload.Title,
			Head:    payload.Head,
			Base:    payload.Base,
			Body:    payload.Body,
			NodeID:  "PR_node_" + strconv.Itoa(prNumber),
			HTMLURL: "https://example.com/" + api.owner + "/" + api.repo + "/pull/" + strconv.Itoa(prNumber),
			State:   "open",
		}
		api.prs[prNumber] = pr
		api.createdPRs++
		api.mu.Unlock()

		writeJSON(writer, map[string]interface{}{
			"number":   pr.Number,
			"title":    pr.Title,
			"body":     pr.Body,
			"html_url": pr.HTMLURL,
			"node_id":  pr.NodeID,
			"head": map[string]interface{}{
				"ref": pr.Head,
			},
			"base": map[string]interface{}{
				"ref": pr.Base,
			},
		})
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
		api.prs[number] = pr
		api.editedPRs++
		api.mu.Unlock()

		writeJSON(writer, map[string]interface{}{
			"number":   pr.Number,
			"title":    pr.Title,
			"body":     pr.Body,
			"html_url": pr.HTMLURL,
			"node_id":  pr.NodeID,
			"head": map[string]interface{}{
				"ref": pr.Head,
			},
			"base": map[string]interface{}{
				"ref": pr.Base,
			},
		})
		return
	}

	issueCommentPath := "/api/v3/repos/" + api.owner + "/" + api.repo + "/issues/1/comments"
	if path == issueCommentPath && request.Method == http.MethodPost {
		var payload struct {
			Body string `json:"body"`
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		api.mu.Lock()
		api.comments = append(api.comments, payload.Body)
		api.mu.Unlock()
		writeJSON(writer, map[string]interface{}{"id": 1, "body": payload.Body})
		return
	}

	if path == "/api/graphql" && request.Method == http.MethodPost {
		api.mu.Lock()
		api.autoMergeCalls++
		api.mu.Unlock()
		writeJSON(writer, map[string]interface{}{
			"data": map[string]interface{}{
				"enablePullRequestAutoMerge": map[string]interface{}{
					"pullRequest": map[string]interface{}{
						"id": "ok",
					},
				},
			},
		})
		return
	}

	http.Error(writer, "not found", http.StatusNotFound)
}

func writeJSON(writer http.ResponseWriter, payload interface{}) {
	writer.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(writer).Encode(payload)
}
