package githubapp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v75/github"
	"golang.org/x/oauth2"
)

type Service struct {
	cfg           Config
	logger        *log.Logger
	slog          *structuredLogger
	webhookSecret []byte
	appClient     *github.Client
	deliveryStore DeliveryStore
	runStore      DeliveryStore
	metrics       *Metrics
	async         bool
}

func NewService(cfg Config, logger *log.Logger) (*Service, error) {
	if logger == nil {
		logger = log.New(os.Stderr, "[patchpilot-app] ", log.LstdFlags)
	}

	privateKey, err := loadPrivateKey(cfg)
	if err != nil {
		return nil, err
	}

	transport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, cfg.AppID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create app transport: %w", err)
	}

	httpClient := &http.Client{Transport: transport}
	appClient := github.NewClient(httpClient)
	if cfg.GitHubAPIBaseURL != "" {
		appClient, err = github.NewEnterpriseClient(cfg.GitHubAPIBaseURL, cfg.GitHubUploadAPIURL, httpClient)
		if err != nil {
			return nil, fmt.Errorf("create app enterprise client: %w", err)
		}
	}

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}

	deliveryStore := NewFileDeliveryStore(filepath.Join(cfg.WorkDir, "deliveries.json"), cfg.DeliveryDedupTTL)
	runStore := NewFileDeliveryStore(filepath.Join(cfg.WorkDir, "run-keys.json"), cfg.RunDedupTTL)
	metrics := NewMetrics()

	return &Service{
		cfg:           cfg,
		logger:        logger,
		slog:          newStructuredLogger(logger),
		webhookSecret: []byte(cfg.WebhookSecret),
		appClient:     appClient,
		deliveryStore: deliveryStore,
		runStore:      runStore,
		metrics:       metrics,
		async:         true,
	}, nil
}

func (service *Service) HandleWebhook(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		http.Error(writer, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload, err := github.ValidatePayload(request, service.webhookSecret)
	if err != nil {
		http.Error(writer, "invalid webhook payload", http.StatusUnauthorized)
		return
	}

	event, err := github.ParseWebHook(github.WebHookType(request), payload)
	if err != nil {
		http.Error(writer, "unsupported webhook", http.StatusBadRequest)
		return
	}

	deliveryID := strings.TrimSpace(request.Header.Get("X-GitHub-Delivery"))
	if deliveryID != "" && service.deliveryStore != nil {
		started, err := service.deliveryStore.TryStart(deliveryID)
		if err != nil {
			service.log("error", "delivery dedupe failed", map[string]interface{}{"delivery_id": deliveryID, "error": err.Error()})
			http.Error(writer, "internal dedupe error", http.StatusInternalServerError)
			return
		}
		if !started {
			service.log("info", "skipping duplicate delivery", map[string]interface{}{"delivery_id": deliveryID})
			if service.metrics != nil {
				service.metrics.IncRun("webhook", "duplicate")
			}
			writer.WriteHeader(http.StatusAccepted)
			return
		}
	}

	switch typed := event.(type) {
	case *github.IssueCommentEvent:
		service.handleIssueCommentEvent(deliveryID, typed)
	case *github.PushEvent:
		service.handlePushEvent(deliveryID, typed)
	default:
		service.log("info", "ignored unsupported event", map[string]interface{}{"delivery_id": deliveryID, "event_type": fmt.Sprintf("%T", typed)})
		_ = service.markDeliveryDone(deliveryID)
	}

	writer.WriteHeader(http.StatusAccepted)
}

func (service *Service) handleIssueCommentEvent(deliveryID string, event *github.IssueCommentEvent) {
	if event.GetAction() != "created" {
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	command, found, err := ParseFixCommand(event.GetComment().GetBody())
	if err != nil {
		client, _, clientErr := service.installationClient(context.Background(), event.GetInstallation().GetID())
		if clientErr == nil {
			service.postIssueComment(
				context.Background(),
				client,
				event.GetRepo().GetOwner().GetLogin(),
				event.GetRepo().GetName(),
				event.GetIssue().GetNumber(),
				fmt.Sprintf("Invalid PatchPilot command: %v", err),
			)
		}
		service.log("warn", "invalid slash command", map[string]interface{}{"delivery_id": deliveryID, "error": err.Error()})
		_ = service.markDeliveryDone(deliveryID)
		return
	}
	if !found {
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	if !service.repoAllowed(event.GetRepo().GetFullName()) {
		service.log("warn", "repo not allowed", map[string]interface{}{"delivery_id": deliveryID, "repo": event.GetRepo().GetFullName()})
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	installationID := event.GetInstallation().GetID()
	if installationID == 0 {
		service.log("warn", "missing installation ID", map[string]interface{}{"delivery_id": deliveryID, "event": "issue_comment"})
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	run := func() {
		runKey := issueCommentRunKey(event, command, deliveryID)
		started, err := service.tryStartRun(runKey)
		if err != nil {
			service.log("error", "run idempotency check failed", map[string]interface{}{"delivery_id": deliveryID, "run_key": runKey, "error": err.Error()})
			_ = service.markDeliveryDone(deliveryID)
			return
		}
		if !started {
			service.log("info", "skipping duplicate issue_comment run", map[string]interface{}{"delivery_id": deliveryID, "run_key": runKey})
			if service.metrics != nil {
				service.metrics.IncRun("issue_comment", "duplicate_run")
			}
			_ = service.markDeliveryDone(deliveryID)
			return
		}
		service.runAsync(deliveryID, "issue_comment", runKey, func() {
			service.processIssueComment(event, installationID, command)
		})
	}
	if service.async {
		go run()
	} else {
		run()
	}
}

func (service *Service) handlePushEvent(deliveryID string, event *github.PushEvent) {
	if !service.cfg.EnablePushAutofix {
		_ = service.markDeliveryDone(deliveryID)
		return
	}
	if event.GetDeleted() {
		_ = service.markDeliveryDone(deliveryID)
		return
	}
	if strings.Contains(strings.ToLower(event.GetSender().GetLogin()), "bot") {
		_ = service.markDeliveryDone(deliveryID)
		return
	}
	if !service.repoAllowed(event.GetRepo().GetFullName()) {
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	defaultBranch := strings.TrimSpace(event.GetRepo().GetDefaultBranch())
	if defaultBranch == "" {
		_ = service.markDeliveryDone(deliveryID)
		return
	}
	ref := strings.TrimPrefix(event.GetRef(), "refs/heads/")
	if ref != defaultBranch {
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	installationID := event.GetInstallation().GetID()
	if installationID == 0 {
		service.log("warn", "missing installation ID", map[string]interface{}{"delivery_id": deliveryID, "event": "push"})
		_ = service.markDeliveryDone(deliveryID)
		return
	}

	run := func() {
		runKey := pushRunKey(event, deliveryID)
		started, err := service.tryStartRun(runKey)
		if err != nil {
			service.log("error", "run idempotency check failed", map[string]interface{}{"delivery_id": deliveryID, "run_key": runKey, "error": err.Error()})
			_ = service.markDeliveryDone(deliveryID)
			return
		}
		if !started {
			service.log("info", "skipping duplicate push run", map[string]interface{}{"delivery_id": deliveryID, "run_key": runKey})
			if service.metrics != nil {
				service.metrics.IncRun("push", "duplicate_run")
			}
			_ = service.markDeliveryDone(deliveryID)
			return
		}
		service.runAsync(deliveryID, "push", runKey, func() {
			service.processPushEvent(event, installationID)
		})
	}
	if service.async {
		go run()
	} else {
		run()
	}
}

func (service *Service) runAsync(deliveryID, label, runKey string, fn func()) {
	started := time.Now()
	defer func() {
		if service.metrics != nil {
			service.metrics.ObserveRunDuration(time.Since(started))
		}
		_ = service.markDeliveryDone(deliveryID)
		_ = service.markRunDone(runKey)
	}()
	defer func() {
		if recovered := recover(); recovered != nil {
			if service.metrics != nil {
				service.metrics.IncRun(label, "panic")
				service.metrics.IncFailure(label)
			}
			service.log("error", "panic in async handler", map[string]interface{}{"label": label, "delivery_id": deliveryID, "panic": fmt.Sprintf("%v", recovered)})
		}
	}()
	fn()
	if service.metrics != nil {
		service.metrics.IncRun(label, "completed")
	}
}

func (service *Service) installationClient(ctx context.Context, installationID int64) (*github.Client, string, error) {
	var tokenResp *github.InstallationToken
	err := service.withGitHubRetry(ctx, "create_installation_token", func(callCtx context.Context) error {
		response, _, tokenErr := service.appClient.Apps.CreateInstallationToken(callCtx, installationID, &github.InstallationTokenOptions{})
		if tokenErr != nil {
			return tokenErr
		}
		tokenResp = response
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("create installation token: %w", err)
	}
	token := tokenResp.GetToken()
	if strings.TrimSpace(token) == "" {
		return nil, "", fmt.Errorf("installation token is empty")
	}

	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	if service.cfg.GitHubAPIBaseURL != "" {
		client, err := github.NewEnterpriseClient(service.cfg.GitHubAPIBaseURL, service.cfg.GitHubUploadAPIURL, httpClient)
		if err != nil {
			return nil, "", fmt.Errorf("create enterprise github client: %w", err)
		}
		return client, token, nil
	}

	return github.NewClient(httpClient), token, nil
}

func (service *Service) repoAllowed(repo string) bool {
	if len(service.cfg.AllowedRepos) == 0 {
		return true
	}
	_, ok := service.cfg.AllowedRepos[normalizeRepoName(repo)]
	return ok
}

func (service *Service) log(level, message string, fields map[string]interface{}) {
	if service.slog == nil {
		service.logger.Printf("%s: %s", strings.ToUpper(level), message)
		return
	}
	service.slog.Log(level, message, fields)
}

func (service *Service) markDeliveryDone(deliveryID string) error {
	if strings.TrimSpace(deliveryID) == "" || service.deliveryStore == nil {
		return nil
	}
	return service.deliveryStore.MarkDone(deliveryID)
}

func (service *Service) tryStartRun(runKey string) (bool, error) {
	if strings.TrimSpace(runKey) == "" || service.runStore == nil {
		return true, nil
	}
	return service.runStore.TryStart(runKey)
}

func (service *Service) markRunDone(runKey string) error {
	if strings.TrimSpace(runKey) == "" || service.runStore == nil {
		return nil
	}
	return service.runStore.MarkDone(runKey)
}

func issueCommentRunKey(event *github.IssueCommentEvent, command FixCommand, deliveryID string) string {
	repo := normalizeRepoName(event.GetRepo().GetFullName())
	issue := event.GetIssue().GetNumber()
	commentID := event.GetComment().GetID()
	if commentID > 0 {
		return fmt.Sprintf("issue_comment:%s:%d:%d", repo, issue, commentID)
	}

	hashInput := strings.Join([]string{
		repo,
		fmt.Sprintf("%d", issue),
		strings.TrimSpace(event.GetSender().GetLogin()),
		strings.TrimSpace(event.GetComment().GetBody()),
		strings.TrimSpace(command.PolicyPath),
		fmt.Sprintf("%t", command.AutoMerge),
		strings.TrimSpace(deliveryID),
	}, "|")
	sum := sha256.Sum256([]byte(hashInput))
	return "issue_comment_fallback:" + hex.EncodeToString(sum[:])
}

func pushRunKey(event *github.PushEvent, deliveryID string) string {
	repo := normalizeRepoName(event.GetRepo().GetFullName())
	ref := strings.TrimSpace(event.GetRef())
	after := strings.TrimSpace(event.GetAfter())
	if after == "" {
		after = strings.TrimSpace(deliveryID)
	}
	return fmt.Sprintf("push:%s:%s:%s", repo, ref, after)
}

func (service *Service) MetricsHandler(writer http.ResponseWriter, request *http.Request) {
	if service.metrics == nil {
		http.Error(writer, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	service.metrics.ServeHTTP(writer, request)
}

func loadPrivateKey(cfg Config) ([]byte, error) {
	if strings.TrimSpace(cfg.PrivateKeyPEM) != "" {
		text := strings.ReplaceAll(cfg.PrivateKeyPEM, `\n`, "\n")
		return []byte(text), nil
	}
	if strings.TrimSpace(cfg.PrivateKeyPath) == "" {
		return nil, fmt.Errorf("no private key configured")
	}
	data, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	return data, nil
}
