package githubapp

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v75/github"
	"golang.org/x/oauth2"
)

type Service struct {
	cfg           Config
	logger        *log.Logger
	webhookSecret []byte
	appClient     *github.Client
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

	appClient := github.NewClient(&http.Client{Transport: transport})

	if err := os.MkdirAll(cfg.WorkDir, 0o755); err != nil {
		return nil, fmt.Errorf("create workdir: %w", err)
	}

	return &Service{
		cfg:           cfg,
		logger:        logger,
		webhookSecret: []byte(cfg.WebhookSecret),
		appClient:     appClient,
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

	switch typed := event.(type) {
	case *github.IssueCommentEvent:
		service.handleIssueCommentEvent(typed)
	case *github.PushEvent:
		service.handlePushEvent(typed)
	default:
		service.logger.Printf("ignored event type %T", typed)
	}

	writer.WriteHeader(http.StatusAccepted)
}

func (service *Service) handleIssueCommentEvent(event *github.IssueCommentEvent) {
	if event.GetAction() != "created" {
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
		service.logger.Printf("invalid slash command: %v", err)
		return
	}
	if !found {
		return
	}

	if !service.repoAllowed(event.GetRepo().GetFullName()) {
		service.logger.Printf("repo %s not allowed by policy", event.GetRepo().GetFullName())
		return
	}

	installationID := event.GetInstallation().GetID()
	if installationID == 0 {
		service.logger.Printf("missing installation ID for issue comment event")
		return
	}

	go service.runAsync("issue_comment", func() {
		service.processIssueComment(event, installationID, command)
	})
}

func (service *Service) handlePushEvent(event *github.PushEvent) {
	if !service.cfg.EnablePushAutofix {
		return
	}
	if event.GetDeleted() {
		return
	}
	if strings.Contains(strings.ToLower(event.GetSender().GetLogin()), "bot") {
		return
	}
	if !service.repoAllowed(event.GetRepo().GetFullName()) {
		return
	}

	defaultBranch := strings.TrimSpace(event.GetRepo().GetDefaultBranch())
	if defaultBranch == "" {
		return
	}
	ref := strings.TrimPrefix(event.GetRef(), "refs/heads/")
	if ref != defaultBranch {
		return
	}

	installationID := event.GetInstallation().GetID()
	if installationID == 0 {
		service.logger.Printf("missing installation ID for push event")
		return
	}

	go service.runAsync("push", func() {
		service.processPushEvent(event, installationID)
	})
}

func (service *Service) runAsync(label string, fn func()) {
	defer func() {
		if recovered := recover(); recovered != nil {
			service.logger.Printf("panic in async %s handler: %v", label, recovered)
		}
	}()
	fn()
}

func (service *Service) installationClient(ctx context.Context, installationID int64) (*github.Client, string, error) {
	tokenResp, _, err := service.appClient.Apps.CreateInstallationToken(ctx, installationID, &github.InstallationTokenOptions{})
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

func timeoutContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, 20*time.Minute)
}
