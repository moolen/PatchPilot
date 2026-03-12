package githubapp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	ghinstallation "github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/google/go-github/v75/github"
	"golang.org/x/oauth2"
)

type repositoryContext struct {
	Client     *github.Client
	Token      string
	Repository *github.Repository
}

func (service *Service) listRepositoryContexts(ctx context.Context) ([]repositoryContext, error) {
	switch service.cfg.AuthMode {
	case AuthModeToken:
		return service.listTokenRepositoryContexts(ctx)
	default:
		return service.listAppRepositoryContexts(ctx)
	}
}

func (service *Service) listAppRepositoryContexts(ctx context.Context) ([]repositoryContext, error) {
	installations, err := service.listInstallations(ctx)
	if err != nil {
		return nil, err
	}
	contexts := make([]repositoryContext, 0)
	for _, installation := range installations {
		installationID := installation.GetID()
		client, token, err := service.installationClient(ctx, installationID)
		if err != nil {
			return nil, fmt.Errorf("installation %d client: %w", installationID, err)
		}
		repositories, err := service.listInstallationRepos(ctx, client)
		if err != nil {
			return nil, fmt.Errorf("installation %d repositories: %w", installationID, err)
		}
		for _, repository := range repositories {
			contexts = append(contexts, repositoryContext{
				Client:     client,
				Token:      token,
				Repository: repository,
			})
		}
	}
	return contexts, nil
}

func (service *Service) listTokenRepositoryContexts(ctx context.Context) ([]repositoryContext, error) {
	client, err := service.tokenClient(ctx, service.cfg.GitHubToken)
	if err != nil {
		return nil, err
	}
	contexts := make([]repositoryContext, 0, len(service.cfg.GitHubTokenRepositories))
	for _, repoKey := range service.cfg.GitHubTokenRepositories {
		owner, repo, ok := strings.Cut(repoKey, "/")
		if !ok || strings.TrimSpace(owner) == "" || strings.TrimSpace(repo) == "" {
			return nil, fmt.Errorf("invalid token repository allowlist entry %q", repoKey)
		}
		var repository *github.Repository
		err := service.withGitHubRetry(ctx, "get_repository", func(callCtx context.Context) error {
			var getErr error
			repository, _, getErr = client.Repositories.Get(callCtx, owner, repo)
			return getErr
		})
		if err != nil {
			return nil, fmt.Errorf("load repository %s: %w", repoKey, err)
		}
		contexts = append(contexts, repositoryContext{
			Client:     client,
			Token:      service.cfg.GitHubToken,
			Repository: repository,
		})
	}
	return contexts, nil
}

func (service *Service) tokenClient(ctx context.Context, token string) (*github.Client, error) {
	if strings.TrimSpace(token) == "" {
		return nil, fmt.Errorf("github token is empty")
	}
	httpClient := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	client := github.NewClient(httpClient)
	if service.cfg.GitHubAPIBaseURL != "" {
		var err error
		client, err = client.WithEnterpriseURLs(service.cfg.GitHubAPIBaseURL, service.cfg.GitHubUploadAPIURL)
		if err != nil {
			return nil, fmt.Errorf("create enterprise github client: %w", err)
		}
	}
	return client, nil
}

func newAppClient(cfg Config) (*github.Client, error) {
	privateKey, err := loadPrivateKey(cfg)
	if err != nil {
		return nil, err
	}
	transport, err := ghinstallation.NewAppsTransport(http.DefaultTransport, cfg.AppID, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create app transport: %w", err)
	}
	httpClient := &http.Client{Transport: transport}
	client := github.NewClient(httpClient)
	if cfg.GitHubAPIBaseURL != "" {
		client, err = client.WithEnterpriseURLs(cfg.GitHubAPIBaseURL, cfg.GitHubUploadAPIURL)
		if err != nil {
			return nil, fmt.Errorf("create app enterprise client: %w", err)
		}
	}
	return client, nil
}
