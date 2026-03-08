package githubapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	AppID              int64
	WebhookSecret      string
	PrivateKeyPath     string
	PrivateKeyPEM      string
	ListenAddr         string
	WorkDir            string
	CVEFixBinary       string
	EnablePushAutofix  bool
	AllowedRepos       map[string]struct{}
	GitHubBaseWebURL   string
	GitHubAPIBaseURL   string
	GitHubUploadAPIURL string
}

func LoadConfigFromEnv() (Config, error) {
	cfg := Config{
		ListenAddr:        firstNonEmpty(strings.TrimSpace(os.Getenv("PP_LISTEN_ADDR")), ":8080"),
		WorkDir:           firstNonEmpty(strings.TrimSpace(os.Getenv("PP_WORKDIR")), filepath.Join(os.TempDir(), "patchpilot-app")),
		CVEFixBinary:      firstNonEmpty(strings.TrimSpace(os.Getenv("PP_CVEFIX_BINARY")), "cvefix"),
		EnablePushAutofix: parseBoolEnv("PP_ENABLE_PUSH_AUTOFIX"),
		GitHubBaseWebURL:  firstNonEmpty(strings.TrimSpace(os.Getenv("PP_GITHUB_WEB_BASE_URL")), "https://github.com"),
	}

	appIDText := strings.TrimSpace(os.Getenv("PP_APP_ID"))
	if appIDText == "" {
		return Config{}, fmt.Errorf("PP_APP_ID is required")
	}
	appID, err := strconv.ParseInt(appIDText, 10, 64)
	if err != nil || appID <= 0 {
		return Config{}, fmt.Errorf("PP_APP_ID must be a positive integer")
	}
	cfg.AppID = appID

	cfg.WebhookSecret = strings.TrimSpace(os.Getenv("PP_WEBHOOK_SECRET"))
	if cfg.WebhookSecret == "" {
		return Config{}, fmt.Errorf("PP_WEBHOOK_SECRET is required")
	}

	cfg.PrivateKeyPath = strings.TrimSpace(os.Getenv("PP_PRIVATE_KEY_PATH"))
	cfg.PrivateKeyPEM = strings.TrimSpace(os.Getenv("PP_PRIVATE_KEY_PEM"))
	if cfg.PrivateKeyPath == "" && cfg.PrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("PP_PRIVATE_KEY_PATH or PP_PRIVATE_KEY_PEM is required")
	}
	if cfg.PrivateKeyPath != "" {
		cfg.PrivateKeyPath = filepath.Clean(cfg.PrivateKeyPath)
	}

	cfg.AllowedRepos = parseAllowedRepos(os.Getenv("PP_ALLOWED_REPOS"))

	cfg.GitHubAPIBaseURL = strings.TrimSpace(os.Getenv("PP_GITHUB_API_BASE_URL"))
	cfg.GitHubUploadAPIURL = strings.TrimSpace(os.Getenv("PP_GITHUB_UPLOAD_API_URL"))
	if (cfg.GitHubAPIBaseURL == "") != (cfg.GitHubUploadAPIURL == "") {
		return Config{}, fmt.Errorf("PP_GITHUB_API_BASE_URL and PP_GITHUB_UPLOAD_API_URL must be set together")
	}

	return cfg, nil
}

func parseAllowedRepos(input string) map[string]struct{} {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	allowed := map[string]struct{}{}
	for _, item := range strings.Split(input, ",") {
		repo := normalizeRepoName(item)
		if repo == "" {
			continue
		}
		allowed[repo] = struct{}{}
	}
	if len(allowed) == 0 {
		return nil
	}
	return allowed
}

func normalizeRepoName(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return ""
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func parseBoolEnv(key string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
