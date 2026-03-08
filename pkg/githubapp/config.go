package githubapp

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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
	EnableAutoMerge    bool
	DeliveryDedupTTL   time.Duration
	MaxRiskScore       int
	DisallowedPaths    []string
	MetricsPath        string
}

func LoadConfigFromEnv() (Config, error) {
	deliveryTTL, err := parseDurationWithDefault("PP_DELIVERY_DEDUP_TTL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}
	maxRiskScore, err := parseIntWithDefault("PP_MAX_RISK_SCORE", 25)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		ListenAddr:        firstNonEmpty(strings.TrimSpace(os.Getenv("PP_LISTEN_ADDR")), ":8080"),
		WorkDir:           firstNonEmpty(strings.TrimSpace(os.Getenv("PP_WORKDIR")), filepath.Join(os.TempDir(), "patchpilot-app")),
		CVEFixBinary:      firstNonEmpty(strings.TrimSpace(os.Getenv("PP_CVEFIX_BINARY")), "cvefix"),
		EnablePushAutofix: parseBoolEnv("PP_ENABLE_PUSH_AUTOFIX"),
		GitHubBaseWebURL:  firstNonEmpty(strings.TrimSpace(os.Getenv("PP_GITHUB_WEB_BASE_URL")), "https://github.com"),
		EnableAutoMerge:   parseBoolWithDefault("PP_ENABLE_AUTO_MERGE", true),
		DeliveryDedupTTL:  deliveryTTL,
		MaxRiskScore:      maxRiskScore,
		DisallowedPaths:   parseCSVList(os.Getenv("PP_DISALLOWED_PATHS")),
		MetricsPath:       firstNonEmpty(strings.TrimSpace(os.Getenv("PP_METRICS_PATH")), "/metrics"),
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

func parseCSVList(input string) []string {
	input = strings.TrimSpace(input)
	if input == "" {
		return nil
	}
	items := make([]string, 0)
	for _, item := range strings.Split(input, ",") {
		value := strings.TrimSpace(item)
		if value == "" {
			continue
		}
		items = append(items, value)
	}
	return items
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

func parseBoolWithDefault(key string, defaultValue bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return parseBoolEnv(key)
}

func parseIntWithDefault(key string, defaultValue int) (int, error) {
	text := strings.TrimSpace(os.Getenv(key))
	if text == "" {
		return defaultValue, nil
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must be >= 0", key)
	}
	return value, nil
}

func parseDurationWithDefault(key string, defaultValue time.Duration) (time.Duration, error) {
	text := strings.TrimSpace(os.Getenv(key))
	if text == "" {
		return defaultValue, nil
	}
	value, err := time.ParseDuration(text)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid duration: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s must be > 0", key)
	}
	return value, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
