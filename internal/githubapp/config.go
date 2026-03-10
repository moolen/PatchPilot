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
	AppID               int64
	PrivateKeyPath      string
	PrivateKeyPEM       string
	ListenAddr          string
	WorkDir             string
	PatchPilotBinary    string
	JobRunner           string
	JobContainerRuntime string
	JobContainerImage   string
	JobContainerBinary  string
	JobContainerNetwork string
	GitHubBaseWebURL    string
	GitHubAPIBaseURL    string
	GitHubUploadAPIURL  string
	EnableAutoMerge     bool
	DisallowedPaths     []string
	MetricsPath         string
	SchedulerTick       time.Duration
	RepoRunTimeout      time.Duration
	RetryMaxAttempts    int
	RetryInitialBackoff time.Duration
	RetryMaxBackoff     time.Duration
}

func LoadConfigFromEnv() (Config, error) {
	schedulerTick, err := parseDurationWithDefault("PP_SCHEDULER_TICK", time.Hour)
	if err != nil {
		return Config{}, err
	}
	repoRunTimeout, err := parseDurationWithDefault("PP_REPO_RUN_TIMEOUT", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	retryMaxAttempts, err := parseIntWithDefault("PP_GITHUB_RETRY_MAX_ATTEMPTS", 5)
	if err != nil {
		return Config{}, err
	}
	if retryMaxAttempts <= 0 {
		return Config{}, fmt.Errorf("PP_GITHUB_RETRY_MAX_ATTEMPTS must be >= 1")
	}
	retryInitialBackoff, err := parseDurationWithDefault("PP_GITHUB_RETRY_INITIAL_BACKOFF", 2*time.Second)
	if err != nil {
		return Config{}, err
	}
	retryMaxBackoff, err := parseDurationWithDefault("PP_GITHUB_RETRY_MAX_BACKOFF", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	if retryMaxBackoff < retryInitialBackoff {
		return Config{}, fmt.Errorf("PP_GITHUB_RETRY_MAX_BACKOFF must be >= PP_GITHUB_RETRY_INITIAL_BACKOFF")
	}

	cfg := Config{
		ListenAddr:          firstNonEmpty(strings.TrimSpace(os.Getenv("PP_LISTEN_ADDR")), ":8080"),
		WorkDir:             firstNonEmpty(strings.TrimSpace(os.Getenv("PP_WORKDIR")), filepath.Join(os.TempDir(), "patchpilot-app")),
		PatchPilotBinary:    firstNonEmpty(strings.TrimSpace(os.Getenv("PP_PATCHPILOT_BINARY")), "patchpilot"),
		JobRunner:           firstNonEmpty(strings.TrimSpace(os.Getenv("PP_JOB_RUNNER")), "local"),
		JobContainerRuntime: firstNonEmpty(strings.TrimSpace(os.Getenv("PP_JOB_CONTAINER_RUNTIME")), "docker"),
		JobContainerImage:   strings.TrimSpace(os.Getenv("PP_JOB_CONTAINER_IMAGE")),
		JobContainerBinary:  firstNonEmpty(strings.TrimSpace(os.Getenv("PP_JOB_CONTAINER_BINARY")), "patchpilot"),
		JobContainerNetwork: firstNonEmpty(strings.TrimSpace(os.Getenv("PP_JOB_CONTAINER_NETWORK")), "bridge"),
		GitHubBaseWebURL:    firstNonEmpty(strings.TrimSpace(os.Getenv("PP_GITHUB_WEB_BASE_URL")), "https://github.com"),
		EnableAutoMerge:     parseBoolWithDefault("PP_ENABLE_AUTO_MERGE", false),
		DisallowedPaths:     parseCSVList(os.Getenv("PP_DISALLOWED_PATHS")),
		MetricsPath:         firstNonEmpty(strings.TrimSpace(os.Getenv("PP_METRICS_PATH")), "/metrics"),
		SchedulerTick:       schedulerTick,
		RepoRunTimeout:      repoRunTimeout,
		RetryMaxAttempts:    retryMaxAttempts,
		RetryInitialBackoff: retryInitialBackoff,
		RetryMaxBackoff:     retryMaxBackoff,
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

	cfg.PrivateKeyPath = strings.TrimSpace(os.Getenv("PP_PRIVATE_KEY_PATH"))
	cfg.PrivateKeyPEM = strings.TrimSpace(os.Getenv("PP_PRIVATE_KEY_PEM"))
	if cfg.PrivateKeyPath == "" && cfg.PrivateKeyPEM == "" {
		return Config{}, fmt.Errorf("PP_PRIVATE_KEY_PATH or PP_PRIVATE_KEY_PEM is required")
	}
	if cfg.PrivateKeyPath != "" {
		cfg.PrivateKeyPath = filepath.Clean(cfg.PrivateKeyPath)
	}

	cfg.GitHubAPIBaseURL = strings.TrimSpace(os.Getenv("PP_GITHUB_API_BASE_URL"))
	cfg.GitHubUploadAPIURL = strings.TrimSpace(os.Getenv("PP_GITHUB_UPLOAD_API_URL"))
	if (cfg.GitHubAPIBaseURL == "") != (cfg.GitHubUploadAPIURL == "") {
		return Config{}, fmt.Errorf("PP_GITHUB_API_BASE_URL and PP_GITHUB_UPLOAD_API_URL must be set together")
	}
	cfg.JobRunner = strings.ToLower(strings.TrimSpace(cfg.JobRunner))
	switch cfg.JobRunner {
	case "", "local":
		cfg.JobRunner = "local"
	case "container":
		if cfg.JobContainerImage == "" {
			return Config{}, fmt.Errorf("PP_JOB_CONTAINER_IMAGE is required when PP_JOB_RUNNER=container")
		}
	default:
		return Config{}, fmt.Errorf("PP_JOB_RUNNER must be one of: local, container")
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
