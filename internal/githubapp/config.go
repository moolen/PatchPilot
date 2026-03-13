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
	AuthMode                       string
	AppID                          int64
	PrivateKeyPath                 string
	PrivateKeyPEM                  string
	GitHubToken                    string
	GitHubTokenRepositories        []string
	ListenAddr                     string
	WorkDir                        string
	PatchPilotBinary               string
	AgentCommand                   string
	RuntimeConfigPath              string
	JobRunner                      string
	JobContainerRuntime            string
	JobContainerImage              string
	JobContainerBinary             string
	JobContainerNetwork            string
	GitHubBaseWebURL               string
	GitHubAPIBaseURL               string
	GitHubUploadAPIURL             string
	EnableAutoMerge                bool
	RequirePolicyFile              bool
	ForceReconcileOnStart          bool
	DisallowedPaths                []string
	RepositoryLabelSelectors       []string
	RepositoryIgnoreLabelSelectors []string
	MetricsPath                    string
	SchedulerTick                  time.Duration
	RepoRunTimeout                 time.Duration
	PRStatusPollInterval           time.Duration
	RetryMaxAttempts               int
	RetryInitialBackoff            time.Duration
	RetryMaxBackoff                time.Duration
}

const (
	AuthModeAuto  = "auto"
	AuthModeApp   = "app"
	AuthModeToken = "token"

	defaultAgentCommand = "codex exec --skip-git-repo-check --sandbox workspace-write -o \"$PATCHPILOT_AGENT_ARTIFACT_DIR/last-message.txt\" - < \"$PATCHPILOT_PROMPT_FILE\""
)

func LoadConfigFromEnv() (Config, error) {
	return LoadConfigFromEnvWithOverrides(nil)
}

func LoadConfigFromEnvWithOverrides(overrides map[string]string) (Config, error) {
	lookup := func(key string) string {
		if overrides != nil {
			if value, exists := overrides[key]; exists {
				return value
			}
		}
		return os.Getenv(key)
	}

	schedulerTick, err := parseDurationWithDefault(lookup, "PP_SCHEDULER_TICK", time.Hour)
	if err != nil {
		return Config{}, err
	}
	repoRunTimeout, err := parseDurationWithDefault(lookup, "PP_REPO_RUN_TIMEOUT", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}
	prStatusPollInterval, err := parseDurationWithDefault(lookup, "PP_PR_STATUS_POLL_INTERVAL", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	retryMaxAttempts, err := parseIntWithDefault(lookup, "PP_GITHUB_RETRY_MAX_ATTEMPTS", 5)
	if err != nil {
		return Config{}, err
	}
	if retryMaxAttempts <= 0 {
		return Config{}, fmt.Errorf("PP_GITHUB_RETRY_MAX_ATTEMPTS must be >= 1")
	}
	retryInitialBackoff, err := parseDurationWithDefault(lookup, "PP_GITHUB_RETRY_INITIAL_BACKOFF", 2*time.Second)
	if err != nil {
		return Config{}, err
	}
	retryMaxBackoff, err := parseDurationWithDefault(lookup, "PP_GITHUB_RETRY_MAX_BACKOFF", 30*time.Second)
	if err != nil {
		return Config{}, err
	}
	if retryMaxBackoff < retryInitialBackoff {
		return Config{}, fmt.Errorf("PP_GITHUB_RETRY_MAX_BACKOFF must be >= PP_GITHUB_RETRY_INITIAL_BACKOFF")
	}

	cfg := Config{
		AuthMode:                       firstNonEmpty(strings.ToLower(strings.TrimSpace(lookup("PP_GITHUB_AUTH_MODE"))), AuthModeAuto),
		ListenAddr:                     firstNonEmpty(strings.TrimSpace(lookup("PP_LISTEN_ADDR")), ":8080"),
		WorkDir:                        firstNonEmpty(strings.TrimSpace(lookup("PP_WORKDIR")), filepath.Join(os.TempDir(), "patchpilot-app")),
		PatchPilotBinary:               firstNonEmpty(strings.TrimSpace(lookup("PP_PATCHPILOT_BINARY")), "patchpilot"),
		AgentCommand:                   firstNonEmpty(strings.TrimSpace(lookup("PP_AGENT_COMMAND")), defaultAgentCommand),
		RuntimeConfigPath:              firstNonEmpty(strings.TrimSpace(lookup("PP_GITHUB_APP_CONFIG_FILE")), strings.TrimSpace(lookup("PP_OCI_MAPPING_FILE"))),
		JobRunner:                      firstNonEmpty(strings.TrimSpace(lookup("PP_JOB_RUNNER")), "local"),
		JobContainerRuntime:            firstNonEmpty(strings.TrimSpace(lookup("PP_JOB_CONTAINER_RUNTIME")), "docker"),
		JobContainerImage:              strings.TrimSpace(lookup("PP_JOB_CONTAINER_IMAGE")),
		JobContainerBinary:             firstNonEmpty(strings.TrimSpace(lookup("PP_JOB_CONTAINER_BINARY")), "patchpilot"),
		JobContainerNetwork:            firstNonEmpty(strings.TrimSpace(lookup("PP_JOB_CONTAINER_NETWORK")), "bridge"),
		GitHubBaseWebURL:               firstNonEmpty(strings.TrimSpace(lookup("PP_GITHUB_WEB_BASE_URL")), "https://github.com"),
		EnableAutoMerge:                parseBoolWithDefault(lookup, "PP_ENABLE_AUTO_MERGE", false),
		ForceReconcileOnStart:          parseBoolWithDefault(lookup, "PP_FORCE_RECONCILE_ON_START", false),
		DisallowedPaths:                parseCSVList(lookup("PP_DISALLOWED_PATHS")),
		RepositoryLabelSelectors:       parseLabelSelectors(lookup("PP_REPOSITORY_LABEL_SELECTOR")),
		RepositoryIgnoreLabelSelectors: parseLabelSelectors(lookup("PP_REPOSITORY_IGNORE_LABEL_SELECTOR")),
		MetricsPath:                    firstNonEmpty(strings.TrimSpace(lookup("PP_METRICS_PATH")), "/metrics"),
		SchedulerTick:                  schedulerTick,
		RepoRunTimeout:                 repoRunTimeout,
		PRStatusPollInterval:           prStatusPollInterval,
		RetryMaxAttempts:               retryMaxAttempts,
		RetryInitialBackoff:            retryInitialBackoff,
		RetryMaxBackoff:                retryMaxBackoff,
	}

	appIDText := strings.TrimSpace(lookup("PP_APP_ID"))
	privateKeyPath := strings.TrimSpace(lookup("PP_PRIVATE_KEY_PATH"))
	privateKeyPEM := strings.TrimSpace(lookup("PP_PRIVATE_KEY_PEM"))

	cfg.GitHubToken = strings.TrimSpace(lookup("PP_GITHUB_TOKEN"))
	cfg.GitHubTokenRepositories = parseRepositoryAllowlist(lookup("PP_GITHUB_TOKEN_REPOSITORIES"))
	switch cfg.AuthMode {
	case "", AuthModeAuto:
		cfg.AuthMode = deriveAuthMode(cfg, appIDText, privateKeyPath, privateKeyPEM)
	case AuthModeApp, AuthModeToken:
	default:
		return Config{}, fmt.Errorf("PP_GITHUB_AUTH_MODE must be one of: %s, %s, %s", AuthModeAuto, AuthModeApp, AuthModeToken)
	}
	if err := validateAuthConfig(&cfg, appIDText, privateKeyPath, privateKeyPEM); err != nil {
		return Config{}, err
	}
	if cfg.RuntimeConfigPath != "" {
		cfg.RuntimeConfigPath = filepath.Clean(cfg.RuntimeConfigPath)
	}

	cfg.GitHubAPIBaseURL = strings.TrimSpace(lookup("PP_GITHUB_API_BASE_URL"))
	cfg.GitHubUploadAPIURL = strings.TrimSpace(lookup("PP_GITHUB_UPLOAD_API_URL"))
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

func deriveAuthMode(cfg Config, appIDText, privateKeyPath, privateKeyPEM string) string {
	switch {
	case strings.TrimSpace(cfg.GitHubToken) != "":
		return AuthModeToken
	case appIDText != "" || privateKeyPath != "" || privateKeyPEM != "":
		return AuthModeApp
	default:
		return AuthModeApp
	}
}

func validateAuthConfig(cfg *Config, appIDText, privateKeyPath, privateKeyPEM string) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	cfg.PrivateKeyPath = strings.TrimSpace(privateKeyPath)
	cfg.PrivateKeyPEM = strings.TrimSpace(privateKeyPEM)
	if cfg.PrivateKeyPath != "" {
		cfg.PrivateKeyPath = filepath.Clean(cfg.PrivateKeyPath)
	}

	switch cfg.AuthMode {
	case AuthModeApp:
		if appIDText == "" {
			return fmt.Errorf("PP_APP_ID is required when PP_GITHUB_AUTH_MODE=%s", AuthModeApp)
		}
		appID, err := strconv.ParseInt(appIDText, 10, 64)
		if err != nil || appID <= 0 {
			return fmt.Errorf("PP_APP_ID must be a positive integer")
		}
		cfg.AppID = appID
		if cfg.PrivateKeyPath == "" && cfg.PrivateKeyPEM == "" {
			return fmt.Errorf("PP_PRIVATE_KEY_PATH or PP_PRIVATE_KEY_PEM is required when PP_GITHUB_AUTH_MODE=%s", AuthModeApp)
		}
	case AuthModeToken:
		if strings.TrimSpace(cfg.GitHubToken) == "" {
			return fmt.Errorf("PP_GITHUB_TOKEN is required when PP_GITHUB_AUTH_MODE=%s", AuthModeToken)
		}
		if len(cfg.GitHubTokenRepositories) == 0 {
			return fmt.Errorf("PP_GITHUB_TOKEN_REPOSITORIES is required when PP_GITHUB_AUTH_MODE=%s", AuthModeToken)
		}
		if appIDText != "" || cfg.PrivateKeyPath != "" || cfg.PrivateKeyPEM != "" {
			return fmt.Errorf("PP_APP_ID and PP_PRIVATE_KEY_* must not be set when PP_GITHUB_AUTH_MODE=%s", AuthModeToken)
		}
	default:
		return fmt.Errorf("unsupported auth mode %q", cfg.AuthMode)
	}
	return nil
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

func parseLabelSelectors(input string) []string {
	values := parseCSVList(input)
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	selectors := make([]string, 0, len(values))
	for _, value := range values {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		selectors = append(selectors, normalized)
	}
	if len(selectors) == 0 {
		return nil
	}
	return selectors
}

func parseRepositoryAllowlist(input string) []string {
	values := parseCSVList(input)
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		normalized := normalizeRepoName(value)
		if normalized == "" {
			continue
		}
		if _, exists := seen[normalized]; exists {
			continue
		}
		seen[normalized] = struct{}{}
		result = append(result, normalized)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

func parseBool(text string) bool {
	value := strings.ToLower(strings.TrimSpace(text))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func parseBoolWithDefault(lookup func(string) string, key string, defaultValue bool) bool {
	value := strings.TrimSpace(lookup(key))
	if value == "" {
		return defaultValue
	}
	return parseBool(value)
}

func parseIntWithDefault(lookup func(string) string, key string, defaultValue int) (int, error) {
	text := strings.TrimSpace(lookup(key))
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

func parseDurationWithDefault(lookup func(string) string, key string, defaultValue time.Duration) (time.Duration, error) {
	text := strings.TrimSpace(lookup(key))
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
