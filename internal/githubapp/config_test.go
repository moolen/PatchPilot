package githubapp

import "testing"

func TestLoadConfigFromEnvSuccess(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "-----BEGIN\\nKEY-----")
	t.Setenv("PP_SCHEDULER_TICK", "45m")
	t.Setenv("PP_REPO_RUN_TIMEOUT", "35m")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppID != 123 {
		t.Fatalf("AppID = %d, want 123", cfg.AppID)
	}
	if cfg.EnableAutoMerge {
		t.Fatalf("EnableAutoMerge = true, want false by default")
	}
	if cfg.SchedulerTick.String() != "45m0s" {
		t.Fatalf("SchedulerTick = %s, want 45m", cfg.SchedulerTick)
	}
	if cfg.RepoRunTimeout.String() != "35m0s" {
		t.Fatalf("RepoRunTimeout = %s, want 35m", cfg.RepoRunTimeout)
	}
	if cfg.RetryMaxAttempts != 5 {
		t.Fatalf("RetryMaxAttempts = %d, want 5", cfg.RetryMaxAttempts)
	}
	if cfg.RetryInitialBackoff.String() != "2s" {
		t.Fatalf("RetryInitialBackoff = %s, want 2s", cfg.RetryInitialBackoff)
	}
	if cfg.RetryMaxBackoff.String() != "30s" {
		t.Fatalf("RetryMaxBackoff = %s, want 30s", cfg.RetryMaxBackoff)
	}
}

func TestLoadConfigFromEnvRequiresFields(t *testing.T) {
	t.Setenv("PP_APP_ID", "")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error for missing PP_APP_ID")
	}
}

func TestLoadConfigFromEnvRequiresGitHubEnterprisePair(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_GITHUB_API_BASE_URL", "https://ghe.example/api/v3")
	t.Setenv("PP_GITHUB_UPLOAD_API_URL", "")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error when only one enterprise URL is configured")
	}
}

func TestLoadConfigFromEnvParsesSafetyFields(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_DISALLOWED_PATHS", ".github/**, secrets/*.txt")
	t.Setenv("PP_REPOSITORY_LABEL_SELECTOR", "patchpilot, Pilot-* , patchpilot")
	t.Setenv("PP_REPOSITORY_IGNORE_LABEL_SELECTOR", "patchpilot-ignore, no-pp")
	t.Setenv("PP_SCHEDULER_TICK", "2h")
	t.Setenv("PP_REPO_RUN_TIMEOUT", "45m")
	t.Setenv("PP_ENABLE_AUTO_MERGE", "false")
	t.Setenv("PP_GITHUB_RETRY_MAX_ATTEMPTS", "7")
	t.Setenv("PP_GITHUB_RETRY_INITIAL_BACKOFF", "3s")
	t.Setenv("PP_GITHUB_RETRY_MAX_BACKOFF", "20s")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SchedulerTick.String() != "2h0m0s" {
		t.Fatalf("SchedulerTick = %s, want 2h", cfg.SchedulerTick)
	}
	if cfg.RepoRunTimeout.String() != "45m0s" {
		t.Fatalf("RepoRunTimeout = %s, want 45m", cfg.RepoRunTimeout)
	}
	if cfg.RetryMaxAttempts != 7 {
		t.Fatalf("RetryMaxAttempts = %d, want 7", cfg.RetryMaxAttempts)
	}
	if cfg.RetryInitialBackoff.String() != "3s" {
		t.Fatalf("RetryInitialBackoff = %s, want 3s", cfg.RetryInitialBackoff)
	}
	if cfg.RetryMaxBackoff.String() != "20s" {
		t.Fatalf("RetryMaxBackoff = %s, want 20s", cfg.RetryMaxBackoff)
	}
	if cfg.EnableAutoMerge {
		t.Fatalf("EnableAutoMerge = true, want false")
	}
	if len(cfg.DisallowedPaths) != 2 {
		t.Fatalf("DisallowedPaths len = %d, want 2", len(cfg.DisallowedPaths))
	}
	if len(cfg.RepositoryLabelSelectors) != 2 {
		t.Fatalf("RepositoryLabelSelectors len = %d, want 2", len(cfg.RepositoryLabelSelectors))
	}
	if cfg.RepositoryLabelSelectors[0] != "patchpilot" || cfg.RepositoryLabelSelectors[1] != "pilot-*" {
		t.Fatalf("RepositoryLabelSelectors = %#v", cfg.RepositoryLabelSelectors)
	}
	if len(cfg.RepositoryIgnoreLabelSelectors) != 2 {
		t.Fatalf("RepositoryIgnoreLabelSelectors len = %d, want 2", len(cfg.RepositoryIgnoreLabelSelectors))
	}
}

func TestLoadConfigFromEnvRejectsInvalidRetryWindow(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_GITHUB_RETRY_INITIAL_BACKOFF", "10s")
	t.Setenv("PP_GITHUB_RETRY_MAX_BACKOFF", "2s")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected retry window validation error")
	}
}

func TestLoadConfigFromEnvParsesContainerJobRunner(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_JOB_RUNNER", "container")
	t.Setenv("PP_JOB_CONTAINER_RUNTIME", "podman")
	t.Setenv("PP_JOB_CONTAINER_IMAGE", "ghcr.io/moolen/patchpilot-job:latest")
	t.Setenv("PP_JOB_CONTAINER_BINARY", "/usr/local/bin/patchpilot")
	t.Setenv("PP_JOB_CONTAINER_NETWORK", "none")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.JobRunner != "container" {
		t.Fatalf("JobRunner = %q, want container", cfg.JobRunner)
	}
	if cfg.JobContainerRuntime != "podman" {
		t.Fatalf("JobContainerRuntime = %q, want podman", cfg.JobContainerRuntime)
	}
	if cfg.JobContainerImage != "ghcr.io/moolen/patchpilot-job:latest" {
		t.Fatalf("JobContainerImage = %q", cfg.JobContainerImage)
	}
	if cfg.JobContainerBinary != "/usr/local/bin/patchpilot" {
		t.Fatalf("JobContainerBinary = %q", cfg.JobContainerBinary)
	}
	if cfg.JobContainerNetwork != "none" {
		t.Fatalf("JobContainerNetwork = %q", cfg.JobContainerNetwork)
	}
}

func TestLoadConfigFromEnvRequiresContainerImageInContainerMode(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_JOB_RUNNER", "container")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error for missing PP_JOB_CONTAINER_IMAGE")
	}
}
