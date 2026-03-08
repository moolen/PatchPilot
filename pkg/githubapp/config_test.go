package githubapp

import "testing"

func TestLoadConfigFromEnvSuccess(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_WEBHOOK_SECRET", "secret")
	t.Setenv("PP_PRIVATE_KEY_PEM", "-----BEGIN\\nKEY-----")
	t.Setenv("PP_ALLOWED_REPOS", "Org/Repo,other/repo")
	t.Setenv("PP_ENABLE_PUSH_AUTOFIX", "true")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.AppID != 123 {
		t.Fatalf("AppID = %d, want 123", cfg.AppID)
	}
	if !cfg.EnablePushAutofix {
		t.Fatalf("EnablePushAutofix = false, want true")
	}
	if _, ok := cfg.AllowedRepos["org/repo"]; !ok {
		t.Fatalf("expected org/repo in allowed repos")
	}
	if _, ok := cfg.AllowedRepos["other/repo"]; !ok {
		t.Fatalf("expected other/repo in allowed repos")
	}
}

func TestLoadConfigFromEnvRequiresFields(t *testing.T) {
	t.Setenv("PP_APP_ID", "")
	t.Setenv("PP_WEBHOOK_SECRET", "secret")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error for missing PP_APP_ID")
	}
}

func TestLoadConfigFromEnvRequiresGitHubEnterprisePair(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_WEBHOOK_SECRET", "secret")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_GITHUB_API_BASE_URL", "https://ghe.example/api/v3")
	t.Setenv("PP_GITHUB_UPLOAD_API_URL", "")

	if _, err := LoadConfigFromEnv(); err == nil {
		t.Fatalf("expected error when only one enterprise URL is configured")
	}
}
