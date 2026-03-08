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
	if !cfg.EnableAutoMerge {
		t.Fatalf("EnableAutoMerge = false, want true")
	}
	if cfg.MaxRiskScore != 25 {
		t.Fatalf("MaxRiskScore = %d, want 25", cfg.MaxRiskScore)
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

func TestLoadConfigFromEnvParsesSafetyFields(t *testing.T) {
	t.Setenv("PP_APP_ID", "123")
	t.Setenv("PP_WEBHOOK_SECRET", "secret")
	t.Setenv("PP_PRIVATE_KEY_PEM", "pem")
	t.Setenv("PP_DISALLOWED_PATHS", ".github/**, secrets/*.txt")
	t.Setenv("PP_DELIVERY_DEDUP_TTL", "2h")
	t.Setenv("PP_MAX_RISK_SCORE", "7")
	t.Setenv("PP_ENABLE_AUTO_MERGE", "false")

	cfg, err := LoadConfigFromEnv()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DeliveryDedupTTL.String() != "2h0m0s" {
		t.Fatalf("DeliveryDedupTTL = %s, want 2h", cfg.DeliveryDedupTTL)
	}
	if cfg.MaxRiskScore != 7 {
		t.Fatalf("MaxRiskScore = %d, want 7", cfg.MaxRiskScore)
	}
	if cfg.EnableAutoMerge {
		t.Fatalf("EnableAutoMerge = true, want false")
	}
	if len(cfg.DisallowedPaths) != 2 {
		t.Fatalf("DisallowedPaths len = %d, want 2", len(cfg.DisallowedPaths))
	}
}
