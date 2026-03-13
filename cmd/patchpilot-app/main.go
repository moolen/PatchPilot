package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/moolen/patchpilot/internal/githubapp"
	"github.com/spf13/cobra"
)

func main() {
	if err := execute(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func execute(args []string, stdout, stderr io.Writer) error {
	root := newRootCommand(stdout, stderr)
	if len(args) == 0 {
		args = []string{"run"}
	}
	root.SetArgs(args)
	return root.Execute()
}

func newRootCommand(stdout, stderr io.Writer) *cobra.Command {
	root := &cobra.Command{
		Use:           "patchpilot-app",
		Short:         "PatchPilot GitHub App service",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newRunCommand(),
		newDoctorCommand(stdout, stderr),
		newManifestCommand(stdout, stderr),
	)
	return root
}

type runOptions struct {
	githubAuthMode                string
	appID                         int64
	privateKeyPath                string
	githubTokenRepositories       string
	listenAddr                    string
	workDir                       string
	patchPilotBinary              string
	agentCommand                  string
	runtimeConfigFile             string
	jobRunner                     string
	jobContainerRuntime           string
	jobContainerImage             string
	jobContainerBinary            string
	jobContainerNetwork           string
	githubWebBaseURL              string
	githubAPIBaseURL              string
	githubUploadAPIURL            string
	enableAutoMerge               bool
	disallowedPaths               string
	repositoryLabelSelector       string
	repositoryIgnoreLabelSelector string
	metricsPath                   string
	schedulerTick                 string
	repoRunTimeout                string
	prStatusPollInterval          string
	githubRetryMaxAttempts        int
	githubRetryInitialBackoff     string
	githubRetryMaxBackoff         string
	requirePolicyFile             bool
	forceReconcileOnStart         bool
}

func newRunCommand() *cobra.Command {
	options := runOptions{}
	command := &cobra.Command{
		Use:   "run",
		Short: "Run the PatchPilot scheduler service",
		RunE: func(command *cobra.Command, args []string) error {
			return run(command, options)
		},
	}
	addRuntimeConfigFlags(command, &options)
	command.Flags().BoolVar(&options.requirePolicyFile, "require-policy-file", false, "Skip repositories that do not contain .patchpilot.yaml")
	return command
}

func newDoctorCommand(stdout, stderr io.Writer) *cobra.Command {
	options := runOptions{}
	command := &cobra.Command{
		Use:   "doctor",
		Short: "Validate runtime dependencies and configuration",
		RunE: func(command *cobra.Command, args []string) error {
			if code := runDoctor(stdout, stderr, options.envOverrides(command)); code != 0 {
				return fmt.Errorf("doctor checks failed")
			}
			return nil
		},
	}
	addRuntimeConfigFlags(command, &options)
	return command
}

func newManifestCommand(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "manifest",
		Short: "Print a starter GitHub App manifest",
		RunE: func(command *cobra.Command, args []string) error {
			if code := runManifest(stdout, stderr); code != 0 {
				return fmt.Errorf("manifest generation failed")
			}
			return nil
		},
	}
}

func run(command *cobra.Command, options runOptions) error {
	cfg, err := githubapp.LoadConfigFromEnvWithOverrides(options.envOverrides(command))
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	cfg.RequirePolicyFile = options.requirePolicyFile

	logger := log.New(os.Stdout, "[patchpilot-app] ", log.LstdFlags)
	service, err := githubapp.NewService(cfg, logger)
	if err != nil {
		return fmt.Errorf("initialize app service: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc(cfg.MetricsPath, service.MetricsHandler)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		errCh <- service.Run(ctx)
	}()
	go func() {
		logger.Printf("listening on %s", cfg.ListenAddr)
		errCh <- server.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			_ = server.Shutdown(context.Background())
			return fmt.Errorf("run service: %w", err)
		}
		stop()
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown server: %w", err)
	}
	return nil
}

func runDoctor(stdout, stderr io.Writer, envOverrides map[string]string) int {
	cfg, err := githubapp.LoadConfigFromEnvWithOverrides(envOverrides)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "doctor: config invalid: %v\n", err)
		return 1
	}

	errorsFound := false
	check := func(name string, err error) {
		if err != nil {
			errorsFound = true
			_, _ = fmt.Fprintf(stderr, "doctor: %s: FAIL (%v)\n", name, err)
			return
		}
		_, _ = fmt.Fprintf(stdout, "doctor: %s: OK\n", name)
	}

	check("workdir writable", ensureWritableDir(cfg.WorkDir))
	check("git binary", ensureBinary("git"))
	if cfg.JobRunner == "container" {
		check("job container runtime", ensureBinary(cfg.JobContainerRuntime))
		if strings.TrimSpace(cfg.JobContainerImage) == "" {
			check("job container image", fmt.Errorf("PP_JOB_CONTAINER_IMAGE is required"))
		} else {
			check("job container image", nil)
		}
	} else {
		check("PatchPilot binary", ensureBinary(cfg.PatchPilotBinary))
		check("syft binary", ensureBinary("syft"))
		check("grype binary", ensureBinary("grype"))
		check("docker binary", ensureBinary("docker"))
		check("go binary", ensureBinary("go"))
		check("node binary", ensureBinary("node"))
		check("npm binary", ensureBinary("npm"))
		check("cargo binary", ensureBinary("cargo"))
	}

	switch cfg.AuthMode {
	case githubapp.AuthModeToken:
		_, _ = fmt.Fprintln(stdout, "doctor: github token auth: OK")
	default:
		if cfg.PrivateKeyPath != "" {
			_, err := os.ReadFile(cfg.PrivateKeyPath)
			check("private key file", err)
		} else {
			_, _ = fmt.Fprintln(stdout, "doctor: private key file: OK (using PP_PRIVATE_KEY_PEM)")
		}
	}
	if strings.TrimSpace(cfg.RuntimeConfigPath) != "" {
		_, err := os.ReadFile(cfg.RuntimeConfigPath)
		check("app runtime config file", err)
	}

	if errorsFound {
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "doctor: all checks passed")
	return 0
}

func runManifest(stdout, stderr io.Writer) int {
	type appManifest struct {
		Name        string            `json:"name"`
		URL         string            `json:"url"`
		HookAttrs   map[string]string `json:"hook_attributes"`
		RedirectURL string            `json:"redirect_url"`
		Public      bool              `json:"public"`
		DefaultPerm map[string]string `json:"default_permissions"`
		DefaultEvts []string          `json:"default_events"`
	}

	appURL := envOrDefault("PP_APP_URL", "https://example.com")
	manifest := appManifest{
		Name:        envOrDefault("PP_APP_NAME", "PatchPilot"),
		URL:         appURL,
		HookAttrs:   map[string]string{"url": appURL},
		RedirectURL: appURL,
		Public:      false,
		DefaultPerm: map[string]string{
			"actions":       "write",
			"checks":        "read",
			"contents":      "write",
			"issues":        "write",
			"metadata":      "read",
			"pull_requests": "write",
			"statuses":      "read",
		},
		DefaultEvts: []string{},
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		_, _ = fmt.Fprintf(stderr, "manifest: encode failed: %v\n", err)
		return 1
	}
	return 0
}

func ensureWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	testFile := filepath.Join(dir, ".patchpilot-doctor")
	if err := os.WriteFile(testFile, []byte("ok"), 0o644); err != nil {
		return err
	}
	_ = os.Remove(testFile)
	return nil
}

func ensureBinary(name string) error {
	if _, err := exec.LookPath(name); err != nil {
		return err
	}
	return nil
}

func envOrDefault(key, defaultValue string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return defaultValue
	}
	return value
}

func addRuntimeConfigFlags(command *cobra.Command, options *runOptions) {
	if command == nil || options == nil {
		return
	}
	flags := command.Flags()
	flags.StringVar(&options.githubAuthMode, "github-auth-mode", "", "GitHub auth mode: app|token|auto (env: PP_GITHUB_AUTH_MODE)")
	flags.Int64Var(&options.appID, "app-id", 0, "GitHub App ID (env: PP_APP_ID)")
	flags.StringVar(&options.privateKeyPath, "private-key-path", "", "Path to GitHub App private key PEM file (env: PP_PRIVATE_KEY_PATH)")
	flags.StringVar(&options.githubTokenRepositories, "github-token-repositories", "", "Comma-separated token allowlist repos owner/repo (env: PP_GITHUB_TOKEN_REPOSITORIES)")
	flags.StringVar(&options.listenAddr, "listen-addr", "", "HTTP listen address (env: PP_LISTEN_ADDR)")
	flags.StringVar(&options.workDir, "workdir", "", "Temporary working directory root (env: PP_WORKDIR)")
	flags.StringVar(&options.patchPilotBinary, "patchpilot-binary", "", "Path to PatchPilot binary (env: PP_PATCHPILOT_BINARY)")
	flags.StringVar(&options.agentCommand, "agent-command", "", "External agent command for remediation (env: PP_AGENT_COMMAND)")
	flags.StringVar(&options.runtimeConfigFile, "runtime-config-file", "", "Path to app runtime config file with oci.mappings/remediation settings (env: PP_GITHUB_APP_CONFIG_FILE)")
	flags.StringVar(&options.jobRunner, "job-runner", "", "Repo job runner: local|container (env: PP_JOB_RUNNER)")
	flags.StringVar(&options.jobContainerRuntime, "job-container-runtime", "", "Container runtime used when job runner is container (env: PP_JOB_CONTAINER_RUNTIME)")
	flags.StringVar(&options.jobContainerImage, "job-container-image", "", "Container image used when job runner is container (env: PP_JOB_CONTAINER_IMAGE)")
	flags.StringVar(&options.jobContainerBinary, "job-container-binary", "", "PatchPilot binary path inside the job container (env: PP_JOB_CONTAINER_BINARY)")
	flags.StringVar(&options.jobContainerNetwork, "job-container-network", "", "Network mode for container jobs (env: PP_JOB_CONTAINER_NETWORK)")
	flags.StringVar(&options.githubWebBaseURL, "github-web-base-url", "", "GitHub web base URL for clone links (env: PP_GITHUB_WEB_BASE_URL)")
	flags.StringVar(&options.githubAPIBaseURL, "github-api-base-url", "", "GitHub API base URL for enterprise mode (env: PP_GITHUB_API_BASE_URL)")
	flags.StringVar(&options.githubUploadAPIURL, "github-upload-api-url", "", "GitHub upload API URL for enterprise mode (env: PP_GITHUB_UPLOAD_API_URL)")
	flags.BoolVar(&options.enableAutoMerge, "enable-auto-merge", false, "Enable remediation PR auto-merge attempts (env: PP_ENABLE_AUTO_MERGE)")
	flags.StringVar(&options.disallowedPaths, "disallowed-paths", "", "Comma-separated path globs that block PR creation (env: PP_DISALLOWED_PATHS)")
	flags.StringVar(&options.repositoryLabelSelector, "repository-label-selector", "", "Comma-separated repository topic selectors for opt-in rollout (env: PP_REPOSITORY_LABEL_SELECTOR)")
	flags.StringVar(&options.repositoryIgnoreLabelSelector, "repository-ignore-label-selector", "", "Comma-separated repository topic selectors that force skip (env: PP_REPOSITORY_IGNORE_LABEL_SELECTOR)")
	flags.StringVar(&options.metricsPath, "metrics-path", "", "Metrics endpoint path (env: PP_METRICS_PATH)")
	flags.StringVar(&options.schedulerTick, "scheduler-tick", "", "Repository discovery/reconcile interval duration (env: PP_SCHEDULER_TICK)")
	flags.StringVar(&options.repoRunTimeout, "repo-run-timeout", "", "Per-repository run timeout duration (env: PP_REPO_RUN_TIMEOUT)")
	flags.StringVar(&options.prStatusPollInterval, "pr-status-poll-interval", "", "Polling interval while waiting for PR CI (env: PP_PR_STATUS_POLL_INTERVAL)")
	flags.IntVar(&options.githubRetryMaxAttempts, "github-retry-max-attempts", 0, "Max GitHub API retry attempts (env: PP_GITHUB_RETRY_MAX_ATTEMPTS)")
	flags.StringVar(&options.githubRetryInitialBackoff, "github-retry-initial-backoff", "", "Initial GitHub API retry backoff duration (env: PP_GITHUB_RETRY_INITIAL_BACKOFF)")
	flags.StringVar(&options.githubRetryMaxBackoff, "github-retry-max-backoff", "", "Max GitHub API retry backoff duration (env: PP_GITHUB_RETRY_MAX_BACKOFF)")
	flags.BoolVar(&options.forceReconcileOnStart, "force-reconcile-on-start", false, "Force one immediate repository reconciliation cycle on startup even when repositories are not due (env: PP_FORCE_RECONCILE_ON_START)")
}

func (options runOptions) envOverrides(command *cobra.Command) map[string]string {
	if command == nil {
		return nil
	}
	flags := command.Flags()
	overrides := map[string]string{}
	set := func(flagName, envKey, value string) {
		if flags.Changed(flagName) {
			overrides[envKey] = value
		}
	}

	set("github-auth-mode", "PP_GITHUB_AUTH_MODE", options.githubAuthMode)
	if flags.Changed("app-id") {
		overrides["PP_APP_ID"] = strconv.FormatInt(options.appID, 10)
	}
	set("private-key-path", "PP_PRIVATE_KEY_PATH", options.privateKeyPath)
	set("github-token-repositories", "PP_GITHUB_TOKEN_REPOSITORIES", options.githubTokenRepositories)
	set("listen-addr", "PP_LISTEN_ADDR", options.listenAddr)
	set("workdir", "PP_WORKDIR", options.workDir)
	set("patchpilot-binary", "PP_PATCHPILOT_BINARY", options.patchPilotBinary)
	set("agent-command", "PP_AGENT_COMMAND", options.agentCommand)
	if flags.Changed("runtime-config-file") {
		overrides["PP_GITHUB_APP_CONFIG_FILE"] = options.runtimeConfigFile
		overrides["PP_OCI_MAPPING_FILE"] = ""
	}
	set("job-runner", "PP_JOB_RUNNER", options.jobRunner)
	set("job-container-runtime", "PP_JOB_CONTAINER_RUNTIME", options.jobContainerRuntime)
	set("job-container-image", "PP_JOB_CONTAINER_IMAGE", options.jobContainerImage)
	set("job-container-binary", "PP_JOB_CONTAINER_BINARY", options.jobContainerBinary)
	set("job-container-network", "PP_JOB_CONTAINER_NETWORK", options.jobContainerNetwork)
	set("github-web-base-url", "PP_GITHUB_WEB_BASE_URL", options.githubWebBaseURL)
	set("github-api-base-url", "PP_GITHUB_API_BASE_URL", options.githubAPIBaseURL)
	set("github-upload-api-url", "PP_GITHUB_UPLOAD_API_URL", options.githubUploadAPIURL)
	if flags.Changed("enable-auto-merge") {
		overrides["PP_ENABLE_AUTO_MERGE"] = strconv.FormatBool(options.enableAutoMerge)
	}
	set("disallowed-paths", "PP_DISALLOWED_PATHS", options.disallowedPaths)
	set("repository-label-selector", "PP_REPOSITORY_LABEL_SELECTOR", options.repositoryLabelSelector)
	set("repository-ignore-label-selector", "PP_REPOSITORY_IGNORE_LABEL_SELECTOR", options.repositoryIgnoreLabelSelector)
	set("metrics-path", "PP_METRICS_PATH", options.metricsPath)
	set("scheduler-tick", "PP_SCHEDULER_TICK", options.schedulerTick)
	set("repo-run-timeout", "PP_REPO_RUN_TIMEOUT", options.repoRunTimeout)
	set("pr-status-poll-interval", "PP_PR_STATUS_POLL_INTERVAL", options.prStatusPollInterval)
	if flags.Changed("github-retry-max-attempts") {
		overrides["PP_GITHUB_RETRY_MAX_ATTEMPTS"] = strconv.Itoa(options.githubRetryMaxAttempts)
	}
	set("github-retry-initial-backoff", "PP_GITHUB_RETRY_INITIAL_BACKOFF", options.githubRetryInitialBackoff)
	set("github-retry-max-backoff", "PP_GITHUB_RETRY_MAX_BACKOFF", options.githubRetryMaxBackoff)
	if flags.Changed("force-reconcile-on-start") {
		overrides["PP_FORCE_RECONCILE_ON_START"] = strconv.FormatBool(options.forceReconcileOnStart)
	}

	if len(overrides) == 0 {
		return nil
	}
	return overrides
}
