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
		args = []string{"serve"}
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
		newServeCommand(),
		newDoctorCommand(stdout, stderr),
		newManifestCommand(stdout, stderr),
	)
	return root
}

func newServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Run the PatchPilot scheduler service",
		RunE: func(command *cobra.Command, args []string) error {
			return serve()
		},
	}
}

func newDoctorCommand(stdout, stderr io.Writer) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Validate runtime dependencies and configuration",
		RunE: func(command *cobra.Command, args []string) error {
			if code := runDoctor(stdout, stderr); code != 0 {
				return fmt.Errorf("doctor checks failed")
			}
			return nil
		},
	}
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

func serve() error {
	cfg, err := githubapp.LoadConfigFromEnv()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

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

func runDoctor(stdout, stderr io.Writer) int {
	cfg, err := githubapp.LoadConfigFromEnv()
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
		check("go binary", ensureBinary("go"))
		check("node binary", ensureBinary("node"))
		check("npm binary", ensureBinary("npm"))
	}

	if cfg.PrivateKeyPath != "" {
		_, err := os.ReadFile(cfg.PrivateKeyPath)
		check("private key file", err)
	} else {
		_, _ = fmt.Fprintln(stdout, "doctor: private key file: OK (using PP_PRIVATE_KEY_PEM)")
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
			"contents":      "write",
			"pull_requests": "write",
			"metadata":      "read",
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
