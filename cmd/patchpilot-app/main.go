package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/moolen/patchpilot/pkg/githubapp"
)

func main() {
	command := "serve"
	if len(os.Args) > 1 {
		command = os.Args[1]
	}

	switch command {
	case "doctor":
		os.Exit(runDoctor(os.Stdout, os.Stderr))
	case "manifest":
		os.Exit(runManifest(os.Stdout, os.Stderr))
	case "serve":
		serve()
	default:
		if len(os.Args) > 1 && os.Args[1] == "--help" {
			printUsage(os.Stdout)
			return
		}
		fmt.Fprintf(os.Stderr, "unknown command %q\n", command)
		printUsage(os.Stderr)
		os.Exit(2)
	}
}

func serve() {
	cfg, err := githubapp.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config: %v\n", err)
		os.Exit(1)
	}

	logger := log.New(os.Stdout, "[patchpilot-app] ", log.LstdFlags)
	service, err := githubapp.NewService(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "initialize app service: %v\n", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/webhook", service.HandleWebhook)
	mux.HandleFunc(cfg.MetricsPath, service.MetricsHandler)

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	logger.Printf("listening on %s", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "listen: %v\n", err)
		os.Exit(1)
	}
}

func runDoctor(stdout, stderr io.Writer) int {
	cfg, err := githubapp.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintf(stderr, "doctor: config invalid: %v\n", err)
		return 1
	}

	errorsFound := false
	check := func(name string, err error) {
		if err != nil {
			errorsFound = true
			fmt.Fprintf(stderr, "doctor: %s: FAIL (%v)\n", name, err)
			return
		}
		fmt.Fprintf(stdout, "doctor: %s: OK\n", name)
	}

	check("workdir writable", ensureWritableDir(cfg.WorkDir))
	check("cvefix binary", ensureBinary(cfg.CVEFixBinary))
	check("syft binary", ensureBinary("syft"))
	check("grype binary", ensureBinary("grype"))

	if cfg.PrivateKeyPath != "" {
		_, err := os.ReadFile(cfg.PrivateKeyPath)
		check("private key file", err)
	} else {
		fmt.Fprintln(stdout, "doctor: private key file: OK (using PP_PRIVATE_KEY_PEM)")
	}

	if errorsFound {
		return 1
	}
	fmt.Fprintln(stdout, "doctor: all checks passed")
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
	webhookURL := envOrDefault("PP_WEBHOOK_URL", "https://example.com/webhook")
	manifest := appManifest{
		Name:        envOrDefault("PP_APP_NAME", "PatchPilot"),
		URL:         appURL,
		HookAttrs:   map[string]string{"url": webhookURL},
		RedirectURL: appURL,
		Public:      false,
		DefaultPerm: map[string]string{
			"contents":      "write",
			"pull_requests": "write",
			"issues":        "write",
			"metadata":      "read",
		},
		DefaultEvts: []string{"issue_comment", "push"},
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(manifest); err != nil {
		fmt.Fprintf(stderr, "manifest: encode failed: %v\n", err)
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

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "Usage: patchpilot-app [serve|doctor|manifest]")
}
