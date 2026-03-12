package githubapp

import (
	"context"
	"io"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRuntimeConfigWatcherReloadsAndKeepsLastGood(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.yaml")
	initial := `oci:
  mappings:
    - repo: acme/demo
      images:
        - source: ghcr.io/acme/demo
          dockerfiles:
            - Dockerfile
`
	if err := os.WriteFile(path, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial runtime config: %v", err)
	}
	cfg, err := LoadAppRuntimeConfig(path)
	if err != nil {
		t.Fatalf("load initial runtime config: %v", err)
	}

	logger := log.New(io.Discard, "", 0)
	service := &Service{
		cfg:     Config{RuntimeConfigPath: path},
		logger:  logger,
		slog:    newStructuredLogger(logger),
		runtime: cfg,
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	service.startRuntimeConfigWatcher(ctx)

	updated := `oci:
  mappings:
    - repo: acme/demo
      images:
        - source: ghcr.io/acme/demo:v2
          dockerfiles:
            - Dockerfile
`
	if err := atomicWriteFile(path, []byte(updated)); err != nil {
		t.Fatalf("write updated runtime config: %v", err)
	}
	waitForCondition(t, 3*time.Second, func() bool {
		current := service.runtimeSnapshot()
		mapping, ok := current.RepositoryMapping("acme/demo")
		if !ok || len(mapping.Images) != 1 {
			return false
		}
		return mapping.Images[0].Source == "ghcr.io/acme/demo:v2"
	})

	invalid := `oci:
  mappings:
    - repo: acme/*
      images:
        - source: ghcr.io/acme/demo
          dockerfiles: [Dockerfile]
`
	if err := atomicWriteFile(path, []byte(invalid)); err != nil {
		t.Fatalf("write invalid runtime config: %v", err)
	}
	time.Sleep(250 * time.Millisecond)

	current := service.runtimeSnapshot()
	mapping, ok := current.RepositoryMapping("acme/demo")
	if !ok || len(mapping.Images) != 1 || mapping.Images[0].Source != "ghcr.io/acme/demo:v2" {
		t.Fatalf("expected last-good runtime config to remain active, got %#v", mapping)
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
