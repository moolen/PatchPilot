package githubapp

import (
	"context"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
)

func (service *Service) runtimeSnapshot() *AppRuntimeConfig {
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	return service.runtime
}

func (service *Service) setRuntimeConfig(cfg *AppRuntimeConfig) {
	service.runtimeMu.Lock()
	defer service.runtimeMu.Unlock()
	service.runtime = cfg
}

func (service *Service) startRuntimeConfigWatcher(ctx context.Context) {
	path := strings.TrimSpace(service.cfg.RuntimeConfigPath)
	if path == "" {
		return
	}
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		service.log("warn", "runtime config watcher disabled", map[string]interface{}{
			"path":  path,
			"error": err.Error(),
		})
		return
	}
	dir := filepath.Dir(path)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		service.log("warn", "runtime config watcher disabled", map[string]interface{}{
			"path":  path,
			"error": err.Error(),
		})
		return
	}
	service.log("info", "runtime config watcher enabled", map[string]interface{}{
		"path":      path,
		"watch_dir": dir,
	})

	go func() {
		defer func() {
			_ = watcher.Close()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case err := <-watcher.Errors:
				if err == nil {
					continue
				}
				service.log("warn", "runtime config watcher error", map[string]interface{}{
					"path":  path,
					"error": err.Error(),
				})
			case event := <-watcher.Events:
				if !runtimeConfigEventRelevant(path, event) {
					continue
				}
				cfg, err := LoadAppRuntimeConfig(path)
				if err != nil {
					service.log("warn", "runtime config reload failed; keeping last-good configuration", map[string]interface{}{
						"path":  path,
						"event": event.String(),
						"error": err.Error(),
					})
					continue
				}
				service.setRuntimeConfig(cfg)
				service.log("info", "runtime config reloaded", map[string]interface{}{
					"path":   path,
					"event":  event.String(),
					"images": countMappedRuntimeImages(cfg),
				})
			}
		}
	}()
}

func runtimeConfigEventRelevant(path string, event fsnotify.Event) bool {
	target := filepath.Clean(path)
	eventPath := filepath.Clean(event.Name)
	if eventPath == target {
		return true
	}
	if filepath.Base(eventPath) == filepath.Base(target) {
		return true
	}
	// Kubernetes ConfigMap updates usually rotate symlinks like `..data`.
	return strings.HasPrefix(filepath.Base(eventPath), "..")
}

func countMappedRuntimeImages(cfg *AppRuntimeConfig) int {
	if cfg == nil {
		return 0
	}
	total := 0
	for _, mapping := range cfg.OCI.Mappings {
		total += len(mapping.Images)
	}
	return total
}
