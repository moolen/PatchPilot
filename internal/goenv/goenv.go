package goenv

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func CommandEnv(dir string) ([]string, error) {
	stateDir, err := StateDir(dir)
	if err != nil {
		return nil, err
	}

	gomodcache := filepath.Join(stateDir, "gomodcache")
	gopath := filepath.Join(stateDir, "gopath")
	gocache := filepath.Join(stateDir, "gocache")
	gotmp := filepath.Join(stateDir, "gotmp")
	for _, path := range []string{gomodcache, gopath, gocache, gotmp} {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return nil, fmt.Errorf("create go cache dir %s: %w", path, err)
		}
	}

	env := os.Environ()
	goflags := strings.TrimSpace(os.Getenv("GOFLAGS"))
	if !strings.Contains(goflags, "-modcacherw") {
		if goflags == "" {
			goflags = "-modcacherw"
		} else {
			goflags = goflags + " -modcacherw"
		}
	}
	env = append(env,
		"GOMODCACHE="+gomodcache,
		"GOPATH="+gopath,
		"GOCACHE="+gocache,
		"TMPDIR="+gotmp,
		"GOTMPDIR="+gotmp,
		"GOFLAGS="+goflags,
	)
	return env, nil
}

func StateDir(dir string) (string, error) {
	current := dir
	for {
		candidate := filepath.Join(current, ".cvefix")
		info, err := os.Stat(candidate)
		if err == nil && info.IsDir() {
			return candidate, nil
		}
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("inspect %s: %w", candidate, err)
		}

		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}

	fallback := filepath.Join(dir, ".cvefix")
	if err := os.MkdirAll(fallback, 0o755); err != nil {
		return "", fmt.Errorf("create fallback state dir %s: %w", fallback, err)
	}
	return fallback, nil
}
