package verifycheck

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func verifyJSONObject(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	return nil
}

func verifyXMLFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer func() {
		_ = file.Close()
	}()
	decoder := xml.NewDecoder(file)
	for {
		if _, err := decoder.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("parse %s: %w", path, err)
		}
	}
}

func verifyRequirementsFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read requirements dir %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if !strings.HasSuffix(name, ".txt") {
			continue
		}
		if name != "requirements.txt" && !strings.HasPrefix(name, "requirements") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		lines := strings.Split(string(data), "\n")
		for index, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			if strings.HasPrefix(trimmed, "-") {
				continue
			}
			if strings.Contains(trimmed, "://") || strings.HasPrefix(strings.ToLower(trimmed), "git+") || strings.Contains(trimmed, "@") {
				continue
			}
			if requirementsVerifyLinePattern.MatchString(trimmed) {
				continue
			}
			return fmt.Errorf("%s:%d invalid requirement line", path, index+1)
		}
	}
	return nil
}

func verifyGradleFiles(dir string) error {
	for _, file := range []string{"build.gradle", "build.gradle.kts"} {
		path := filepath.Join(dir, file)
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return fmt.Errorf("read %s: %w", path, err)
		}
		if strings.TrimSpace(string(data)) == "" {
			return fmt.Errorf("%s is empty", path)
		}
	}
	return nil
}

func verifyCargoManifest(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	content := string(data)
	if strings.Contains(content, "[package]") || strings.Contains(content, "[workspace]") {
		return nil
	}
	return fmt.Errorf("%s missing [package] or [workspace] section", path)
}

func verifyCSProjFiles(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read project dir %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".csproj") {
			continue
		}
		if err := verifyXMLFile(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}

func hasRequirementsFile(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := strings.ToLower(entry.Name())
		if name == "requirements.txt" || (strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt")) {
			return true
		}
	}
	return false
}

func hasCSProjFile(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".csproj") {
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

func trimError(message string) string {
	message = strings.TrimSpace(message)
	const maxLen = 1000
	if len(message) <= maxLen {
		return message
	}
	return strings.TrimSpace(message[:maxLen]) + "…"
}
