package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moolen/patchpilot/internal/execsafe"
	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/sbom"
	"github.com/moolen/patchpilot/internal/verifycheck"
	"github.com/moolen/patchpilot/internal/vuln"
)

func sbomOptionsFromPolicy(cfg *policy.Config) sbom.Options {
	if cfg == nil {
		return sbom.Options{}
	}
	return sbom.Options{Exclude: append([]string(nil), cfg.Scan.SkipPaths...)}
}

func vulnOptionsFromPolicy(cfg *policy.Config) vuln.ScanOptions {
	if cfg == nil {
		return vuln.ScanOptions{}
	}

	rules := make([]vuln.IgnoreRule, 0)
	for _, id := range cfg.Exclude.CVEs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		rules = append(rules, vuln.IgnoreRule{ID: id})
	}
	for _, selector := range cfg.Exclude.Vulnerabilities {
		rules = append(rules, vuln.IgnoreRule{
			ID:        selector.ID,
			Package:   selector.Package,
			Ecosystem: selector.Ecosystem,
			Path:      selector.Path,
		})
	}
	return vuln.ScanOptions{
		IgnoreRules: rules,
		SkipPaths:   append([]string(nil), cfg.Scan.SkipPaths...),
	}
}

func fileOptionsFromPolicy(cfg *policy.Config) fixer.FileOptions {
	if cfg == nil {
		return fixer.FileOptions{}
	}
	return fixer.FileOptions{SkipPaths: append([]string(nil), cfg.Scan.SkipPaths...)}
}

func dockerOptionsFromPolicy(cfg *policy.Config) fixer.DockerfileOptions {
	if cfg == nil {
		return fixer.DockerfileOptions{BaseImagePatching: true, OSPackagePatching: true}
	}
	return fixer.DockerfileOptions{
		SkipPaths:            append([]string(nil), cfg.Scan.SkipPaths...),
		AllowedBaseImages:    append([]string(nil), cfg.Docker.AllowedBaseImages...),
		DisallowedBaseImages: append([]string(nil), cfg.Docker.DisallowedBaseImages...),
		BaseImagePatching:    cfg.Docker.Patching.BaseImages != policy.DockerPatchDisabled,
		OSPackagePatching:    cfg.Docker.Patching.OSPackages != policy.DockerPatchDisabled,
	}
}

func discoverVerificationDirs(repo string, cfg *policy.Config) ([]string, error) {
	if cfg == nil {
		return verifycheck.DiscoverModuleDirs(repo)
	}
	return verifycheck.DiscoverModuleDirsWithOptions(repo, verifycheck.DiscoverOptions{
		SkipPaths: append([]string(nil), cfg.Scan.SkipPaths...),
	})
}

func runVerificationChecks(ctx context.Context, repo string, dirs []string, cfg *policy.Config) (verifycheck.Report, error) {
	if cfg == nil || len(cfg.Verification.Commands) == 0 {
		return verifycheck.RunStandard(ctx, repo, dirs), nil
	}

	commands := make([]verifycheck.CommandSpec, 0, len(cfg.Verification.Commands))
	for _, command := range cfg.Verification.Commands {
		spec := verifycheck.CommandSpec{
			Name:    command.Name,
			Command: command.Run,
		}
		if strings.TrimSpace(command.Timeout) != "" {
			timeout, err := time.ParseDuration(command.Timeout)
			if err != nil {
				return verifycheck.Report{}, fmt.Errorf("parse verification command timeout for %q: %w", command.Name, err)
			}
			spec.Timeout = timeout
		}
		commands = append(commands, spec)
	}
	return verifycheck.RunWithCommands(ctx, repo, dirs, cfg.Verification.Mode, commands), nil
}

func configureRegistryFromPolicy(repo string, cfg *policy.Config) (func(), error) {
	if cfg == nil {
		return func() {}, nil
	}

	options := fixer.RegistryOptions{
		AuthMode: cfg.Registry.Auth.Mode,
	}
	if strings.TrimSpace(cfg.Registry.Cache.Dir) != "" {
		cacheDir := strings.TrimSpace(cfg.Registry.Cache.Dir)
		if !filepath.IsAbs(cacheDir) {
			cacheDir = filepath.Join(repo, cacheDir)
		}
		options.CacheDir = cacheDir
	}
	if strings.TrimSpace(cfg.Registry.Cache.TTL) != "" {
		ttl, err := time.ParseDuration(strings.TrimSpace(cfg.Registry.Cache.TTL))
		if err != nil {
			return nil, fmt.Errorf("parse registry cache ttl: %w", err)
		}
		options.CacheTTL = ttl
	}

	if cfg.Registry.Auth.Mode == policy.RegistryAuthBearer {
		tokenEnv := strings.TrimSpace(cfg.Registry.Auth.TokenEnv)
		token := strings.TrimSpace(os.Getenv(tokenEnv))
		if token == "" {
			return nil, fmt.Errorf("registry auth token env %q is empty", tokenEnv)
		}
		options.AuthToken = token
	}

	restore := fixer.ConfigureRegistry(options)
	return restore, nil
}

func runPostExecutionHooks(ctx context.Context, repo string, cfg *policy.Config, success bool) error {
	if cfg == nil || len(cfg.PostExecution.Commands) == 0 {
		return nil
	}

	for _, hook := range cfg.PostExecution.Commands {
		if !shouldRunHook(hook.When, success) {
			continue
		}
		logProgress("post-exec hook %q: starting", hook.Name)
		result, err := execsafe.Run(ctx, execsafe.Spec{
			Name:           "post-exec-hook",
			Dir:            repo,
			ShellCommand:   hook.Run,
			ArtifactDir:    filepath.Join(repo, ".cvefix"),
			ArtifactPrefix: fmt.Sprintf("post-hook-%s", sanitizeArtifactName(hook.Name)),
		})
		trimmed := strings.TrimSpace(result.Combined)
		if trimmed != "" {
			_, _ = fmt.Fprintf(os.Stderr, "[cvefix] post-exec %q output:\n%s\n", hook.Name, trimmed)
		}
		if err != nil {
			if hook.FailOnError {
				return fmt.Errorf("post-execution hook %q failed: %w", hook.Name, err)
			}
			logProgress("post-exec hook %q failed (ignored): %v", hook.Name, err)
			continue
		}
		logProgress("post-exec hook %q: completed", hook.Name)
	}

	return nil
}

func sanitizeArtifactName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", "..", "-")
	name = replacer.Replace(name)
	name = strings.Trim(name, "-")
	if name == "" {
		return "hook"
	}
	return name
}

func shouldRunHook(when string, success bool) bool {
	when = strings.ToLower(strings.TrimSpace(when))
	switch when {
	case "", policy.HookWhenAlways:
		return true
	case policy.HookWhenSuccess:
		return success
	case policy.HookWhenFailure:
		return !success
	default:
		return false
	}
}
