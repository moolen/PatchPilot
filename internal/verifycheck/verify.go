package verifycheck

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moolen/patchpilot/internal/execsafe"
	"github.com/moolen/patchpilot/internal/goenv"
)

func RunStandard(ctx context.Context, repo string, dirs []string) Report {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return Report{Mode: ModeStandard, Modules: []ModuleResult{invalidModuleResult(repo, allStandardCheckDefinitions(), fmt.Errorf("resolve repo path: %w", err))}}
	}

	provided := dedupeSorted(dirs)
	modules := make([]ModuleResult, 0, len(provided))
	seen := map[string]struct{}{}

	for _, dir := range provided {
		absDir, relDir, err := resolveModuleDir(repoAbs, dir)
		checks := standardCheckDefinitions()
		if err != nil {
			modules = append(modules, invalidModuleResult(dir, checks, err))
			continue
		}
		checks = append(checks, standardNonGoChecksForDir(absDir)...)
		if len(checks) == 0 {
			continue
		}
		module := ModuleResult{Dir: relDir, Checks: make([]CheckResult, 0, len(checks))}
		for _, check := range checks {
			module.Checks = append(module.Checks, runCheck(ctx, absDir, check))
		}
		modules = append(modules, module)
		seen[relDir] = struct{}{}
	}

	extraDirs, err := discoverStandardTargetDirs(repoAbs)
	if err != nil {
		modules = append(modules, invalidModuleResult(".", allStandardCheckDefinitions(), err))
		return Report{Mode: ModeStandard, Modules: modules}
	}
	for _, dir := range extraDirs {
		absDir, relDir, err := resolveModuleDir(repoAbs, dir)
		if err != nil {
			continue
		}
		if _, ok := seen[relDir]; ok {
			continue
		}
		checks := standardNonGoChecksForDir(absDir)
		if len(checks) == 0 {
			continue
		}
		module := ModuleResult{Dir: relDir, Checks: make([]CheckResult, 0, len(checks))}
		for _, check := range checks {
			module.Checks = append(module.Checks, runCheck(ctx, absDir, check))
		}
		modules = append(modules, module)
	}

	sort.Slice(modules, func(i, j int) bool {
		return modules[i].Dir < modules[j].Dir
	})
	return Report{Mode: ModeStandard, Modules: modules}
}

func RunWithCommands(ctx context.Context, repo string, dirs []string, mode string, commands []CommandSpec) Report {
	definitions, reportMode := buildCommandDefinitions(mode, commands)
	return runWithChecks(ctx, repo, dirs, definitions, reportMode)
}

func runWithChecks(ctx context.Context, repo string, dirs []string, checks []checkDefinition, mode string) Report {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return Report{Mode: mode, Modules: []ModuleResult{invalidModuleResult(repo, checks, fmt.Errorf("resolve repo path: %w", err))}}
	}

	deduped := dedupeSorted(dirs)
	modules := make([]ModuleResult, 0, len(deduped))
	for _, dir := range deduped {
		absDir, relDir, err := resolveModuleDir(repoAbs, dir)
		if err != nil {
			modules = append(modules, invalidModuleResult(dir, checks, err))
			continue
		}
		module := ModuleResult{Dir: relDir, Checks: make([]CheckResult, 0, len(checks))}
		for _, check := range checks {
			module.Checks = append(module.Checks, runCheck(ctx, absDir, check))
		}
		modules = append(modules, module)
	}
	return Report{Mode: mode, Modules: modules}
}

func runCheck(ctx context.Context, dir string, check checkDefinition) CheckResult {
	started := time.Now()
	timeout := checkTimeout
	if check.Timeout > 0 {
		timeout = check.Timeout
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var err error
	if check.Internal != nil {
		err = check.Internal(checkCtx, dir)
	} else if check.Command != "" {
		err = runShellCheckFunc(checkCtx, dir, check.Command)
	} else {
		err = runGoCheckFunc(checkCtx, dir, check.GoArgs...)
	}
	result := CheckResult{
		Name:           check.Name,
		Status:         StatusOK,
		DurationMillis: time.Since(started).Milliseconds(),
	}
	if err == nil {
		return result
	}
	if errors.Is(checkCtx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		result.Status = StatusTimeout
	} else {
		result.Status = StatusFailed
	}
	result.Error = trimError(err.Error())
	return result
}

func runGoCheck(ctx context.Context, dir string, args ...string) error {
	env, err := goenv.CommandEnv(dir)
	if err != nil {
		return err
	}
	result, err := execsafe.Run(ctx, execsafe.Spec{
		Name:       "go-check",
		Dir:        dir,
		Binary:     "go",
		Args:       args,
		ReplaceEnv: true,
		Env:        env,
	})
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(result.Combined)
	if trimmed == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, trimmed)
}

func runShellCheck(ctx context.Context, dir, command string) error {
	env, err := goenv.CommandEnv(dir)
	if err != nil {
		return err
	}
	result, err := execsafe.Run(ctx, execsafe.Spec{
		Name:         "shell-check",
		Dir:          dir,
		ShellCommand: command,
		ReplaceEnv:   true,
		Env:          env,
	})
	if err == nil {
		return nil
	}
	trimmed := strings.TrimSpace(result.Combined)
	if trimmed == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, trimmed)
}

func invalidModuleResult(dir string, checkDefinitions []checkDefinition, err error) ModuleResult {
	checks := make([]CheckResult, 0, len(checkDefinitions))
	message := trimError(err.Error())
	for _, check := range checkDefinitions {
		checks = append(checks, CheckResult{Name: check.Name, Status: StatusFailed, Error: message})
	}
	return ModuleResult{Dir: dir, Checks: checks}
}
