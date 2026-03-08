package verifycheck

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/moolen/patchpilot/internal/execsafe"
	"github.com/moolen/patchpilot/internal/goenv"
	"github.com/moolen/patchpilot/internal/pathmatch"
)

const (
	ModeStandard       = "standard"
	ModeAppend         = "append"
	ModeReplace        = "replace"
	checkTimeout       = 5 * time.Minute
	maxPrintedFailures = 12
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusFailed  Status = "failed"
	StatusTimeout Status = "timeout"
)

type CheckResult struct {
	Name           string `json:"name"`
	Status         Status `json:"status"`
	DurationMillis int64  `json:"duration_millis"`
	Error          string `json:"error,omitempty"`
}

type ModuleResult struct {
	Dir    string        `json:"dir"`
	Checks []CheckResult `json:"checks"`
}

type Regression struct {
	Dir            string `json:"dir"`
	Check          string `json:"check"`
	BaselineStatus Status `json:"baseline_status"`
	AfterStatus    Status `json:"after_status"`
	BaselineError  string `json:"baseline_error,omitempty"`
	AfterError     string `json:"after_error,omitempty"`
}

type Report struct {
	Mode        string         `json:"mode"`
	Modules     []ModuleResult `json:"modules"`
	Regressions []Regression   `json:"regressions,omitempty"`
}

type Summary struct {
	Modules     int
	Checks      int
	OK          int
	Failed      int
	Timeouts    int
	Regressions int
}

var runGoCheckFunc = runGoCheck
var runShellCheckFunc = runShellCheck

type DiscoverOptions struct {
	SkipPaths []string
}

type CommandSpec struct {
	Name    string
	Command string
	Timeout time.Duration
}

type standardCheck struct {
	Name string
	Args []string
}

type checkDefinition struct {
	Name    string
	GoArgs  []string
	Command string
	Timeout time.Duration
}

var standardChecks = []standardCheck{
	{Name: "build", Args: []string{"build", "./..."}},
	{Name: "compile-tests", Args: []string{"test", "-run", "^$", "./..."}},
	{Name: "vet", Args: []string{"vet", "./..."}},
}

func DiscoverModuleDirs(repo string) ([]string, error) {
	return DiscoverModuleDirsWithOptions(repo, DiscoverOptions{})
}

func DiscoverModuleDirsWithOptions(repo string, options DiscoverOptions) ([]string, error) {
	repoAbs, err := filepath.Abs(repo)
	if err != nil {
		return nil, fmt.Errorf("resolve repo path: %w", err)
	}

	dirs := make([]string, 0)
	err = filepath.WalkDir(repoAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if shouldSkipPath(repoAbs, path, options.SkipPaths) {
				return filepath.SkipDir
			}
			switch entry.Name() {
			case ".git", ".cvefix", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Name() != "go.mod" {
			return nil
		}
		if shouldSkipPath(repoAbs, path, options.SkipPaths) {
			return nil
		}
		relDir, err := filepath.Rel(repoAbs, filepath.Dir(path))
		if err != nil {
			return fmt.Errorf("relativize module dir %s: %w", path, err)
		}
		dirs = append(dirs, filepath.Clean(relDir))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repo for go.mod files: %w", err)
	}
	sort.Strings(dirs)
	return dedupeSorted(dirs), nil
}

func ModuleDirs(report Report) []string {
	dirs := make([]string, 0, len(report.Modules))
	for _, module := range report.Modules {
		dirs = append(dirs, module.Dir)
	}
	sort.Strings(dirs)
	return dirs
}

func RunStandard(ctx context.Context, repo string, dirs []string) Report {
	return runWithChecks(ctx, repo, dirs, standardCheckDefinitions(), ModeStandard)
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

func Compare(baseline, after Report) []Regression {
	baselineChecks := map[string]CheckResult{}
	for _, module := range baseline.Modules {
		for _, check := range module.Checks {
			baselineChecks[module.Dir+"|"+check.Name] = check
		}
	}

	regressions := make([]Regression, 0)
	for _, module := range after.Modules {
		for _, check := range module.Checks {
			key := module.Dir + "|" + check.Name
			before, ok := baselineChecks[key]
			if !ok || before.Status != StatusOK || check.Status == StatusOK {
				continue
			}
			regressions = append(regressions, Regression{
				Dir:            module.Dir,
				Check:          check.Name,
				BaselineStatus: before.Status,
				AfterStatus:    check.Status,
				BaselineError:  before.Error,
				AfterError:     check.Error,
			})
		}
	}
	sort.Slice(regressions, func(i, j int) bool {
		if regressions[i].Dir == regressions[j].Dir {
			return regressions[i].Check < regressions[j].Check
		}
		return regressions[i].Dir < regressions[j].Dir
	})
	return regressions
}

func Summarize(report Report) Summary {
	summary := Summary{Modules: len(report.Modules), Regressions: len(report.Regressions)}
	for _, module := range report.Modules {
		for _, check := range module.Checks {
			summary.Checks++
			switch check.Status {
			case StatusOK:
				summary.OK++
			case StatusTimeout:
				summary.Timeouts++
			default:
				summary.Failed++
			}
		}
	}
	return summary
}

func PrintSummary(w io.Writer, report Report) {
	summary := Summarize(report)
	_, _ = fmt.Fprintf(w, "Verification mode: %s\n", report.Mode)
	_, _ = fmt.Fprintf(w, "Modules checked: %d\n", summary.Modules)
	_, _ = fmt.Fprintf(w, "Checks run: %d\n", summary.Checks)
	_, _ = fmt.Fprintf(w, "Checks OK: %d\n", summary.OK)
	_, _ = fmt.Fprintf(w, "Checks failed: %d\n", summary.Failed)
	_, _ = fmt.Fprintf(w, "Checks timed out: %d\n", summary.Timeouts)
	_, _ = fmt.Fprintf(w, "Verification regressions: %d\n", summary.Regressions)
	if len(report.Regressions) > 0 {
		_, _ = fmt.Fprintln(w, "Verification regressions detail:")
		for _, regression := range report.Regressions {
			_, _ = fmt.Fprintf(w, "- %s [%s]: %s -> %s\n", regression.Dir, regression.Check, regression.BaselineStatus, regression.AfterStatus)
		}
	}
	printFailures(w, report)
}

func standardCheckDefinitions() []checkDefinition {
	checks := make([]checkDefinition, 0, len(standardChecks))
	for _, check := range standardChecks {
		checks = append(checks, checkDefinition{
			Name:   check.Name,
			GoArgs: append([]string(nil), check.Args...),
		})
	}
	return checks
}

func buildCommandDefinitions(mode string, commands []CommandSpec) ([]checkDefinition, string) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != ModeReplace {
		mode = ModeAppend
	}
	definitions := make([]checkDefinition, 0, len(standardChecks)+len(commands))
	if mode == ModeAppend {
		definitions = append(definitions, standardCheckDefinitions()...)
	}
	for _, command := range commands {
		name := strings.TrimSpace(command.Name)
		if name == "" {
			continue
		}
		run := strings.TrimSpace(command.Command)
		if run == "" {
			continue
		}
		definitions = append(definitions, checkDefinition{
			Name:    name,
			Command: run,
			Timeout: command.Timeout,
		})
	}
	if len(definitions) == 0 {
		return standardCheckDefinitions(), ModeStandard
	}
	if mode == ModeReplace {
		return definitions, "custom"
	}
	if len(commands) == 0 {
		return definitions, ModeStandard
	}
	return definitions, ModeStandard + "+custom"
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
	if check.Command != "" {
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

func resolveModuleDir(repoAbs, dir string) (string, string, error) {
	candidate := filepath.Clean(dir)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(repoAbs, candidate)
	}
	absDir, err := filepath.Abs(candidate)
	if err != nil {
		return "", "", fmt.Errorf("resolve module dir %s: %w", dir, err)
	}
	relDir, err := filepath.Rel(repoAbs, absDir)
	if err != nil {
		return "", "", fmt.Errorf("relativize module dir %s: %w", dir, err)
	}
	if relDir == ".." || strings.HasPrefix(relDir, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("module dir %s escapes repo %s", dir, repoAbs)
	}
	info, err := os.Stat(absDir)
	if err != nil {
		return "", "", fmt.Errorf("stat module dir %s: %w", dir, err)
	}
	if !info.IsDir() {
		return "", "", fmt.Errorf("module dir %s is not a directory", dir)
	}
	return absDir, filepath.Clean(relDir), nil
}

func invalidModuleResult(dir string, checkDefinitions []checkDefinition, err error) ModuleResult {
	checks := make([]CheckResult, 0, len(checkDefinitions))
	message := trimError(err.Error())
	for _, check := range checkDefinitions {
		checks = append(checks, CheckResult{Name: check.Name, Status: StatusFailed, Error: message})
	}
	return ModuleResult{Dir: dir, Checks: checks}
}

func printFailures(w io.Writer, report Report) {
	printed := 0
	total := 0
	for _, module := range report.Modules {
		for _, check := range module.Checks {
			if check.Status == StatusOK {
				continue
			}
			total++
			if printed >= maxPrintedFailures {
				continue
			}
			_, _ = fmt.Fprintf(w, "- %s [%s] %s: %s\n", module.Dir, check.Name, check.Status, check.Error)
			printed++
		}
	}
	if total == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Verification detail entries: %d\n", total)
	if total > printed {
		_, _ = fmt.Fprintf(w, "... %d more verification failures written to .cvefix/verification.json\n", total-printed)
	}
}

func dedupeSorted(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	copyItems := append([]string(nil), items...)
	sort.Strings(copyItems)
	result := make([]string, 0, len(copyItems))
	for _, item := range copyItems {
		if len(result) > 0 && result[len(result)-1] == item {
			continue
		}
		result = append(result, item)
	}
	return result
}

func shouldSkipPath(repo, path string, skipPaths []string) bool {
	if len(skipPaths) == 0 {
		return false
	}
	return pathmatch.ShouldSkipPath(repo, path, skipPaths)
}

func trimError(message string) string {
	message = strings.TrimSpace(message)
	const maxLen = 1000
	if len(message) <= maxLen {
		return message
	}
	return strings.TrimSpace(message[:maxLen]) + "…"
}
