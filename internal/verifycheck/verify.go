package verifycheck

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
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
	Name     string
	GoArgs   []string
	Command  string
	Internal func(ctx context.Context, dir string) error
	Timeout  time.Duration
}

var standardChecks = []standardCheck{
	{Name: "build", Args: []string{"build", "./..."}},
	{Name: "compile-tests", Args: []string{"test", "-run", "^$", "./..."}},
	{Name: "vet", Args: []string{"vet", "./..."}},
}

var requirementsVerifyLinePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+(\[[A-Za-z0-9_,.-]+\])?(\s*[<>=!~]{1,2}\s*[^\s#;]+)?(\s*;.*)?$`)

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
			case ".git", ".patchpilot", "vendor":
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

func allStandardCheckDefinitions() []checkDefinition {
	checks := append([]checkDefinition{}, standardCheckDefinitions()...)
	checks = append(checks,
		checkDefinition{Name: "npm-manifest-parse"},
		checkDefinition{Name: "pip-requirements-parse"},
		checkDefinition{Name: "maven-pom-parse"},
		checkDefinition{Name: "gradle-build-parse"},
		checkDefinition{Name: "cargo-manifest-parse"},
		checkDefinition{Name: "nuget-project-parse"},
		checkDefinition{Name: "composer-manifest-parse"},
	)
	return checks
}

func standardNonGoChecksForDir(absDir string) []checkDefinition {
	checks := make([]checkDefinition, 0)
	if fileExists(filepath.Join(absDir, "package.json")) {
		checks = append(checks, checkDefinition{
			Name: "npm-manifest-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyJSONObject(filepath.Join(dir, "package.json"))
			},
		})
	}
	if hasRequirementsFile(absDir) {
		checks = append(checks, checkDefinition{
			Name: "pip-requirements-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyRequirementsFiles(dir)
			},
		})
	}
	if fileExists(filepath.Join(absDir, "pom.xml")) {
		checks = append(checks, checkDefinition{
			Name: "maven-pom-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyXMLFile(filepath.Join(dir, "pom.xml"))
			},
		})
	}
	if fileExists(filepath.Join(absDir, "build.gradle")) || fileExists(filepath.Join(absDir, "build.gradle.kts")) {
		checks = append(checks, checkDefinition{
			Name: "gradle-build-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyGradleFiles(dir)
			},
		})
	}
	if fileExists(filepath.Join(absDir, "Cargo.toml")) {
		checks = append(checks, checkDefinition{
			Name: "cargo-manifest-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyCargoManifest(filepath.Join(dir, "Cargo.toml"))
			},
		})
	}
	if hasCSProjFile(absDir) {
		checks = append(checks, checkDefinition{
			Name: "nuget-project-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyCSProjFiles(dir)
			},
		})
	}
	if fileExists(filepath.Join(absDir, "composer.json")) {
		checks = append(checks, checkDefinition{
			Name: "composer-manifest-parse",
			Internal: func(ctx context.Context, dir string) error {
				_ = ctx
				return verifyJSONObject(filepath.Join(dir, "composer.json"))
			},
		})
	}
	return checks
}

func discoverStandardTargetDirs(repoAbs string) ([]string, error) {
	dirs := make([]string, 0)
	err := filepath.WalkDir(repoAbs, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", ".patchpilot", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !isStandardTargetFile(entry.Name()) {
			return nil
		}
		relDir, err := filepath.Rel(repoAbs, filepath.Dir(path))
		if err != nil {
			return err
		}
		dirs = append(dirs, filepath.Clean(relDir))
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk repo for verification targets: %w", err)
	}
	return dedupeSorted(dirs), nil
}

func isStandardTargetFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".csproj") {
		return true
	}
	if strings.EqualFold(name, "go.mod") || strings.EqualFold(name, "package.json") || strings.EqualFold(name, "pom.xml") || strings.EqualFold(name, "build.gradle") || strings.EqualFold(name, "build.gradle.kts") || strings.EqualFold(name, "cargo.toml") || strings.EqualFold(name, "composer.json") {
		return true
	}
	return strings.HasPrefix(lower, "requirements") && strings.HasSuffix(lower, ".txt")
}

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
	found := false
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".csproj") {
			continue
		}
		found = true
		if err := verifyXMLFile(filepath.Join(dir, entry.Name())); err != nil {
			return err
		}
	}
	if !found {
		return nil
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
		_, _ = fmt.Fprintf(w, "... %d more verification failures written to .patchpilot/verification.json\n", total-printed)
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
