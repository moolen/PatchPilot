package githubapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	localJobRunnerMode     = "local"
	containerJobRunnerMode = "container"
	containerWorkspacePath = "/workspace/repo"
)

type patchPilotJobRunner interface {
	Run(ctx context.Context, repoPath string, patchpilotArgs []string) (string, string, error)
	Description() string
}

type localPatchPilotRunner struct {
	binary string
}

func (runner localPatchPilotRunner) Run(ctx context.Context, repoPath string, patchpilotArgs []string) (string, string, error) {
	return runCommand(ctx, repoPath, nil, runner.binary, patchpilotArgs...)
}

func (runner localPatchPilotRunner) Description() string {
	return "local"
}

type containerPatchPilotRunner struct {
	runtime string
	image   string
	binary  string
	network string
}

func (runner containerPatchPilotRunner) Run(ctx context.Context, repoPath string, patchpilotArgs []string) (string, string, error) {
	name, args, err := runner.invocation(repoPath, patchpilotArgs)
	if err != nil {
		return "", "", err
	}
	return runCommand(ctx, repoPath, nil, name, args...)
}

func (runner containerPatchPilotRunner) Description() string {
	return fmt.Sprintf("container(%s)", runner.runtime)
}

func (runner containerPatchPilotRunner) invocation(repoPath string, patchpilotArgs []string) (string, []string, error) {
	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", nil, fmt.Errorf("resolve repo path: %w", err)
	}
	runtime := strings.TrimSpace(runner.runtime)
	if runtime == "" {
		runtime = "docker"
	}
	image := strings.TrimSpace(runner.image)
	if image == "" {
		return "", nil, fmt.Errorf("container image is required")
	}
	binary := strings.TrimSpace(runner.binary)
	if binary == "" {
		binary = "patchpilot"
	}
	network := strings.TrimSpace(runner.network)
	if network == "" {
		network = "bridge"
	}
	userSpec := strconv.Itoa(os.Getuid()) + ":" + strconv.Itoa(os.Getgid())
	args := []string{
		"run",
		"--rm",
		"--workdir", containerWorkspacePath,
		"--user", userSpec,
		"--network", network,
		"--cap-drop=ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev",
		"--tmpfs", "/run:rw,noexec,nosuid,nodev",
		"-e", "HOME=/tmp",
		"-e", "TMPDIR=/tmp",
		"-e", "GIT_TERMINAL_PROMPT=0",
		"-v", absRepoPath + ":" + containerWorkspacePath + ":rw",
	}
	rewrittenArgs, extraMounts := rewritePatchPilotArgsForContainer(absRepoPath, patchpilotArgs)
	for _, mount := range extraMounts {
		args = append(args, "-v", mount)
	}
	args = append(args, image, binary)
	args = append(args, rewrittenArgs...)
	return runtime, args, nil
}

func rewritePatchPilotArgsForContainer(repoPath string, patchpilotArgs []string) ([]string, []string) {
	if len(patchpilotArgs) == 0 {
		return nil, nil
	}
	rewritten := make([]string, 0, len(patchpilotArgs))
	mounts := map[string]struct{}{}
	addMount := func(spec string) {
		if strings.TrimSpace(spec) == "" {
			return
		}
		mounts[spec] = struct{}{}
	}
	for i := 0; i < len(patchpilotArgs); i++ {
		arg := patchpilotArgs[i]
		switch {
		case arg == "--dir" && i+1 < len(patchpilotArgs):
			rewritten = append(rewritten, arg, rewriteRepoPathArg(repoPath, patchpilotArgs[i+1]))
			i++
		case strings.HasPrefix(arg, "--dir="):
			value := strings.TrimPrefix(arg, "--dir=")
			rewritten = append(rewritten, "--dir="+rewriteRepoPathArg(repoPath, value))
		case arg == "--policy" && i+1 < len(patchpilotArgs):
			value, mount := rewritePolicyPathArg(repoPath, patchpilotArgs[i+1])
			rewritten = append(rewritten, arg, value)
			addMount(mount)
			i++
		case strings.HasPrefix(arg, "--policy="):
			value := strings.TrimPrefix(arg, "--policy=")
			rewrittenValue, mount := rewritePolicyPathArg(repoPath, value)
			rewritten = append(rewritten, "--policy="+rewrittenValue)
			addMount(mount)
		default:
			rewritten = append(rewritten, arg)
		}
	}
	extraMounts := make([]string, 0, len(mounts))
	for spec := range mounts {
		extraMounts = append(extraMounts, spec)
	}
	return rewritten, extraMounts
}

func rewriteRepoPathArg(repoPath, value string) string {
	if samePath(repoPath, value) {
		return containerWorkspacePath
	}
	return value
}

func rewritePolicyPathArg(repoPath, value string) (string, string) {
	if strings.TrimSpace(value) == "" || !filepath.IsAbs(value) {
		return value, ""
	}
	if rewritten, ok := rewritePathWithinRepoForContainer(repoPath, value); ok {
		return rewritten, ""
	}
	containerPath := "/workspace/policy/" + filepath.Base(value)
	return containerPath, value + ":" + containerPath + ":ro"
}

func rewritePathWithinRepoForContainer(repoPath, value string) (string, bool) {
	if strings.TrimSpace(repoPath) == "" || strings.TrimSpace(value) == "" {
		return "", false
	}
	absRepoPath, err := filepath.Abs(repoPath)
	if err != nil {
		return "", false
	}
	absValue, err := filepath.Abs(value)
	if err != nil {
		return "", false
	}
	if samePath(absRepoPath, absValue) {
		return containerWorkspacePath, true
	}
	rel, err := filepath.Rel(absRepoPath, absValue)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return containerWorkspacePath, true
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", false
	}
	return filepath.ToSlash(filepath.Join(containerWorkspacePath, rel)), true
}

func samePath(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	normalizedLeft := filepath.Clean(left)
	normalizedRight := filepath.Clean(right)
	return normalizedLeft == normalizedRight
}

func newPatchPilotJobRunner(cfg Config) (patchPilotJobRunner, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.JobRunner)) {
	case "", localJobRunnerMode:
		return localPatchPilotRunner{binary: cfg.PatchPilotBinary}, nil
	case containerJobRunnerMode:
		return containerPatchPilotRunner{
			runtime: cfg.JobContainerRuntime,
			image:   cfg.JobContainerImage,
			binary:  cfg.JobContainerBinary,
			network: cfg.JobContainerNetwork,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported job runner %q", cfg.JobRunner)
	}
}
