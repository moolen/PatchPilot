package githubapp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agentpkg "github.com/moolen/patchpilot/internal/agent"
	"github.com/moolen/patchpilot/internal/fixer"
	"github.com/moolen/patchpilot/internal/policy"
	"github.com/moolen/patchpilot/internal/vuln"
)

func fileOptionsFromPolicy(cfg *policy.Config) fixer.FileOptions {
	if cfg == nil {
		return fixer.FileOptions{UntrustedRepo: true}
	}
	return fixer.FileOptions{
		SkipPaths:     append([]string(nil), cfg.Scan.SkipPaths...),
		UntrustedRepo: true,
	}
}

func dockerOptionsFromPolicy(cfg *policy.Config) fixer.DockerfileOptions {
	if cfg == nil {
		return fixer.DockerfileOptions{BaseImagePatching: true, OSPackagePatching: true}
	}
	baseImageRules := make([]fixer.BaseImageRule, 0, len(cfg.Docker.BaseImageRules))
	for _, rule := range cfg.Docker.BaseImageRules {
		tagSets := make([]fixer.BaseImageTagSet, 0, len(rule.TagSets))
		for _, tagSet := range rule.TagSets {
			tagSets = append(tagSets, fixer.BaseImageTagSet{
				SemverRange: tagSet.SemverRange,
				Allow:       append([]string(nil), tagSet.Allow...),
			})
		}
		baseImageRules = append(baseImageRules, fixer.BaseImageRule{
			Image:   rule.Image,
			TagSets: tagSets,
			Deny:    append([]string(nil), rule.Deny...),
		})
	}
	return fixer.DockerfileOptions{
		SkipPaths:            append([]string(nil), cfg.Scan.SkipPaths...),
		AllowedBaseImages:    append([]string(nil), cfg.Docker.AllowedBaseImages...),
		DisallowedBaseImages: append([]string(nil), cfg.Docker.DisallowedBaseImages...),
		BaseImageRules:       baseImageRules,
		BaseImagePatching:    cfg.Docker.Patching.BaseImages != policy.DockerPatchDisabled,
		OSPackagePatching:    cfg.Docker.Patching.OSPackages != policy.DockerPatchDisabled,
	}
}

func goRuntimeOptionsFromPolicy(cfg *policy.Config) fixer.GoRuntimeOptions {
	if cfg == nil {
		return fixer.GoRuntimeOptions{Mode: fixer.GoRuntimeModeMinimum}
	}
	return fixer.GoRuntimeOptions{
		SkipPaths: append([]string(nil), cfg.Scan.SkipPaths...),
		Mode:      cfg.Go.Patching.Runtime,
	}
}

func applyFixer(ctx context.Context, repoPath, name string, apply func(context.Context, string) ([]fixer.Patch, error)) ([]fixer.Patch, error) {
	patches, err := apply(ctx, repoPath)
	if err != nil {
		return nil, fmt.Errorf("%s fixer: %w", name, err)
	}
	return patches, nil
}

func (service *Service) applyDeterministicRepositoryFixes(ctx context.Context, repoPath string, cfg *policy.Config, report *vuln.Report) ([]fixer.Patch, []string, error) {
	if report == nil {
		return nil, nil, nil
	}
	fileOptions := fileOptionsFromPolicy(cfg)
	dockerOptions := dockerOptionsFromPolicy(cfg)
	goRuntimeOptions := goRuntimeOptionsFromPolicy(cfg)
	engines := []struct {
		name string
		run  func(context.Context, string, []vuln.Finding) ([]fixer.Patch, error)
	}{
		{name: "go_runtime", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyGoRuntimeFixesWithOptions(ctx, repo, findings, goRuntimeOptions)
		}},
		{name: "go_modules", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyGoModuleFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "github_actions", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyGitHubActionsFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "npm", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyNPMFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "pip", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyPIPFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "maven", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyMavenFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "gradle", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyGradleFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "cargo", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyCargoFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "nuget", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyNuGetFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
		{name: "composer", run: func(ctx context.Context, repo string, findings []vuln.Finding) ([]fixer.Patch, error) {
			return fixer.ApplyComposerFixesWithOptions(ctx, repo, findings, fileOptions)
		}},
	}
	patches := make([]fixer.Patch, 0)
	issues := make([]string, 0)
	for _, engine := range engines {
		enginePatches, err := engine.run(ctx, repoPath, report.Findings)
		if err != nil {
			issues = append(issues, fmt.Sprintf("%s: %v", engine.name, err))
			continue
		}
		patches = append(patches, enginePatches...)
	}
	baseImageOptions := dockerOptions
	baseImageOptions.OSPackagePatching = false
	baseImagePatches, err := fixer.ApplyDockerfileFixesWithOptions(ctx, repoPath, report.Findings, baseImageOptions)
	if err != nil {
		issues = append(issues, fmt.Sprintf("docker_base_images: %v", err))
	} else {
		patches = append(patches, baseImagePatches...)
	}
	return patches, issues, nil
}

func (service *Service) applyContainerOSPatchingWithAI(ctx context.Context, repoPath, repoKey string, report *vuln.Report, scan scanRunResult) error {
	if report == nil || len(report.Findings) == 0 {
		return nil
	}
	containerFindings := make([]vuln.Finding, 0)
	for _, finding := range report.Findings {
		if isContainerPackageEcosystem(finding.Ecosystem) {
			containerFindings = append(containerFindings, finding)
		}
	}
	if len(containerFindings) == 0 {
		return nil
	}
	dockerfiles, err := discoverDockerfiles(repoPath, nil)
	if err != nil {
		return err
	}
	state := map[string]any{
		"repository":           repoKey,
		"dockerfiles":          dockerfiles,
		"container_findings":   containerFindings,
		"oci_image":            scan.OCIImage,
		"oci_image_tag":        scan.OCIImageTag,
		"oci_image_repository": scan.OCIImageRepository,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return service.runAgentPatchAttempt(ctx, repoPath, "container-os-patching", "github_app_container_os_patching", "Update Dockerfiles to remediate container OS package vulnerabilities after deterministic base image updates. Do not run validation commands.", string(data), []string{
		"Do not run build, test, or scan commands.",
		"Prefer minimal Dockerfile changes.",
		"Preserve or restore non-root USER behavior.",
		"Do not modify .patchpilot artifacts or .patchpilot.yaml.",
	}, []string{
		"Review container findings and relevant Dockerfiles.",
		"Apply OS package remediation only where it is actually needed.",
		"Do not run validation commands.",
	}, service.runtime.Remediation.Prompts.ContainerOSPatching)
}

func (service *Service) runAgentPatchAttempt(ctx context.Context, repoPath, artifactSuffix, taskKind, goal, currentState string, constraints, validationPlan []string, remediationPrompts []policy.AgentRemediationPromptPolicy) error {
	if strings.TrimSpace(service.cfg.AgentCommand) == "" {
		return nil
	}
	artifactDir := filepath.Join(repoPath, ".patchpilot", "githubapp-agent", artifactSuffix)
	runner := agentpkg.Runner{
		Command: service.cfg.AgentCommand,
		Stdout:  os.Stderr,
		Stderr:  os.Stderr,
	}
	prompts := make([]agentpkg.RemediationPrompt, 0, len(remediationPrompts))
	for _, prompt := range remediationPrompts {
		prompts = append(prompts, agentpkg.RemediationPrompt{
			Mode:     prompt.Mode,
			Template: prompt.Template,
		})
	}
	_, err := runner.RunAttempt(ctx, agentpkg.AttemptRequest{
		RepoPath:           repoPath,
		AttemptNumber:      1,
		TaskKind:           taskKind,
		Goal:               goal,
		CurrentStateLabel:  "Current state",
		CurrentState:       currentState,
		Constraints:        constraints,
		ValidationPlan:     validationPlan,
		RemediationPrompts: prompts,
		WorkingDirectory:   repoPath,
		PromptFilePath:     filepath.Join(artifactDir, "prompt.txt"),
	})
	if err != nil {
		return fmt.Errorf("run agent patch attempt: %w", err)
	}
	return nil
}
