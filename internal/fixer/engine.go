package fixer

import (
	"context"

	"github.com/moolen/patchpilot/internal/vuln"
)

type Engine interface {
	Name() string
	Apply(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error)
}

type engineFunc struct {
	name  string
	apply func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error)
}

func (engine engineFunc) Name() string {
	return engine.name
}

func (engine engineFunc) Apply(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return engine.apply(ctx, repo, findings)
}

func DefaultEngines(fileOptions FileOptions, dockerOptions DockerfileOptions) []Engine {
	return []Engine{
		engineFunc{
			name: "go_runtime",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				_ = findings
				return ApplyGoRuntimeFixesWithOptions(ctx, repo, fileOptions)
			},
		},
		engineFunc{
			name: "go_modules",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyGoModuleFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "docker",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyDockerfileFixesWithOptions(ctx, repo, findings, dockerOptions)
			},
		},
		engineFunc{
			name: "npm",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyNPMFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "pip",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyPIPFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "maven",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyMavenFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "gradle",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyGradleFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "cargo",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyCargoFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "nuget",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyNuGetFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
		engineFunc{
			name: "composer",
			apply: func(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
				return ApplyComposerFixesWithOptions(ctx, repo, findings, fileOptions)
			},
		},
	}
}
