package verifycheck

import (
	"context"
	"path/filepath"
	"strings"
)

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
