package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type actionMetadata struct {
	Inputs  map[string]actionInput  `yaml:"inputs"`
	Outputs map[string]actionOutput `yaml:"outputs"`
	Runs    actionRuns              `yaml:"runs"`
}

type actionInput struct {
	Required bool   `yaml:"required"`
	Default  string `yaml:"default"`
}

type actionOutput struct {
	Description string `yaml:"description"`
}

type actionRuns struct {
	Using string `yaml:"using"`
	Image string `yaml:"image"`
}

func TestActionMetadataContract(t *testing.T) {
	raw, err := os.ReadFile("action.yml")
	if err != nil {
		t.Fatalf("read action metadata: %v", err)
	}

	var metadata actionMetadata
	if err := yaml.Unmarshal(raw, &metadata); err != nil {
		t.Fatalf("parse action metadata: %v", err)
	}

	expectedInputs := map[string]string{
		"command":               "fix",
		"dir":                   ".",
		"repo_url":              "",
		"policy":                "",
		"enable_agent":          "false",
		"agent_command":         "codex",
		"agent_max_attempts":    "5",
		"extra_args":            "",
		"acceptable_exit_codes": "0",
	}
	for key, expectedDefault := range expectedInputs {
		input, ok := metadata.Inputs[key]
		if !ok {
			t.Fatalf("missing input %q in action.yml", key)
		}
		if input.Required {
			t.Fatalf("input %q must remain optional for compatibility", key)
		}
		if input.Default != expectedDefault {
			t.Fatalf("unexpected default for input %q: got %q want %q", key, input.Default, expectedDefault)
		}
	}

	if _, ok := metadata.Outputs["exit-code"]; !ok {
		t.Fatalf("missing output %q in action.yml", "exit-code")
	}
	if strings.TrimSpace(metadata.Outputs["exit-code"].Description) == "" {
		t.Fatalf("output %q description must not be empty", "exit-code")
	}

	if metadata.Runs.Using != "docker" {
		t.Fatalf("action runtime changed: got %q want %q", metadata.Runs.Using, "docker")
	}
	if metadata.Runs.Image != "Dockerfile" {
		t.Fatalf("action image changed: got %q want %q", metadata.Runs.Image, "Dockerfile")
	}
}

func TestActionDocsCoverContractSurface(t *testing.T) {
	raw, err := os.ReadFile("docs/github-action.md")
	if err != nil {
		t.Fatalf("read docs: %v", err)
	}
	content := string(raw)
	for _, key := range []string{
		"`command`",
		"`dir`",
		"`repo_url`",
		"`policy`",
		"`enable_agent`",
		"`agent_command`",
		"`agent_max_attempts`",
		"`extra_args`",
		"`acceptable_exit_codes`",
		"`exit-code`",
	} {
		if !strings.Contains(content, key) {
			t.Fatalf("expected docs/github-action.md to reference %s", key)
		}
	}
}
