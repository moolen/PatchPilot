package prompts

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"text/template"
)

var defaultValidationCommands = []string{
	"go build ./...",
	"go test -run=^$ ./...",
}

var defaultConstraints = []string{
	"prefer minimal, repository-specific changes",
	"preserve the repository's intended behavior",
	"do not modify .patchpilot/ artifacts or .patchpilot.yaml",
}

const (
	RemediationPromptModeExtend  = "extend"
	RemediationPromptModeReplace = "replace"
)

type RemediationPrompt struct {
	Mode     string
	Template string
}

//go:embed prompt.tmpl
var promptTemplateText string

var promptTemplate = template.Must(template.New("prompt.tmpl").Parse(promptTemplateText))

type Request struct {
	RepoPath                 string
	AttemptNumber            int
	TaskKind                 string
	Goal                     string
	CurrentStateLabel        string
	CurrentState             string
	FailureStage             string
	FailureError             string
	PreviousAttemptSummaries []string
	ValidationPlan           []string
	Constraints              []string
	RemediationPrompts       []RemediationPrompt
}

type templateData struct {
	RepoPath                 string
	AttemptNumber            int
	TaskKind                 string
	Goal                     string
	CurrentStateLabel        string
	CurrentState             string
	FailureStage             string
	FailureError             string
	PreviousAttemptSummaries []string
	ValidationPlan           []string
	Constraints              []string
	HasFailure               bool
}

func Build(req Request) (string, error) {
	data := templateData{
		RepoPath:                 req.RepoPath,
		AttemptNumber:            req.AttemptNumber,
		TaskKind:                 normalizeTaskKind(req.TaskKind),
		Goal:                     normalizeGoal(req.Goal),
		CurrentStateLabel:        normalizeCurrentStateLabel(req.CurrentStateLabel),
		CurrentState:             normalizeCurrentState(req.CurrentState),
		FailureStage:             strings.TrimSpace(req.FailureStage),
		FailureError:             strings.TrimSpace(req.FailureError),
		PreviousAttemptSummaries: normalizeList(req.PreviousAttemptSummaries, []string{"none"}),
		ValidationPlan:           normalizeList(req.ValidationPlan, defaultValidationCommands),
		Constraints:              normalizeList(req.Constraints, defaultConstraints),
	}
	data.HasFailure = data.FailureStage != "" || data.FailureError != ""

	defaultPrompt, err := renderPromptTemplate(promptTemplate, data)
	if err != nil {
		return "", fmt.Errorf("render default prompt template: %w", err)
	}

	promptText := defaultPrompt
	for index, prompt := range req.RemediationPrompts {
		rendered, err := renderUserRemediationPrompt(
			fmt.Sprintf("remediation_prompt_%d", index+1),
			strings.TrimSpace(prompt.Template),
			data,
			defaultPrompt,
			promptText,
		)
		if err != nil {
			return "", fmt.Errorf("render remediation prompt %d: %w", index+1, err)
		}
		switch prompt.Mode {
		case RemediationPromptModeReplace:
			promptText = rendered
		default:
			promptText = appendPromptText(promptText, rendered)
		}
	}
	return promptText, nil
}

func ValidateRemediationTemplate(templateText string) error {
	data := templateData{
		RepoPath:                 "/repo",
		AttemptNumber:            1,
		TaskKind:                 "fix_vulnerabilities",
		Goal:                     "Repair the repository with minimal changes and satisfy the validation plan.",
		CurrentStateLabel:        "Current state",
		CurrentState:             "{}",
		FailureStage:             "scan_baseline",
		FailureError:             "example failure",
		PreviousAttemptSummaries: []string{"none"},
		ValidationPlan:           append([]string(nil), defaultValidationCommands...),
		Constraints:              append([]string(nil), defaultConstraints...),
		HasFailure:               true,
	}
	defaultPrompt, err := renderPromptTemplate(promptTemplate, data)
	if err != nil {
		return fmt.Errorf("render default prompt template: %w", err)
	}
	_, err = renderUserRemediationPrompt("validation", strings.TrimSpace(templateText), data, defaultPrompt, defaultPrompt)
	if err != nil {
		return err
	}
	return nil
}

func renderPromptTemplate(tmpl *template.Template, data templateData) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderUserRemediationPrompt(name, templateText string, data templateData, defaultPrompt, promptSoFar string) (string, error) {
	tmpl, err := template.New(name).Option("missingkey=error").Parse(templateText)
	if err != nil {
		return "", err
	}
	context := map[string]any{
		"RepoPath":                 data.RepoPath,
		"AttemptNumber":            data.AttemptNumber,
		"TaskKind":                 data.TaskKind,
		"Goal":                     data.Goal,
		"CurrentStateLabel":        data.CurrentStateLabel,
		"CurrentState":             data.CurrentState,
		"FailureStage":             data.FailureStage,
		"FailureError":             data.FailureError,
		"HasFailure":               data.HasFailure,
		"PreviousAttemptSummaries": append([]string(nil), data.PreviousAttemptSummaries...),
		"ValidationPlan":           append([]string(nil), data.ValidationPlan...),
		"Constraints":              append([]string(nil), data.Constraints...),
		"DefaultPrompt":            defaultPrompt,
		"PromptSoFar":              promptSoFar,
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, context); err != nil {
		return "", err
	}
	return strings.TrimSpace(buf.String()), nil
}

func appendPromptText(existing, addition string) string {
	addition = strings.TrimSpace(addition)
	if addition == "" {
		return existing
	}
	if strings.TrimSpace(existing) == "" {
		return addition
	}
	return strings.TrimRight(existing, "\n") + "\n\n" + addition
}

func normalizeTaskKind(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "repository repair"
	}
	return trimmed
}

func normalizeGoal(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "Repair the repository with minimal changes and satisfy the validation plan."
	}
	return trimmed
}

func normalizeCurrentStateLabel(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "Current state"
	}
	return trimmed
}

func normalizeCurrentState(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "{}"
	}
	return trimmed
}

func normalizeList(values []string, fallback []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		cleaned = append(cleaned, value)
	}
	if len(cleaned) > 0 {
		return cleaned
	}
	return append([]string(nil), fallback...)
}
