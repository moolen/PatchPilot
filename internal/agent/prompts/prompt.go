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

func Build(req Request) string {
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

	var buf bytes.Buffer
	if err := promptTemplate.Execute(&buf, data); err != nil {
		panic(fmt.Sprintf("execute prompt template: %v", err))
	}
	return buf.String()
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
