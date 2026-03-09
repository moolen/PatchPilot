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

//go:embed prompt.tmpl
var promptTemplateText string

var promptTemplate = template.Must(template.New("prompt.tmpl").Parse(promptTemplateText))

type Request struct {
	RepoPath                 string
	AttemptNumber            int
	RemainingVulnerabilities string
	PreviousAttemptSummaries []string
	ValidationCommands       []string
	PromptFilePath           string
}

type templateData struct {
	RepoPath                 string
	AttemptNumber            int
	RemainingVulnerabilities string
	PreviousAttemptSummaries []string
	ValidationCommands       []string
	PromptFilePath           string
	HasPromptFilePath        bool
}

func Build(req Request) string {
	data := templateData{
		RepoPath:                 req.RepoPath,
		AttemptNumber:            req.AttemptNumber,
		RemainingVulnerabilities: normalizeRemainingVulnerabilities(req.RemainingVulnerabilities),
		PreviousAttemptSummaries: normalizeList(req.PreviousAttemptSummaries, []string{"none"}),
		ValidationCommands:       normalizeList(req.ValidationCommands, defaultValidationCommands),
		PromptFilePath:           strings.TrimSpace(req.PromptFilePath),
	}
	data.HasPromptFilePath = data.PromptFilePath != ""

	var buf bytes.Buffer
	if err := promptTemplate.Execute(&buf, data); err != nil {
		panic(fmt.Sprintf("execute prompt template: %v", err))
	}
	return buf.String()
}

func normalizeRemainingVulnerabilities(raw string) string {
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
