package githubapp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	agentpkg "github.com/moolen/patchpilot/internal/agent"
	"github.com/moolen/patchpilot/internal/policy"
)

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
