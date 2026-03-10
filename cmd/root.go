package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/moolen/patchpilot/internal/policy"
	"github.com/spf13/cobra"
)

type cliOptions struct {
	dir                 string
	repoURL             string
	policyPath          string
	policyMode          string
	untrustedRepoPolicy bool
	jsonOutput          bool
	enableAgent         bool
	agentCommand        string
	agentMaxAttempts    int
	agentArtifactDir    string
}

var (
	cloneRepoFunc = cloneRepo
	makeTempDir   = os.MkdirTemp
)

func Execute(args []string) error {
	command := NewRootCommand()
	command.SetArgs(args)
	return command.Execute()
}

func NewRootCommand() *cobra.Command {
	options := &cliOptions{}

	root := &cobra.Command{
		Use:           "patchpilot",
		Short:         "Fix vulnerabilities in source repositories with minimal version bumps",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().StringVar(&options.dir, "dir", "", "Directory to use as the working repository")
	root.PersistentFlags().StringVar(&options.repoURL, "repo-url", "", "Git URL to clone into a temporary directory and use as the working repository")
	root.PersistentFlags().StringVar(&options.policyPath, "policy", "", "Path to central policy file merged with in-repo .patchpilot.yaml")
	root.PersistentFlags().StringVar(&options.policyMode, "policy-mode", "merge", "Policy layering mode when --policy is set (merge|override)")
	root.PersistentFlags().BoolVar(&options.untrustedRepoPolicy, "untrusted-repo-policy", false, "Treat repo-local .patchpilot.yaml as untrusted and ignore executable or secret-sensitive sections")
	root.PersistentFlags().BoolVar(&options.jsonOutput, "json", false, "Emit structured JSON progress logs")
	_ = root.PersistentFlags().MarkHidden("untrusted-repo-policy")

	root.AddCommand(
		newScanCommand(options),
		newFixCommand(options),
		newVerifyCommand(options),
		newSchemaCommand(),
	)

	return root
}

func newScanCommand(options *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "scan [repo]",
		Short: "Generate SBOM and scan for vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			repo, err := resolveRepo(command, options, args)
			if err != nil {
				return err
			}
			cfg, err := loadPolicyConfig(repo, options)
			if err != nil {
				return err
			}
			return runScan(command.Context(), repo, cfg, options.jsonOutput)
		},
	}
}

func newFixCommand(options *cliOptions) *cobra.Command {
	command := &cobra.Command{
		Use:   "fix [repo]",
		Short: "Apply minimal dependency fixes for detected vulnerabilities",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			repo, err := resolveRepo(command, options, args)
			if err != nil {
				return err
			}
			cfg, err := loadPolicyConfig(repo, options)
			if err != nil {
				return err
			}
			return runFix(command.Context(), repo, cfg, fixOptions{
				EnableAgent:      options.enableAgent,
				AgentCommand:     options.agentCommand,
				AgentMaxAttempts: options.agentMaxAttempts,
				AgentArtifactDir: options.agentArtifactDir,
				UntrustedRepo:    options.untrustedRepoPolicy,
				JSONOutput:       options.jsonOutput,
			})
		},
	}

	command.Flags().BoolVar(&options.enableAgent, "enable-agent", true, "Enable external agent repair loop when deterministic fixes fail")
	command.Flags().StringVar(&options.agentCommand, "agent-command", "codex exec --skip-git-repo-check --sandbox workspace-write -o \"$PATCHPILOT_AGENT_ARTIFACT_DIR/last-message.txt\" - < \"$PATCHPILOT_PROMPT_FILE\"", "External agent harness command (must run non-interactively)")
	command.Flags().IntVar(&options.agentMaxAttempts, "agent-max-attempts", 5, "Maximum number of external agent repair attempts")
	command.Flags().StringVar(&options.agentArtifactDir, "agent-artifact-dir", "", "Directory for agent attempt artifacts (default: <repo>/.patchpilot/agent state directory)")

	return command
}

func newVerifyCommand(options *cliOptions) *cobra.Command {
	return &cobra.Command{
		Use:   "verify [repo]",
		Short: "Re-run scan and verification checks against saved baselines",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			repo, err := resolveRepo(command, options, args)
			if err != nil {
				return err
			}
			cfg, err := loadPolicyConfig(repo, options)
			if err != nil {
				return err
			}
			return runVerify(command.Context(), repo, cfg, options.jsonOutput)
		},
	}
}

func resolveRepo(command *cobra.Command, options *cliOptions, args []string) (string, error) {
	if options.dir != "" && options.repoURL != "" {
		return "", errors.New("flags --dir and --repo-url are mutually exclusive")
	}

	if options.repoURL != "" {
		return cloneRepoToTemp(command.Context(), command.ErrOrStderr(), options.repoURL)
	}

	repo := options.dir
	if repo == "" && len(args) > 0 {
		repo = args[0]
	}
	if repo == "" {
		repo = "."
	}

	absRepo, err := filepath.Abs(repo)
	if err != nil {
		return "", fmt.Errorf("resolve repo path: %w", err)
	}
	return absRepo, nil
}

func cloneRepoToTemp(ctx context.Context, writer io.Writer, repoURL string) (string, error) {
	tempRoot, err := makeTempDir("", "patchpilot-clone-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	target := filepath.Join(tempRoot, "repo")
	if err := cloneRepoFunc(ctx, writer, repoURL, target); err != nil {
		return "", err
	}

	absTarget, err := filepath.Abs(target)
	if err != nil {
		return "", fmt.Errorf("resolve cloned repo path: %w", err)
	}
	_, _ = fmt.Fprintf(writer, "Cloned %s to %s\n", repoURL, absTarget)
	return absTarget, nil
}

func cloneRepo(ctx context.Context, writer io.Writer, repoURL, target string) error {
	if strings.TrimSpace(repoURL) == "" {
		return errors.New("repo URL cannot be empty")
	}
	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("required tool %q not found in PATH", "git")
	}

	command := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, target)
	command.Stdout = writer
	command.Stderr = writer
	if err := command.Run(); err != nil {
		return fmt.Errorf("clone repo %q: %w", repoURL, err)
	}
	return nil
}

func loadPolicyConfig(repo string, options *cliOptions) (*policy.Config, error) {
	return policy.LoadWithOptions(repo, policy.LoadOptions{
		CentralPath:   options.policyPath,
		Mode:          options.policyMode,
		UntrustedRepo: options.untrustedRepoPolicy,
	})
}
