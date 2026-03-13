package githubapp

import "strings"

func appendPatchPilotPolicyArgs(args []string, cfg Config) []string {
	path := strings.TrimSpace(cfg.PatchPilotPolicyPath)
	if path == "" {
		return args
	}
	mode := strings.TrimSpace(cfg.PatchPilotPolicyMode)
	if mode == "" {
		mode = "merge"
	}
	return append(args, "--policy", path, "--policy-mode", mode)
}
