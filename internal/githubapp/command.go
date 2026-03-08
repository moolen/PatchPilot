package githubapp

import (
	"fmt"
	"strings"
)

type FixCommand struct {
	PolicyPath string
	PolicyMode string
	AutoMerge  bool
}

func ParseFixCommand(body string) (FixCommand, bool, error) {
	for _, line := range strings.Split(body, "\n") {
		text := strings.TrimSpace(line)
		if text == "" {
			continue
		}

		tokens := strings.Fields(text)
		if len(tokens) < 2 {
			continue
		}
		if tokens[0] != "/cvefix" && tokens[0] != "/patchpilot" {
			continue
		}
		if tokens[1] != "fix" {
			continue
		}

		command := FixCommand{}
		for index := 2; index < len(tokens); index++ {
			switch tokens[index] {
			case "--policy":
				index++
				if index >= len(tokens) {
					return FixCommand{}, true, fmt.Errorf("--policy requires a path value")
				}
				command.PolicyPath = strings.TrimSpace(tokens[index])
				if command.PolicyPath == "" {
					return FixCommand{}, true, fmt.Errorf("--policy requires a non-empty path value")
				}
			case "--policy-mode":
				index++
				if index >= len(tokens) {
					return FixCommand{}, true, fmt.Errorf("--policy-mode requires a value")
				}
				command.PolicyMode = strings.ToLower(strings.TrimSpace(tokens[index]))
				switch command.PolicyMode {
				case "merge", "override":
				default:
					return FixCommand{}, true, fmt.Errorf("--policy-mode must be merge or override")
				}
			case "--auto-merge":
				command.AutoMerge = true
			case "--no-auto-merge":
				command.AutoMerge = false
			default:
				return FixCommand{}, true, fmt.Errorf("unknown option %q", tokens[index])
			}
		}

		return command, true, nil
	}

	return FixCommand{}, false, nil
}
