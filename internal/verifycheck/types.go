package verifycheck

import (
	"context"
	"regexp"
	"time"
)

const (
	ModeStandard       = "standard"
	ModeAppend         = "append"
	ModeReplace        = "replace"
	checkTimeout       = 5 * time.Minute
	maxPrintedFailures = 12
)

type Status string

const (
	StatusOK      Status = "ok"
	StatusFailed  Status = "failed"
	StatusTimeout Status = "timeout"
)

type CheckResult struct {
	Name           string `json:"name"`
	Status         Status `json:"status"`
	DurationMillis int64  `json:"duration_millis"`
	Error          string `json:"error,omitempty"`
}

type ModuleResult struct {
	Dir    string        `json:"dir"`
	Checks []CheckResult `json:"checks"`
}

type Regression struct {
	Dir            string `json:"dir"`
	Check          string `json:"check"`
	BaselineStatus Status `json:"baseline_status"`
	AfterStatus    Status `json:"after_status"`
	BaselineError  string `json:"baseline_error,omitempty"`
	AfterError     string `json:"after_error,omitempty"`
}

type Report struct {
	Mode        string         `json:"mode"`
	Modules     []ModuleResult `json:"modules"`
	Regressions []Regression   `json:"regressions,omitempty"`
}

type Summary struct {
	Modules     int
	Checks      int
	OK          int
	Failed      int
	Timeouts    int
	Regressions int
}

var runGoCheckFunc = runGoCheck
var runShellCheckFunc = runShellCheck

type DiscoverOptions struct {
	SkipPaths []string
}

type CommandSpec struct {
	Name    string
	Command string
	Timeout time.Duration
}

type standardCheck struct {
	Name string
	Args []string
}

type checkDefinition struct {
	Name     string
	GoArgs   []string
	Command  string
	Internal func(ctx context.Context, dir string) error
	Timeout  time.Duration
}

var standardChecks = []standardCheck{
	{Name: "build", Args: []string{"build", "./..."}},
	{Name: "compile-tests", Args: []string{"test", "-run", "^$", "./..."}},
	{Name: "vet", Args: []string{"vet", "./..."}},
}

var requirementsVerifyLinePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+(\[[A-Za-z0-9_,.-]+\])?(\s*[<>=!~]{1,2}\s*[^\s#;]+)?(\s*;.*)?$`)
