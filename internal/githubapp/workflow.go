package githubapp

type fixRunResult struct {
	ExitCode        int
	Stdout          string
	Stderr          string
	Changed         bool
	Branch          string
	HeadSHA         string
	BlockedReason   string
	RiskScore       int
	ChangedFiles    []string
	RegressionCount int
}

const remediationPRTitle = "chore: automated CVE remediation"
