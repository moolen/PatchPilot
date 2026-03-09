package githubapp

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/moolen/patchpilot/internal/report"
	"github.com/moolen/patchpilot/internal/verifycheck"
)

type SafetyAssessment struct {
	Blocked                  bool
	Reason                   string
	RiskScore                int
	VerificationRegressions  int
	RemainingVulnerabilities int
	ChangedFiles             []string
}

func (service *Service) evaluateSafety(repoPath string, changedFiles []string) (SafetyAssessment, error) {
	assessment := SafetyAssessment{ChangedFiles: append([]string(nil), changedFiles...)}

	for _, changed := range changedFiles {
		if pathBlocked(changed, service.cfg.DisallowedPaths) {
			assessment.Blocked = true
			assessment.Reason = fmt.Sprintf("changed path %q is blocked by PP_DISALLOWED_PATHS", changed)
			return assessment, nil
		}
	}

	summaryPath := filepath.Join(repoPath, ".patchpilot", "summary.json")
	if data, err := os.ReadFile(summaryPath); err == nil {
		var summary report.Summary
		if unmarshalErr := json.Unmarshal(data, &summary); unmarshalErr == nil {
			assessment.RemainingVulnerabilities = summary.After
			assessment.RiskScore += summary.After
			assessment.RiskScore += len(changedFiles) / 3
		}
	}

	verificationPath := filepath.Join(repoPath, ".patchpilot", "verification.json")
	if data, err := os.ReadFile(verificationPath); err == nil {
		var verification verifycheck.Report
		if unmarshalErr := json.Unmarshal(data, &verification); unmarshalErr == nil {
			assessment.VerificationRegressions = len(verification.Regressions)
			if len(verification.Regressions) > 0 {
				assessment.Blocked = true
				assessment.Reason = fmt.Sprintf("verification regressions detected: %d", len(verification.Regressions))
				return assessment, nil
			}
			summary := verifycheck.Summarize(verification)
			assessment.RiskScore += summary.Failed + summary.Timeouts
		}
	}

	if assessment.RiskScore > service.cfg.MaxRiskScore {
		assessment.Blocked = true
		assessment.Reason = fmt.Sprintf("risk score %d exceeds max %d", assessment.RiskScore, service.cfg.MaxRiskScore)
	}
	return assessment, nil
}

func pathBlocked(changedPath string, patterns []string) bool {
	normalized := filepath.ToSlash(strings.TrimSpace(changedPath))
	if normalized == "" {
		return false
	}
	for _, pattern := range patterns {
		matcher := filepath.ToSlash(strings.TrimSpace(pattern))
		if matcher == "" {
			continue
		}
		if strings.HasSuffix(matcher, "/**") {
			prefix := strings.TrimSuffix(matcher, "/**")
			if normalized == prefix || strings.HasPrefix(normalized, prefix+"/") {
				return true
			}
			continue
		}
		if ok, _ := path.Match(matcher, normalized); ok {
			return true
		}
		if normalized == matcher {
			return true
		}
	}
	return false
}
