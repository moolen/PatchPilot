package verifycheck

import (
	"fmt"
	"io"
	"sort"
)

func Compare(baseline, after Report) []Regression {
	baselineChecks := map[string]CheckResult{}
	for _, module := range baseline.Modules {
		for _, check := range module.Checks {
			baselineChecks[module.Dir+"|"+check.Name] = check
		}
	}

	regressions := make([]Regression, 0)
	for _, module := range after.Modules {
		for _, check := range module.Checks {
			key := module.Dir + "|" + check.Name
			before, ok := baselineChecks[key]
			if !ok || before.Status != StatusOK || check.Status == StatusOK {
				continue
			}
			regressions = append(regressions, Regression{
				Dir:            module.Dir,
				Check:          check.Name,
				BaselineStatus: before.Status,
				AfterStatus:    check.Status,
				BaselineError:  before.Error,
				AfterError:     check.Error,
			})
		}
	}
	sort.Slice(regressions, func(i, j int) bool {
		if regressions[i].Dir == regressions[j].Dir {
			return regressions[i].Check < regressions[j].Check
		}
		return regressions[i].Dir < regressions[j].Dir
	})
	return regressions
}

func Summarize(report Report) Summary {
	summary := Summary{Modules: len(report.Modules), Regressions: len(report.Regressions)}
	for _, module := range report.Modules {
		for _, check := range module.Checks {
			summary.Checks++
			switch check.Status {
			case StatusOK:
				summary.OK++
			case StatusTimeout:
				summary.Timeouts++
			default:
				summary.Failed++
			}
		}
	}
	return summary
}

func PrintSummary(w io.Writer, report Report) {
	summary := Summarize(report)
	_, _ = fmt.Fprintf(w, "Verification mode: %s\n", report.Mode)
	_, _ = fmt.Fprintf(w, "Modules checked: %d\n", summary.Modules)
	_, _ = fmt.Fprintf(w, "Checks run: %d\n", summary.Checks)
	_, _ = fmt.Fprintf(w, "Checks OK: %d\n", summary.OK)
	_, _ = fmt.Fprintf(w, "Checks failed: %d\n", summary.Failed)
	_, _ = fmt.Fprintf(w, "Checks timed out: %d\n", summary.Timeouts)
	_, _ = fmt.Fprintf(w, "Verification regressions: %d\n", summary.Regressions)
	if len(report.Regressions) > 0 {
		_, _ = fmt.Fprintln(w, "Verification regressions detail:")
		for _, regression := range report.Regressions {
			_, _ = fmt.Fprintf(w, "- %s [%s]: %s -> %s\n", regression.Dir, regression.Check, regression.BaselineStatus, regression.AfterStatus)
		}
	}
	printFailures(w, report)
}

func printFailures(w io.Writer, report Report) {
	printed := 0
	total := 0
	for _, module := range report.Modules {
		for _, check := range module.Checks {
			if check.Status == StatusOK {
				continue
			}
			total++
			if printed >= maxPrintedFailures {
				continue
			}
			_, _ = fmt.Fprintf(w, "- %s [%s] %s: %s\n", module.Dir, check.Name, check.Status, check.Error)
			printed++
		}
	}
	if total == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "Verification detail entries: %d\n", total)
	if total > printed {
		_, _ = fmt.Fprintf(w, "... %d more verification failures written to .patchpilot/verification.json\n", total-printed)
	}
}
