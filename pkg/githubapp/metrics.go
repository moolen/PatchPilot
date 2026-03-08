package githubapp

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Metrics struct {
	mu sync.Mutex

	runsTotal     map[string]int64
	fixesTotal    map[string]int64
	failuresTotal map[string]int64

	runDurationCount int64
	runDurationSum   float64
}

func NewMetrics() *Metrics {
	return &Metrics{
		runsTotal:     map[string]int64{},
		fixesTotal:    map[string]int64{},
		failuresTotal: map[string]int64{},
	}
}

func (metrics *Metrics) IncRun(trigger, status string) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.runsTotal[labelKey(trigger, status)]++
}

func (metrics *Metrics) IncFix(outcome string) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.fixesTotal[outcome]++
}

func (metrics *Metrics) IncFailure(stage string) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.failuresTotal[stage]++
}

func (metrics *Metrics) ObserveRunDuration(duration time.Duration) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	metrics.runDurationCount++
	metrics.runDurationSum += duration.Seconds()
}

func (metrics *Metrics) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()

	builder := strings.Builder{}
	builder.WriteString("# HELP patchpilot_runs_total Total remediation runs by trigger and status.\n")
	builder.WriteString("# TYPE patchpilot_runs_total counter\n")
	for key, value := range metrics.runsTotal {
		trigger, status := splitLabelKey(key)
		builder.WriteString(fmt.Sprintf("patchpilot_runs_total{trigger=%q,status=%q} %d\n", trigger, status, value))
	}

	builder.WriteString("# HELP patchpilot_fixes_total Total remediation outcomes.\n")
	builder.WriteString("# TYPE patchpilot_fixes_total counter\n")
	for outcome, value := range metrics.fixesTotal {
		builder.WriteString(fmt.Sprintf("patchpilot_fixes_total{outcome=%q} %d\n", outcome, value))
	}

	builder.WriteString("# HELP patchpilot_failures_total Total remediation failures grouped by stage.\n")
	builder.WriteString("# TYPE patchpilot_failures_total counter\n")
	for stage, value := range metrics.failuresTotal {
		builder.WriteString(fmt.Sprintf("patchpilot_failures_total{stage=%q} %d\n", stage, value))
	}

	builder.WriteString("# HELP patchpilot_run_duration_seconds Duration of remediation runs in seconds.\n")
	builder.WriteString("# TYPE patchpilot_run_duration_seconds summary\n")
	builder.WriteString("patchpilot_run_duration_seconds_count " + strconv.FormatInt(metrics.runDurationCount, 10) + "\n")
	builder.WriteString("patchpilot_run_duration_seconds_sum " + strconv.FormatFloat(metrics.runDurationSum, 'f', 6, 64) + "\n")

	writer.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = writer.Write([]byte(builder.String()))
}

func labelKey(left, right string) string {
	return left + "|" + right
}

func splitLabelKey(value string) (string, string) {
	parts := strings.SplitN(value, "|", 2)
	if len(parts) != 2 {
		return value, ""
	}
	return parts[0], parts[1]
}
