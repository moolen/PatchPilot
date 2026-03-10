package githubapp

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
)

func TestMetricsRefreshStateTracksSchedulerAndSecurityState(t *testing.T) {
	metrics := NewMetrics()
	now := time.Date(2026, time.March, 9, 20, 0, 0, 0, time.UTC)

	metrics.RefreshState(map[string]scheduledRepositoryState{
		"acme/one": {
			NextRunAt:        now.Add(-5 * time.Minute),
			LastFindingCount: 3,
			LastFindingsBySeverity: map[string]int{
				"critical": 2,
				"high":     1,
			},
			OpenPR: &trackedRemediationPRState{
				Number:    1,
				CreatedAt: now.Add(-2 * time.Hour),
			},
		},
		"acme/two": {
			NextRunAt:        now.Add(10 * time.Minute),
			LastFindingCount: 2,
			LastFindingsBySeverity: map[string]int{
				"medium": 1,
				"weird":  1,
			},
		},
	}, now)

	assertGaugeValue(t, metrics, "patchpilot_scheduler_due_repositories", nil, 1)
	assertGaugeValue(t, metrics, "patchpilot_scheduler_oldest_due_age_seconds", nil, 300)
	assertGaugeValue(t, metrics, "patchpilot_fixable_findings_total", nil, 5)
	assertGaugeValue(t, metrics, "patchpilot_fixable_findings_by_severity", map[string]string{"severity": "critical"}, 2)
	assertGaugeValue(t, metrics, "patchpilot_fixable_findings_by_severity", map[string]string{"severity": "high"}, 1)
	assertGaugeValue(t, metrics, "patchpilot_fixable_findings_by_severity", map[string]string{"severity": "medium"}, 1)
	assertGaugeValue(t, metrics, "patchpilot_fixable_findings_by_severity", map[string]string{"severity": "unknown"}, 1)
	assertGaugeValue(t, metrics, "patchpilot_repositories_with_findings", nil, 2)
	assertGaugeValue(t, metrics, "patchpilot_open_remediation_pull_requests", nil, 1)
	assertGaugeValue(t, metrics, "patchpilot_oldest_open_remediation_pull_request_age_seconds", nil, 7200)
}

func TestMetricsServeHTTPIncludesPrometheusOutput(t *testing.T) {
	metrics := NewMetrics()
	metrics.IncSchedulerCycle("started")
	metrics.RefreshState(map[string]scheduledRepositoryState{
		"acme/demo": {
			NextRunAt:        time.Now().UTC().Add(-time.Minute),
			LastFindingCount: 1,
		},
	}, time.Now().UTC())

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	recorder := httptest.NewRecorder()
	metrics.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("ServeHTTP status = %d, want %d", recorder.Code, http.StatusOK)
	}

	body := recorder.Body.String()
	for _, name := range []string{
		"patchpilot_scheduler_cycles_total",
		"patchpilot_scheduler_due_repositories",
		"patchpilot_fixable_findings_total",
	} {
		if !strings.Contains(body, name) {
			t.Fatalf("metrics output missing %s\n%s", name, body)
		}
	}
}

func TestWithGitHubRetryRecordsPrometheusMetrics(t *testing.T) {
	service := newRetryTestService()
	service.cfg.RetryMaxAttempts = 3
	service.cfg.RetryInitialBackoff = 100 * time.Millisecond
	service.cfg.RetryMaxBackoff = time.Second

	originalSleep := sleepWithContextFunc
	t.Cleanup(func() { sleepWithContextFunc = originalSleep })
	sleepWithContextFunc = func(ctx context.Context, duration time.Duration) error {
		return nil
	}

	attempts := 0
	err := service.withGitHubRetry(context.Background(), "test_secondary_rate_limit", func(ctx context.Context) error {
		attempts++
		if attempts == 1 {
			return &httpStatusError{
				StatusCode: http.StatusForbidden,
				Header:     http.Header{"Retry-After": []string{"2"}},
				Body:       "secondary rate limit",
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withGitHubRetry returned error: %v", err)
	}

	assertCounterValue(t, service.metrics, "patchpilot_github_api_requests_total", map[string]string{
		"operation": "test_secondary_rate_limit",
		"outcome":   "error",
	}, 1)
	assertCounterValue(t, service.metrics, "patchpilot_github_api_requests_total", map[string]string{
		"operation": "test_secondary_rate_limit",
		"outcome":   "success",
	}, 1)
	assertCounterValue(t, service.metrics, "patchpilot_github_api_retries_total", map[string]string{
		"operation": "test_secondary_rate_limit",
	}, 1)
	assertCounterValue(t, service.metrics, "patchpilot_github_api_rate_limit_total", map[string]string{
		"kind": "secondary",
	}, 1)
}

func assertGaugeValue(t *testing.T, metrics *Metrics, name string, labels map[string]string, want float64) {
	t.Helper()
	got := lookupMetric(t, metrics, name, labels).GetGauge().GetValue()
	if math.Abs(got-want) > 0.000001 {
		t.Fatalf("%s gauge = %v, want %v", name, got, want)
	}
}

func assertCounterValue(t *testing.T, metrics *Metrics, name string, labels map[string]string, want float64) {
	t.Helper()
	got := lookupMetric(t, metrics, name, labels).GetCounter().GetValue()
	if math.Abs(got-want) > 0.000001 {
		t.Fatalf("%s counter = %v, want %v", name, got, want)
	}
}

func assertHistogramCount(t *testing.T, metrics *Metrics, name string, labels map[string]string, want uint64) {
	t.Helper()
	got := lookupMetric(t, metrics, name, labels).GetHistogram().GetSampleCount()
	if got != want {
		t.Fatalf("%s histogram count = %d, want %d", name, got, want)
	}
}

func lookupMetric(t *testing.T, metrics *Metrics, name string, labels map[string]string) *dto.Metric {
	t.Helper()

	families, err := metrics.registry.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.GetMetric() {
			if metricLabelsMatch(metric, labels) {
				return metric
			}
		}
	}

	t.Fatalf("metric %s with labels %v not found", name, labels)
	return nil
}

func metricLabelsMatch(metric *dto.Metric, labels map[string]string) bool {
	if len(labels) == 0 {
		return len(metric.GetLabel()) == 0
	}
	if len(metric.GetLabel()) != len(labels) {
		return false
	}
	for _, label := range metric.GetLabel() {
		value, ok := labels[label.GetName()]
		if !ok || value != label.GetValue() {
			return false
		}
	}
	return true
}
