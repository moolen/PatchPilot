package githubapp

import (
	"context"
	"io"
	"log"
	"net/http"
	"testing"
	"time"

	"github.com/google/go-github/v75/github"
)

func TestWithGitHubRetryRetriesSecondaryRateLimit(t *testing.T) {
	service := newRetryTestService()
	service.cfg.RetryMaxAttempts = 3
	service.cfg.RetryInitialBackoff = 100 * time.Millisecond
	service.cfg.RetryMaxBackoff = time.Second

	originalSleep := sleepWithContextFunc
	t.Cleanup(func() { sleepWithContextFunc = originalSleep })
	delays := make([]time.Duration, 0)
	sleepWithContextFunc = func(ctx context.Context, duration time.Duration) error {
		delays = append(delays, duration)
		return nil
	}

	attempts := 0
	err := service.withGitHubRetry(context.Background(), "test_secondary_rate_limit", func(ctx context.Context) error {
		attempts++
		if attempts == 1 {
			return &github.ErrorResponse{
				Message: "You have exceeded a secondary rate limit. Please wait.",
				Response: &http.Response{
					StatusCode: http.StatusForbidden,
					Header:     http.Header{"Retry-After": []string{"2"}},
				},
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withGitHubRetry returned error: %v", err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if len(delays) != 1 || delays[0] != 2*time.Second {
		t.Fatalf("unexpected retry delays: %#v", delays)
	}
}

func TestWithGitHubRetryStopsOnNonRetriable(t *testing.T) {
	service := newRetryTestService()
	service.cfg.RetryMaxAttempts = 3

	originalSleep := sleepWithContextFunc
	t.Cleanup(func() { sleepWithContextFunc = originalSleep })
	sleepWithContextFunc = func(ctx context.Context, duration time.Duration) error {
		t.Fatalf("sleep should not be called for non-retriable errors")
		return nil
	}

	attempts := 0
	expectedErr := &github.ErrorResponse{
		Message: "validation failed",
		Response: &http.Response{
			StatusCode: http.StatusUnprocessableEntity,
		},
	}
	err := service.withGitHubRetry(context.Background(), "test_non_retriable", func(ctx context.Context) error {
		attempts++
		return expectedErr
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1", attempts)
	}
}

func TestWithGitHubRetryRetriesHttpStatusError(t *testing.T) {
	service := newRetryTestService()
	service.cfg.RetryMaxAttempts = 3
	service.cfg.RetryInitialBackoff = 200 * time.Millisecond
	service.cfg.RetryMaxBackoff = 2 * time.Second

	originalSleep := sleepWithContextFunc
	t.Cleanup(func() { sleepWithContextFunc = originalSleep })
	sleepWithContextFunc = func(ctx context.Context, duration time.Duration) error { return nil }

	attempts := 0
	err := service.withGitHubRetry(context.Background(), "test_http_status", func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return &httpStatusError{StatusCode: http.StatusServiceUnavailable}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("withGitHubRetry returned error: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
}

func TestIssueCommentRunKeyUsesCommentID(t *testing.T) {
	event := &github.IssueCommentEvent{
		Comment: &github.IssueComment{
			ID:   github.Ptr(int64(77)),
			Body: github.Ptr("/cvefix fix"),
		},
		Issue: &github.Issue{Number: github.Ptr(9)},
		Repo:  &github.Repository{FullName: github.Ptr("Acme/Demo")},
	}
	command := FixCommand{}
	key := issueCommentRunKey(event, command, "delivery-1")
	if key != "issue_comment:acme/demo:9:77" {
		t.Fatalf("unexpected run key: %q", key)
	}
}

func TestIssueCommentRunKeyFallbackDiffersByDelivery(t *testing.T) {
	event := &github.IssueCommentEvent{
		Comment: &github.IssueComment{Body: github.Ptr("/cvefix fix")},
		Issue:   &github.Issue{Number: github.Ptr(9)},
		Repo:    &github.Repository{FullName: github.Ptr("acme/demo")},
		Sender:  &github.User{Login: github.Ptr("alice")},
	}
	command := FixCommand{PolicyPath: ".patchpilot.yaml", AutoMerge: true}
	left := issueCommentRunKey(event, command, "delivery-1")
	right := issueCommentRunKey(event, command, "delivery-2")
	if left == right {
		t.Fatalf("expected fallback run keys to differ by delivery")
	}
}

func newRetryTestService() *Service {
	logger := log.New(io.Discard, "", 0)
	return &Service{
		cfg: Config{
			RetryMaxAttempts:    3,
			RetryInitialBackoff: time.Second,
			RetryMaxBackoff:     5 * time.Second,
		},
		logger:  logger,
		slog:    newStructuredLogger(logger),
		metrics: NewMetrics(),
	}
}
