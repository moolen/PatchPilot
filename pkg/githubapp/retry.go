package githubapp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v75/github"
)

var sleepWithContextFunc = sleepWithContext

type httpStatusError struct {
	StatusCode int
	Header     http.Header
	Body       string
}

func (err *httpStatusError) Error() string {
	body := strings.TrimSpace(err.Body)
	if body == "" {
		return fmt.Sprintf("github http status %d", err.StatusCode)
	}
	return fmt.Sprintf("github http status %d: %s", err.StatusCode, body)
}

func (service *Service) withGitHubRetry(ctx context.Context, operation string, fn func(context.Context) error) error {
	maxAttempts := service.cfg.RetryMaxAttempts
	if maxAttempts <= 0 {
		maxAttempts = 1
	}
	initial := service.cfg.RetryInitialBackoff
	if initial <= 0 {
		initial = 2 * time.Second
	}
	maxBackoff := service.cfg.RetryMaxBackoff
	if maxBackoff < initial {
		maxBackoff = initial
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}

		delay, retryable := retryDelay(err, attempt, initial, maxBackoff)
		if !retryable || attempt == maxAttempts {
			if retryable {
				service.log("error", "github operation retry attempts exhausted", map[string]interface{}{
					"operation": operation,
					"attempts":  attempt,
					"error":     err.Error(),
				})
			}
			return err
		}

		service.log("warn", "retrying github operation", map[string]interface{}{
			"operation": operation,
			"attempt":   attempt,
			"delay_ms":  delay.Milliseconds(),
			"error":     err.Error(),
		})

		if service.metrics != nil {
			service.metrics.IncRun("github_api", "retry")
		}

		if sleepErr := sleepWithContextFunc(ctx, delay); sleepErr != nil {
			return sleepErr
		}
	}
	return fmt.Errorf("github operation %q failed", operation)
}

func retryDelay(err error, attempt int, initial, maxBackoff time.Duration) (time.Duration, bool) {
	if explicit, ok := explicitRetryDelay(err); ok {
		return clampRetryDelay(explicit, initial, 5*time.Minute), true
	}

	if retriableNetworkError(err) {
		return exponentialBackoff(attempt, initial, maxBackoff), true
	}

	var acceptedErr *github.AcceptedError
	if errors.As(err, &acceptedErr) {
		return exponentialBackoff(attempt, initial, maxBackoff), true
	}

	var errorResponse *github.ErrorResponse
	if errors.As(err, &errorResponse) {
		status := statusCodeFromResponse(errorResponse.Response)
		if delay, ok := retryAfterFromResponse(errorResponse.Response); ok {
			return clampRetryDelay(delay, initial, 5*time.Minute), true
		}
		if status == http.StatusTooManyRequests || status >= http.StatusInternalServerError {
			return exponentialBackoff(attempt, initial, maxBackoff), true
		}
		if status == http.StatusForbidden && containsSecondaryRateLimit(errorResponse.Message) {
			return exponentialBackoff(attempt, initial, maxBackoff), true
		}
		return 0, false
	}

	var statusErr *httpStatusError
	if errors.As(err, &statusErr) {
		if delay, ok := retryAfterFromHeader(statusErr.Header); ok {
			return clampRetryDelay(delay, initial, 5*time.Minute), true
		}
		if statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= http.StatusInternalServerError {
			return exponentialBackoff(attempt, initial, maxBackoff), true
		}
		if statusErr.StatusCode == http.StatusForbidden && containsSecondaryRateLimit(statusErr.Body) {
			return exponentialBackoff(attempt, initial, maxBackoff), true
		}
	}

	return 0, false
}

func explicitRetryDelay(err error) (time.Duration, bool) {
	var abuseRateLimit *github.AbuseRateLimitError
	if errors.As(err, &abuseRateLimit) {
		if abuseRateLimit.RetryAfter != nil && *abuseRateLimit.RetryAfter > 0 {
			return *abuseRateLimit.RetryAfter, true
		}
		if delay, ok := retryAfterFromResponse(abuseRateLimit.Response); ok {
			return delay, true
		}
		return 0, false
	}

	var rateLimit *github.RateLimitError
	if errors.As(err, &rateLimit) {
		if delay, ok := retryAfterFromResponse(rateLimit.Response); ok {
			return delay, true
		}
		if rateLimit.Rate.Reset.Time.After(time.Now().UTC()) {
			return time.Until(rateLimit.Rate.Reset.Time) + time.Second, true
		}
		return 0, false
	}

	return 0, false
}

func retryAfterFromResponse(response *http.Response) (time.Duration, bool) {
	if response == nil {
		return 0, false
	}
	return retryAfterFromHeader(response.Header)
}

func retryAfterFromHeader(header http.Header) (time.Duration, bool) {
	if header == nil {
		return 0, false
	}
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func containsSecondaryRateLimit(message string) bool {
	normalized := strings.ToLower(strings.TrimSpace(message))
	return strings.Contains(normalized, "secondary rate limit")
}

func retriableNetworkError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return netErr.Timeout() || netErr.Temporary()
	}
	return false
}

func exponentialBackoff(attempt int, initial, maxBackoff time.Duration) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	multiplier := math.Pow(2, float64(attempt-1))
	delay := time.Duration(float64(initial) * multiplier)
	return clampRetryDelay(delay, initial, maxBackoff)
}

func clampRetryDelay(delay, min, max time.Duration) time.Duration {
	if delay < min {
		return min
	}
	if max > 0 && delay > max {
		return max
	}
	return delay
}

func statusCodeFromResponse(response *http.Response) int {
	if response == nil {
		return 0
	}
	return response.StatusCode
}

func sleepWithContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
