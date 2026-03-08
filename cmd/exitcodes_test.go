package cmd

import (
	"errors"
	"testing"
)

func TestExitCodeFromError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected int
	}{
		{name: "nil error", err: nil, expected: int(ExitCodeSuccess)},
		{name: "generic error", err: errors.New("boom"), expected: int(ExitCodeGenericFailure)},
		{name: "scan code", err: wrapWithExitCode(ExitCodeScanFailed, errors.New("scan failed")), expected: int(ExitCodeScanFailed)},
		{name: "patch code", err: wrapWithExitCode(ExitCodePatchFailed, errors.New("patch failed")), expected: int(ExitCodePatchFailed)},
		{name: "verification code", err: verificationRegressedError(2), expected: int(ExitCodeVerificationRegressed)},
		{name: "vulns remain code", err: vulnsRemainError(5), expected: int(ExitCodeVulnsRemain)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := ExitCodeFromError(test.err)
			if got != test.expected {
				t.Fatalf("expected exit code %d, got %d", test.expected, got)
			}
		})
	}
}

func TestWrapWithExitCodePreservesExistingCode(t *testing.T) {
	original := verificationRegressedError(1)
	wrapped := wrapWithExitCode(ExitCodeScanFailed, original)
	if ExitCodeFromError(wrapped) != int(ExitCodeVerificationRegressed) {
		t.Fatalf("expected existing exit code to be preserved, got %d", ExitCodeFromError(wrapped))
	}
}

func TestExitErrorErrorAndUnwrap(t *testing.T) {
	root := errors.New("root cause")
	wrapped := &ExitError{Code: ExitCodePatchFailed, Err: root}

	if got := wrapped.Error(); got != "root cause" {
		t.Fatalf("unexpected Error() string: %q", got)
	}
	if unwrapped := wrapped.Unwrap(); !errors.Is(unwrapped, root) {
		t.Fatalf("expected Unwrap() to return the wrapped error")
	}

	empty := &ExitError{}
	if got := empty.Error(); got != "" {
		t.Fatalf("expected empty error string, got %q", got)
	}
	if empty.Unwrap() != nil {
		t.Fatalf("expected nil unwrap for empty error")
	}
}
