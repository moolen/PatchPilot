package cmd

import (
	"errors"
	"fmt"
)

type ExitCode int

const (
	ExitCodeSuccess               ExitCode = 0
	ExitCodeGenericFailure        ExitCode = 1
	ExitCodeScanFailed            ExitCode = 20
	ExitCodePatchFailed           ExitCode = 21
	ExitCodeVerificationRegressed ExitCode = 22
	ExitCodeVulnsRemain           ExitCode = 23
)

type ExitError struct {
	Code ExitCode
	Err  error
}

func (errorWithCode *ExitError) Error() string {
	if errorWithCode == nil || errorWithCode.Err == nil {
		return ""
	}
	return errorWithCode.Err.Error()
}

func (errorWithCode *ExitError) Unwrap() error {
	if errorWithCode == nil {
		return nil
	}
	return errorWithCode.Err
}

func ExitCodeFromError(err error) int {
	if err == nil {
		return int(ExitCodeSuccess)
	}
	var errorWithCode *ExitError
	if errors.As(err, &errorWithCode) {
		return int(errorWithCode.Code)
	}
	return int(ExitCodeGenericFailure)
}

func wrapWithExitCode(code ExitCode, err error) error {
	if err == nil {
		return nil
	}
	var existing *ExitError
	if errors.As(err, &existing) {
		return err
	}
	return &ExitError{Code: code, Err: err}
}

func verificationRegressedError(regressions int) error {
	return &ExitError{
		Code: ExitCodeVerificationRegressed,
		Err:  fmt.Errorf("verification regressed: %d check(s) changed from passing to failing/timeout", regressions),
	}
}

func vulnsRemainError(remaining int) error {
	return &ExitError{
		Code: ExitCodeVulnsRemain,
		Err:  fmt.Errorf("vulnerabilities remain: %d", remaining),
	}
}
