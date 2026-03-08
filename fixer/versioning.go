package fixer

import (
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

var versionTokenPattern = regexp.MustCompile(`[0-9A-Za-z][0-9A-Za-z+._-]*`)

func preferHigherVersion(current, candidate string) string {
	if strings.TrimSpace(current) == "" {
		return strings.TrimSpace(candidate)
	}
	if strings.TrimSpace(candidate) == "" {
		return strings.TrimSpace(current)
	}
	if compareLooseVersions(current, candidate) >= 0 {
		return strings.TrimSpace(current)
	}
	return strings.TrimSpace(candidate)
}

func compareLooseVersions(left, right string) int {
	leftToken := normalizeVersionToken(left)
	rightToken := normalizeVersionToken(right)
	if leftToken == "" && rightToken == "" {
		return 0
	}
	if leftToken == "" {
		return -1
	}
	if rightToken == "" {
		return 1
	}

	leftSemver := canonicalSemver(leftToken)
	rightSemver := canonicalSemver(rightToken)
	if leftSemver != "" && rightSemver != "" {
		return semver.Compare(leftSemver, rightSemver)
	}

	return compareDotSeparated(leftToken, rightToken)
}

func normalizeVersionToken(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	match := versionTokenPattern.FindString(input)
	return strings.TrimSpace(match)
}

func compareDotSeparated(left, right string) int {
	leftParts := splitVersionParts(left)
	rightParts := splitVersionParts(right)
	maxLen := len(leftParts)
	if len(rightParts) > maxLen {
		maxLen = len(rightParts)
	}
	for index := 0; index < maxLen; index++ {
		leftPart := ""
		if index < len(leftParts) {
			leftPart = leftParts[index]
		}
		rightPart := ""
		if index < len(rightParts) {
			rightPart = rightParts[index]
		}
		if leftPart == rightPart {
			continue
		}

		leftNumber, leftErr := strconv.Atoi(leftPart)
		rightNumber, rightErr := strconv.Atoi(rightPart)
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		default:
			if leftPart < rightPart {
				return -1
			}
			return 1
		}
	}
	return 0
}

func splitVersionParts(version string) []string {
	version = strings.TrimPrefix(version, "v")
	return strings.FieldsFunc(version, func(r rune) bool {
		switch r {
		case '.', '-', '_':
			return true
		default:
			return false
		}
	})
}
