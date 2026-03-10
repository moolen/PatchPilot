package githubapp

import (
	"path"
	"strings"
)

const (
	labelFilteredScheduleKey = "repository-label-filtered"
	labelIgnoredScheduleKey  = "repository-label-ignored"
)

func normalizeRepositoryLabels(labels []string) []string {
	if len(labels) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(labels))
	normalized := make([]string, 0, len(labels))
	for _, label := range labels {
		value := strings.ToLower(strings.TrimSpace(label))
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	if len(normalized) == 0 {
		return nil
	}
	return normalized
}

func repositoryMatchesLabelSelectors(labels, selectors []string) bool {
	if len(labels) == 0 || len(selectors) == 0 {
		return false
	}
	for _, selector := range selectors {
		if selector == "" {
			continue
		}
		for _, label := range labels {
			if labelSelectorMatches(label, selector) {
				return true
			}
		}
	}
	return false
}

func labelSelectorMatches(label, selector string) bool {
	label = strings.ToLower(strings.TrimSpace(label))
	selector = strings.ToLower(strings.TrimSpace(selector))
	if label == "" || selector == "" {
		return false
	}
	if !strings.ContainsAny(selector, "*?[") {
		return label == selector
	}
	matched, err := path.Match(selector, label)
	if err != nil {
		return false
	}
	return matched
}
