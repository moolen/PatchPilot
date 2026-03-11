package fixer

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
)

type compiledBaseImageRule struct {
	tagSets []compiledBaseImageTagSet
	deny    []*regexp.Regexp
}

type compiledBaseImageTagSet struct {
	allow       []*regexp.Regexp
	constraints []semverConstraint
}

type semverConstraint struct {
	operator string
	version  string
}

func findMatchingBaseImageRule(repo string, rules []BaseImageRule) (BaseImageRule, bool) {
	repo = normalizeRuleImageRepository(repo)
	for _, rule := range rules {
		if normalizeRuleImageRepository(rule.Image) == repo {
			return rule, true
		}
	}
	return BaseImageRule{}, false
}

func resolveRuleDrivenImageTag(ctx context.Context, image string, rule BaseImageRule) string {
	ref, ok := parseImageReference(image)
	if !ok {
		return ""
	}
	currentVersion, ok := extractImageTagSemver(ref.Tag)
	if !ok {
		return ""
	}
	compiled, ok := compileBaseImageRule(rule)
	if !ok {
		return ""
	}
	tags, err := listRegistryTags(ctx, ref)
	if err != nil {
		return ""
	}

	bestTag := ""
	bestVersion := ""
	for _, tag := range tags {
		version, ok := extractImageTagSemver(tag)
		if !ok {
			continue
		}
		if semver.Compare(version, currentVersion) <= 0 {
			continue
		}
		if !compiled.matches(tag, version) {
			continue
		}
		if bestVersion == "" || semver.Compare(version, bestVersion) > 0 || (semver.Compare(version, bestVersion) == 0 && tag > bestTag) {
			bestTag = tag
			bestVersion = version
		}
	}
	return bestTag
}

func compileBaseImageRule(rule BaseImageRule) (compiledBaseImageRule, bool) {
	compiled := compiledBaseImageRule{
		tagSets: make([]compiledBaseImageTagSet, 0, len(rule.TagSets)),
		deny:    make([]*regexp.Regexp, 0, len(rule.Deny)),
	}
	for _, pattern := range rule.Deny {
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			return compiledBaseImageRule{}, false
		}
		compiled.deny = append(compiled.deny, matcher)
	}
	for _, tagSet := range rule.TagSets {
		constraints, err := parseSemverRange(tagSet.SemverRange)
		if err != nil {
			return compiledBaseImageRule{}, false
		}
		compiledSet := compiledBaseImageTagSet{
			allow:       make([]*regexp.Regexp, 0, len(tagSet.Allow)),
			constraints: constraints,
		}
		for _, pattern := range tagSet.Allow {
			matcher, err := regexp.Compile(pattern)
			if err != nil {
				return compiledBaseImageRule{}, false
			}
			compiledSet.allow = append(compiledSet.allow, matcher)
		}
		compiled.tagSets = append(compiled.tagSets, compiledSet)
	}
	return compiled, true
}

func (rule compiledBaseImageRule) matches(tag, version string) bool {
	for _, deny := range rule.deny {
		if deny.MatchString(tag) {
			return false
		}
	}
	for _, tagSet := range rule.tagSets {
		if tagSet.matches(tag, version) {
			return true
		}
	}
	return false
}

func (tagSet compiledBaseImageTagSet) matches(tag, version string) bool {
	if len(tagSet.allow) > 0 {
		matched := false
		for _, allow := range tagSet.allow {
			if allow.MatchString(tag) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, constraint := range tagSet.constraints {
		comparison := semver.Compare(version, constraint.version)
		switch constraint.operator {
		case ">":
			if comparison <= 0 {
				return false
			}
		case ">=":
			if comparison < 0 {
				return false
			}
		case "<":
			if comparison >= 0 {
				return false
			}
		case "<=":
			if comparison > 0 {
				return false
			}
		case "=":
			if comparison != 0 {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func parseSemverRange(raw string) ([]semverConstraint, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	constraints := make([]semverConstraint, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		operator := "="
		version := field
		for _, prefix := range []string{">=", "<=", ">", "<", "="} {
			if strings.HasPrefix(field, prefix) {
				operator = prefix
				version = strings.TrimSpace(strings.TrimPrefix(field, prefix))
				break
			}
		}
		canonical := canonicalRangeSemver(version)
		if canonical == "" {
			return nil, strconv.ErrSyntax
		}
		constraints = append(constraints, semverConstraint{
			operator: operator,
			version:  canonical,
		})
	}
	return constraints, nil
}

func canonicalRangeSemver(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	version = strings.TrimPrefix(version, "v")
	parts := strings.SplitN(version, "+", 2)
	version = parts[0]

	prerelease := ""
	if dash := strings.Index(version, "-"); dash != -1 {
		prerelease = version[dash:]
		version = version[:dash]
	}
	segments := strings.Split(version, ".")
	if len(segments) < 2 || len(segments) > 3 {
		return ""
	}
	for _, segment := range segments {
		if segment == "" {
			return ""
		}
		if _, err := strconv.Atoi(segment); err != nil {
			return ""
		}
	}
	for len(segments) < 3 {
		segments = append(segments, "0")
	}
	canonical := "v" + strings.Join(segments, ".") + prerelease
	if !semver.IsValid(canonical) {
		return ""
	}
	return canonical
}

func extractImageTagSemver(tag string) (string, bool) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", false
	}
	tag = strings.TrimPrefix(tag, "v")
	segments := make([]string, 0, 3)
	index := 0
	for len(segments) < 3 {
		start := index
		for index < len(tag) && tag[index] >= '0' && tag[index] <= '9' {
			index++
		}
		if start == index {
			break
		}
		segments = append(segments, tag[start:index])
		if len(segments) == 3 || index >= len(tag) || tag[index] != '.' {
			break
		}
		index++
	}
	if len(segments) < 2 {
		return "", false
	}
	for len(segments) < 3 {
		segments = append(segments, "0")
	}
	rest := tag[index:]
	canonical := "v" + strings.Join(segments, ".")
	if strings.HasPrefix(rest, "-") {
		candidate := rest[1:]
		if next := strings.Index(candidate, "-"); next != -1 {
			candidate = candidate[:next]
		}
		if isLikelyPrerelease(candidate) {
			canonical += "-" + candidate
		}
	}
	if !semver.IsValid(canonical) {
		return "", false
	}
	return canonical, true
}

func isLikelyPrerelease(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	switch {
	case value == "":
		return false
	case strings.HasPrefix(value, "alpha"):
		return true
	case strings.HasPrefix(value, "beta"):
		return true
	case strings.HasPrefix(value, "rc"):
		return true
	case strings.HasPrefix(value, "pre"):
		return true
	case strings.HasPrefix(value, "preview"):
		return true
	case strings.HasPrefix(value, "dev"):
		return true
	default:
		return false
	}
}

func normalizeRuleImageRepository(image string) string {
	image, _ = splitImageDigest(image)
	repo, tag := splitImageRef(image)
	if tag == "" {
		return repo
	}
	return repo
}
