package fixer

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"os"
	"fmt"

	"github.com/bmatcuk/doublestar/v4"
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

type OCIImagePolicy struct {
	Name   string
	Source string
	Tags   OCIImageTagPolicy
}

type OCIImageTagPolicy struct {
	Allow  []string
	Semver []OCIImageSemverPolicy
	Deny   []string
}

type OCIImageSemverPolicy struct {
	Range             []string
	IncludePrerelease bool
	PrereleaseAllow   []string
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

func resolveOCIBaseImageTag(ctx context.Context, image string, policies []OCIImagePolicy) (string, string) {
	ref, ok := parseImageReference(image)
	if !ok {
		return "", ""
	}
	source := ref.OriginalRepository
	matches := matchingOCIPolicies(source, policies)
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, policy := range matches {
			name := strings.TrimSpace(policy.Name)
			if name == "" {
				name = strings.TrimSpace(policy.Source)
			}
			names = append(names, name)
		}
		logOCIDecision("warning: multiple OCI policies matched source=%q, using first match: %s", source, strings.Join(names, ", "))
	}
	var selected *OCIImagePolicy
	if len(matches) > 0 {
		selected = &matches[0]
		logOCIDecision("from=%q selected OCI policy=%q source_pattern=%q", image, strings.TrimSpace(selected.Name), strings.TrimSpace(selected.Source))
	} else {
		logOCIDecision("from=%q no OCI policy matched source=%q, applying default latest-semver behavior", image, source)
	}

	tags, err := listRegistryTags(ctx, ref)
	if err != nil {
		logOCIDecision("from=%q tag lookup failed for %s/%s: %v", image, ref.Registry, ref.Repository, err)
		return "", ""
	}
	logOCIDecision("from=%q discovered %d tags for source=%q", image, len(tags), source)
	if len(tags) > 0 {
		logOCIDecision("from=%q tags=%s", image, strings.Join(tags, ","))
	}

	if selected == nil {
		tag := selectLatestSemverTagByDefault(ref.Tag, tags)
		return tag, source
	}
	tag := selectLatestSemverTagByPolicy(ref.Tag, tags, *selected)
	return tag, source
}

func matchingOCIPolicies(source string, policies []OCIImagePolicy) []OCIImagePolicy {
	source = strings.TrimSpace(source)
	result := make([]OCIImagePolicy, 0)
	for _, policy := range policies {
		pattern := strings.TrimSpace(policy.Source)
		if pattern == "" {
			continue
		}
		matched, err := doublestar.PathMatch(pattern, source)
		if err != nil {
			logOCIDecision("warning: invalid OCI source pattern=%q: %v", pattern, err)
			continue
		}
		if matched {
			result = append(result, policy)
		}
	}
	return result
}

func selectLatestSemverTagByDefault(currentTag string, tags []string) string {
	candidates := make([]tagCandidate, 0, len(tags))
	_, currentSuffix := splitTagSuffix(currentTag)
	for _, tag := range tags {
		core, suffix := splitTagSuffix(tag)
		version, ok := extractImageTagSemver(core)
		if !ok {
			continue
		}
		// Default guardrail: when current tag has a suffix family, require exact suffix matching.
		if strings.TrimSpace(currentSuffix) != "" && suffix != currentSuffix {
			continue
		}
		candidates = append(candidates, tagCandidate{Tag: tag, Version: version})
	}
	logOCIDecision("default-filter current_tag=%q semver_candidates=%d", currentTag, len(candidates))
	return bestTagCandidate(candidates)
}

func selectLatestSemverTagByPolicy(currentTag string, tags []string, policy OCIImagePolicy) string {
	allowMatchers := compileRegexps(policy.Tags.Allow)
	denyMatchers := compileRegexps(policy.Tags.Deny)

	stageAllow := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(allowMatchers) == 0 {
			stageAllow = append(stageAllow, tag)
			continue
		}
		if matchesAnyRegexp(allowMatchers, tag) {
			stageAllow = append(stageAllow, tag)
		}
	}

	stageSemver := make([]tagCandidate, 0, len(stageAllow))
	for _, tag := range stageAllow {
		core, _ := splitTagSuffix(tag)
		version, ok := extractImageTagSemver(core)
		if !ok {
			continue
		}
		if !matchesSemverPolicy(tag, version, policy.Tags.Semver) {
			continue
		}
		stageSemver = append(stageSemver, tagCandidate{Tag: tag, Version: version})
	}

	stageDeny := make([]tagCandidate, 0, len(stageSemver))
	for _, candidate := range stageSemver {
		if len(denyMatchers) > 0 && matchesAnyRegexp(denyMatchers, candidate.Tag) {
			continue
		}
		stageDeny = append(stageDeny, candidate)
	}
	logOCIDecision(
		"policy-filter policy=%q current_tag=%q allow_in=%d allow_out=%d semver_out=%d deny_out=%d final=%d",
		strings.TrimSpace(policy.Name),
		currentTag,
		len(tags),
		len(stageAllow),
		len(stageSemver),
		len(stageSemver)-len(stageDeny),
		len(stageDeny),
	)
	return bestTagCandidate(stageDeny)
}

type tagCandidate struct {
	Tag     string
	Version string
}

func bestTagCandidate(candidates []tagCandidate) string {
	bestTag := ""
	bestVersion := ""
	for _, candidate := range candidates {
		if bestVersion == "" || semver.Compare(candidate.Version, bestVersion) > 0 || (semver.Compare(candidate.Version, bestVersion) == 0 && candidate.Tag > bestTag) {
			bestTag = candidate.Tag
			bestVersion = candidate.Version
		}
	}
	return bestTag
}

func matchesSemverPolicy(tag, version string, rules []OCIImageSemverPolicy) bool {
	if len(rules) == 0 {
		return true
	}
	isPrerelease := strings.Contains(version, "-")
	for _, rule := range rules {
		if isPrerelease && !rule.IncludePrerelease {
			continue
		}
		if isPrerelease && len(rule.PrereleaseAllow) > 0 {
			matchers := compileRegexps(rule.PrereleaseAllow)
			if !matchesAnyRegexp(matchers, tag) {
				continue
			}
		}
		if len(rule.Range) == 0 {
			return true
		}
		for _, rawRange := range rule.Range {
			constraints, err := parseSemverRange(rawRange)
			if err != nil {
				logOCIDecision("warning: invalid semver range %q: %v", rawRange, err)
				continue
			}
			if matchesSemverConstraints(version, constraints) {
				return true
			}
		}
	}
	return false
}

func matchesSemverConstraints(version string, constraints []semverConstraint) bool {
	for _, constraint := range constraints {
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

func compileRegexps(patterns []string) []*regexp.Regexp {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		matcher, err := regexp.Compile(pattern)
		if err != nil {
			logOCIDecision("warning: invalid regex pattern=%q: %v", pattern, err)
			continue
		}
		result = append(result, matcher)
	}
	return result
}

func matchesAnyRegexp(matchers []*regexp.Regexp, value string) bool {
	for _, matcher := range matchers {
		if matcher.MatchString(value) {
			return true
		}
	}
	return false
}

func logOCIDecision(format string, args ...any) {
	_, _ = fmt.Fprintf(os.Stderr, "[patchpilot] oci: "+format+"\n", args...)
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
