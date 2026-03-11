package fixer

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"

	"github.com/moolen/patchpilot/internal/vuln"
)

var runGitLSRemoteFunc = runGitLSRemote

func ApplyGitHubActionsFixes(ctx context.Context, repo string, findings []vuln.Finding) ([]Patch, error) {
	return ApplyGitHubActionsFixesWithOptions(ctx, repo, findings, FileOptions{})
}

func ApplyGitHubActionsFixesWithOptions(ctx context.Context, repo string, findings []vuln.Finding, options FileOptions) ([]Patch, error) {
	workflows, err := findFilesWithOptions(repo, isGitHubWorkflowFile, options)
	if err != nil {
		return nil, err
	}

	requirements := collectGitHubActionRequirements(workflows, findings)
	resolver := newGitHubActionRefResolver()
	patches := make([]Patch, 0)
	for _, path := range workflows {
		need, ok := requirements[path]
		if !ok || len(need.FixedVersions) == 0 {
			continue
		}
		filePatches, changed, err := patchGitHubWorkflow(ctx, path, need, resolver)
		if err != nil {
			return nil, err
		}
		if changed {
			patches = append(patches, filePatches...)
		}
	}
	return patches, nil
}

type gitHubActionNeeds struct {
	FixedVersions map[string]string
}

type gitHubActionRef struct {
	PackagePath string
	Repository  string
	Ref         string
}

type gitHubActionRefResolver struct {
	tagsByRepository map[string]map[string]string
}

func newGitHubActionRefResolver() *gitHubActionRefResolver {
	return &gitHubActionRefResolver{
		tagsByRepository: map[string]map[string]string{},
	}
}

func collectGitHubActionRequirements(workflows []string, findings []vuln.Finding) map[string]gitHubActionNeeds {
	known := map[string]struct{}{}
	for _, workflow := range workflows {
		known[workflow] = struct{}{}
	}

	requirements := map[string]gitHubActionNeeds{}
	for _, finding := range findings {
		if !isGitHubActionsEcosystem(finding.Ecosystem) {
			continue
		}
		packagePath := normalizeGitHubActionPackagePath(finding.Package)
		if packagePath == "" || strings.TrimSpace(finding.FixedVersion) == "" {
			continue
		}
		key := gitHubActionRequirementKey(packagePath)
		for _, location := range finding.Locations {
			if _, ok := known[location]; !ok {
				continue
			}
			need := requirements[location]
			if need.FixedVersions == nil {
				need.FixedVersions = map[string]string{}
			}
			need.FixedVersions[key] = preferGitHubActionFixedVersion(need.FixedVersions[key], finding.FixedVersion)
			requirements[location] = need
		}
	}
	return requirements
}

func patchGitHubWorkflow(
	ctx context.Context,
	path string,
	need gitHubActionNeeds,
	resolver *gitHubActionRefResolver,
) ([]Patch, bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	docs := make([]*yaml.Node, 0, 1)
	for {
		var doc yaml.Node
		if err := decoder.Decode(&doc); err != nil {
			if err == io.EOF {
				break
			}
			return nil, false, fmt.Errorf("parse %s: %w", path, err)
		}
		if len(doc.Content) == 0 && doc.Kind == 0 {
			break
		}
		docs = append(docs, &doc)
	}

	patches := make([]Patch, 0)
	changed := false
	for _, doc := range docs {
		docChanged, docPatches, err := patchGitHubWorkflowNode(ctx, doc, path, need, resolver)
		if err != nil {
			return nil, false, err
		}
		if docChanged {
			changed = true
			patches = append(patches, docPatches...)
		}
	}
	if !changed {
		return nil, false, nil
	}

	var buf bytes.Buffer
	encoder := yaml.NewEncoder(&buf)
	encoder.SetIndent(2)
	for _, doc := range docs {
		if err := encoder.Encode(doc); err != nil {
			_ = encoder.Close()
			return nil, false, fmt.Errorf("encode %s: %w", path, err)
		}
	}
	if err := encoder.Close(); err != nil {
		return nil, false, fmt.Errorf("finalize %s: %w", path, err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		return nil, false, fmt.Errorf("write %s: %w", path, err)
	}
	return patches, true, nil
}

func patchGitHubWorkflowNode(
	ctx context.Context,
	node *yaml.Node,
	path string,
	need gitHubActionNeeds,
	resolver *gitHubActionRefResolver,
) (bool, []Patch, error) {
	if node == nil {
		return false, nil, nil
	}

	changed := false
	patches := make([]Patch, 0)
	switch node.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range node.Content {
			childChanged, childPatches, err := patchGitHubWorkflowNode(ctx, child, path, need, resolver)
			if err != nil {
				return false, nil, err
			}
			if childChanged {
				changed = true
				patches = append(patches, childPatches...)
			}
		}
	case yaml.MappingNode:
		for index := 0; index+1 < len(node.Content); index += 2 {
			key := node.Content[index]
			value := node.Content[index+1]
			if key.Kind == yaml.ScalarNode && key.Value == "uses" && value.Kind == yaml.ScalarNode {
				updated, patch, ok, err := maybePatchGitHubActionUses(ctx, strings.TrimSpace(value.Value), path, need, resolver)
				if err != nil {
					return false, nil, err
				}
				if ok {
					value.Value = updated
					changed = true
					patches = append(patches, patch)
				}
			}
			childChanged, childPatches, err := patchGitHubWorkflowNode(ctx, value, path, need, resolver)
			if err != nil {
				return false, nil, err
			}
			if childChanged {
				changed = true
				patches = append(patches, childPatches...)
			}
		}
	}
	return changed, patches, nil
}

func maybePatchGitHubActionUses(
	ctx context.Context,
	usesValue string,
	path string,
	need gitHubActionNeeds,
	resolver *gitHubActionRefResolver,
) (string, Patch, bool, error) {
	ref, ok := parseGitHubActionRef(usesValue)
	if !ok {
		return "", Patch{}, false, nil
	}
	targetVersion, ok := need.FixedVersions[gitHubActionRequirementKey(ref.PackagePath)]
	if !ok || strings.TrimSpace(targetVersion) == "" {
		return "", Patch{}, false, nil
	}

	updatedRef, err := resolver.Resolve(ctx, ref, targetVersion)
	if err != nil {
		return "", Patch{}, false, fmt.Errorf("resolve updated ref for %s in %s: %w", ref.PackagePath, path, err)
	}
	if updatedRef == ref.Ref {
		return "", Patch{}, false, nil
	}

	return ref.PackagePath + "@" + updatedRef, Patch{
		Manager: "github_actions",
		Target:  path,
		Package: ref.PackagePath,
		From:    ref.Ref,
		To:      updatedRef,
	}, true, nil
}

func (resolver *gitHubActionRefResolver) Resolve(ctx context.Context, ref gitHubActionRef, targetVersion string) (string, error) {
	targetVersion = strings.TrimSpace(targetVersion)
	if targetVersion == "" {
		return "", fmt.Errorf("target version is empty")
	}
	if !isFullGitSHA(ref.Ref) {
		return targetVersion, nil
	}
	if isFullGitSHA(targetVersion) {
		return strings.ToLower(targetVersion), nil
	}

	tags, err := resolver.tagsForRepository(ctx, ref.Repository)
	if err != nil {
		return "", err
	}
	candidates := []string{targetVersion}
	if strings.HasPrefix(targetVersion, "v") {
		candidates = append(candidates, strings.TrimPrefix(targetVersion, "v"))
	} else {
		candidates = append(candidates, "v"+targetVersion)
	}
	for _, candidate := range candidates {
		if sha := tags[candidate]; sha != "" {
			return sha, nil
		}
	}
	return "", fmt.Errorf("resolve tag %q in %s: tag not found", targetVersion, ref.Repository)
}

func (resolver *gitHubActionRefResolver) tagsForRepository(ctx context.Context, repository string) (map[string]string, error) {
	if tags, ok := resolver.tagsByRepository[repository]; ok {
		return tags, nil
	}
	output, err := runGitLSRemoteFunc(ctx, repository)
	if err != nil {
		return nil, err
	}
	tags := parseGitLSRemoteTags(output)
	resolver.tagsByRepository[repository] = tags
	return tags, nil
}

func runGitLSRemote(ctx context.Context, repository string) ([]byte, error) {
	url := "https://github.com/" + strings.Trim(repository, "/") + ".git"
	cmd := exec.CommandContext(ctx, "git", "ls-remote", "--tags", url)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git ls-remote %s: %w: %s", repository, err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func parseGitLSRemoteTags(output []byte) map[string]string {
	tags := map[string]string{}
	annotated := map[string]string{}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		sha := strings.ToLower(strings.TrimSpace(fields[0]))
		refName := strings.TrimSpace(fields[1])
		refName = strings.TrimPrefix(refName, "refs/tags/")
		if refName == fields[1] {
			continue
		}
		if strings.HasSuffix(refName, "^{}") {
			annotated[strings.TrimSuffix(refName, "^{}")] = sha
			continue
		}
		if tags[refName] == "" {
			tags[refName] = sha
		}
	}
	for refName, sha := range annotated {
		tags[refName] = sha
	}
	return tags
}

func parseGitHubActionRef(raw string) (gitHubActionRef, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "./") || strings.HasPrefix(raw, "docker://") {
		return gitHubActionRef{}, false
	}
	at := strings.LastIndex(raw, "@")
	if at <= 0 || at == len(raw)-1 {
		return gitHubActionRef{}, false
	}
	packagePath := normalizeGitHubActionPackagePath(raw[:at])
	ref := strings.TrimSpace(raw[at+1:])
	repository := gitHubActionRepository(packagePath)
	if packagePath == "" || ref == "" || repository == "" {
		return gitHubActionRef{}, false
	}
	return gitHubActionRef{
		PackagePath: packagePath,
		Repository:  repository,
		Ref:         ref,
	}, true
}

func gitHubActionRepository(packagePath string) string {
	parts := strings.Split(normalizeGitHubActionPackagePath(packagePath), "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func normalizeGitHubActionPackagePath(packagePath string) string {
	return strings.Trim(strings.TrimSpace(packagePath), "/")
}

func gitHubActionRequirementKey(packagePath string) string {
	return strings.ToLower(normalizeGitHubActionPackagePath(packagePath))
}

func preferGitHubActionFixedVersion(current, candidate string) string {
	current = strings.TrimSpace(current)
	candidate = strings.TrimSpace(candidate)
	if current == "" {
		return candidate
	}
	if candidate == "" {
		return current
	}
	left := canonicalGitHubActionSemver(current)
	right := canonicalGitHubActionSemver(candidate)
	if left == "" || right == "" {
		if current <= candidate {
			return current
		}
		return candidate
	}
	if semver.Compare(left, right) <= 0 {
		return current
	}
	return candidate
}

func canonicalGitHubActionSemver(version string) string {
	return canonicalSemver(version)
}

func isGitHubActionsEcosystem(ecosystem string) bool {
	return strings.EqualFold(strings.TrimSpace(ecosystem), "github-actions")
}

func isGitHubWorkflowFile(path string, entry fs.DirEntry) bool {
	if entry.IsDir() {
		return false
	}
	name := strings.ToLower(entry.Name())
	if !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".yaml") {
		return false
	}
	slashPath := filepath.ToSlash(path)
	return strings.Contains(slashPath, "/.github/workflows/")
}

func isFullGitSHA(ref string) bool {
	ref = strings.TrimSpace(ref)
	if len(ref) != 40 {
		return false
	}
	for _, ch := range ref {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}
