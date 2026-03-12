package fixer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"golang.org/x/mod/semver"
)

// ResolveLatestSemverImageTag returns the highest semver tag found for the
// given image repository, ignoring non-semver tags such as "latest".
func ResolveLatestSemverImageTag(ctx context.Context, imageRepository string) (string, error) {
	ref, err := parseImageRepository(imageRepository)
	if err != nil {
		return "", err
	}
	tags, err := listRegistryTags(ctx, ref)
	if err != nil {
		return "", err
	}
	type candidate struct {
		tag     string
		version string
	}
	candidates := make([]candidate, 0, len(tags))
	for _, tag := range tags {
		version, ok := extractImageTagSemver(tag)
		if !ok {
			continue
		}
		candidates = append(candidates, candidate{tag: tag, version: version})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no semver tags found for %s", imageRepository)
	}
	sort.Slice(candidates, func(i, j int) bool {
		comparison := semver.Compare(candidates[i].version, candidates[j].version)
		if comparison == 0 {
			return candidates[i].tag < candidates[j].tag
		}
		return comparison > 0
	})
	return candidates[0].tag, nil
}

func parseImageRepository(imageRepository string) (imageReference, error) {
	imageRepository = strings.TrimSpace(imageRepository)
	if imageRepository == "" {
		return imageReference{}, fmt.Errorf("image repository is empty")
	}
	imageWithoutDigest, _ := splitImageDigest(imageRepository)
	registry := "docker.io"
	repository := imageWithoutDigest
	first := imageWithoutDigest
	if slash := strings.Index(first, "/"); slash != -1 {
		first = first[:slash]
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		registry = first
		repository = strings.TrimPrefix(imageWithoutDigest, first+"/")
	}
	if registry == "docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}
	if repository == "" {
		return imageReference{}, fmt.Errorf("invalid image repository %q", imageRepository)
	}
	return imageReference{
		Registry:           registry,
		Repository:         repository,
		OriginalRepository: imageWithoutDigest,
	}, nil
}
