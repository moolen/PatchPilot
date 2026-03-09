package fixer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"
)

const defaultRegistryCacheTTL = 4 * time.Hour

type imageReference struct {
	Registry           string
	Repository         string
	OriginalRepository string
	Tag                string
	Digest             string
}

type registryTagCacheEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	Tags      []string  `json:"tags"`
}

var (
	registryHTTPClient       = &http.Client{Timeout: 20 * time.Second}
	registryNowFunc          = time.Now
	registryBaseURL          = func(host string) string { return "https://" + host }
	registryCacheDir         = defaultRegistryCacheDir
	registryCacheTTL         = defaultRegistryCacheTTL
	registryAuthMode         = "auto"
	registryAuthToken        = ""
	registryCacheDirOverride = ""
)

type RegistryOptions struct {
	CacheDir  string
	CacheTTL  time.Duration
	AuthMode  string
	AuthToken string
}

func ConfigureRegistry(options RegistryOptions) func() {
	previousTTL := registryCacheTTL
	previousMode := registryAuthMode
	previousToken := registryAuthToken
	previousCacheDirOverride := registryCacheDirOverride

	if options.CacheTTL > 0 {
		registryCacheTTL = options.CacheTTL
	}
	if strings.TrimSpace(options.AuthMode) != "" {
		registryAuthMode = strings.ToLower(strings.TrimSpace(options.AuthMode))
	}
	registryAuthToken = strings.TrimSpace(options.AuthToken)
	if strings.TrimSpace(options.CacheDir) != "" {
		registryCacheDirOverride = strings.TrimSpace(options.CacheDir)
	}

	return func() {
		registryCacheTTL = previousTTL
		registryAuthMode = previousMode
		registryAuthToken = previousToken
		registryCacheDirOverride = previousCacheDirOverride
	}
}

func resolveUpdatedImageTag(ctx context.Context, image, fixed string) string {
	ref, ok := parseImageReference(image)
	if !ok {
		return ""
	}

	currentCore, _ := splitTagSuffix(ref.Tag)
	currentSemver := canonicalImageSemver(currentCore)
	fixedSemver := canonicalImageSemver(fixed)
	if currentSemver == "" || fixedSemver == "" {
		return ""
	}
	if semver.Compare(currentSemver, fixedSemver) >= 0 {
		return ref.Tag
	}

	tags, err := listRegistryTags(ctx, ref)
	if err != nil {
		return updateImageTag(ref.Tag, fixed)
	}

	if candidate := selectRegistryTag(ref.Tag, fixedSemver, tags); candidate != "" {
		return candidate
	}
	return updateImageTag(ref.Tag, fixed)
}

func resolveUpdatedImageDigest(ctx context.Context, image, tag string) string {
	ref, ok := parseImageReference(image)
	if !ok {
		return ""
	}
	if tag == "" {
		return ""
	}
	digest, err := fetchRegistryManifestDigest(ctx, ref, tag)
	if err != nil {
		return ""
	}
	return digest
}

func parseImageReference(image string) (imageReference, bool) {
	imageWithoutDigest, digest := splitImageDigest(image)
	originalRepo, tag := splitImageRef(imageWithoutDigest)
	if tag == "" {
		return imageReference{}, false
	}

	registry := "docker.io"
	repository := originalRepo
	first := originalRepo
	if slash := strings.Index(first, "/"); slash != -1 {
		first = first[:slash]
	}
	if strings.Contains(first, ".") || strings.Contains(first, ":") || first == "localhost" {
		registry = first
		repository = strings.TrimPrefix(originalRepo, first+"/")
	}
	if registry == "docker.io" && !strings.Contains(repository, "/") {
		repository = "library/" + repository
	}

	return imageReference{
		Registry:           registry,
		Repository:         repository,
		OriginalRepository: originalRepo,
		Tag:                tag,
		Digest:             digest,
	}, true
}

func selectRegistryTag(currentTag, fixedSemver string, tags []string) string {
	currentCore, suffix := splitTagSuffix(currentTag)
	currentSemver := canonicalImageSemver(currentCore)
	if currentSemver == "" {
		return ""
	}
	family := versionFamily(currentCore)

	candidates := make([]string, 0)
	for _, tag := range tags {
		candidateCore, candidateSuffix := splitTagSuffix(tag)
		if candidateSuffix != suffix {
			continue
		}
		candidateSemver := canonicalImageSemver(candidateCore)
		if candidateSemver == "" {
			continue
		}
		if !matchesVersionFamily(candidateCore, family) {
			continue
		}
		if semver.Compare(candidateSemver, currentSemver) <= 0 {
			continue
		}
		if semver.Compare(candidateSemver, fixedSemver) < 0 {
			continue
		}
		candidates = append(candidates, tag)
	}
	if len(candidates) == 0 {
		return ""
	}
	sort.Slice(candidates, func(i, j int) bool {
		leftCore, _ := splitTagSuffix(candidates[i])
		rightCore, _ := splitTagSuffix(candidates[j])
		left := canonicalImageSemver(leftCore)
		right := canonicalImageSemver(rightCore)
		return semver.Compare(left, right) < 0
	})
	return candidates[0]
}

func splitTagSuffix(tag string) (string, string) {
	index := strings.Index(tag, "-")
	if index == -1 {
		return tag, ""
	}
	return tag[:index], tag[index:]
}

func versionFamily(core string) []string {
	parts := strings.Split(strings.TrimPrefix(core, "v"), ".")
	if len(parts) == 0 {
		return nil
	}
	return parts
}

func matchesVersionFamily(core string, family []string) bool {
	parts := strings.Split(strings.TrimPrefix(core, "v"), ".")
	if len(parts) < len(family) {
		return false
	}
	for index, part := range family {
		if parts[index] != part {
			return false
		}
	}
	return true
}

func listRegistryTags(ctx context.Context, ref imageReference) ([]string, error) {
	if cached, ok := readRegistryTagsFromCache(ref); ok {
		return cached, nil
	}

	tags, err := fetchRegistryTags(ctx, ref)
	if err != nil {
		if cached, ok := readRegistryTagsFromCacheStale(ref); ok {
			return cached, nil
		}
		return nil, err
	}
	writeRegistryTagsToCache(ref, tags)
	return tags, nil
}

func fetchRegistryTags(ctx context.Context, ref imageReference) ([]string, error) {
	nextURL := registryBaseURL(ref.Registry) + "/v2/" + ref.Repository + "/tags/list?n=100"
	tags := make([]string, 0)
	seen := map[string]struct{}{}
	token := initialRegistryToken()

	for nextURL != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}

		response, err := registryHTTPClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode == http.StatusUnauthorized {
			if registryAuthMode != "auto" {
				_ = response.Body.Close()
				return nil, fmt.Errorf("registry tags request unauthorized (auth mode %q)", registryAuthMode)
			}
			authHeader := response.Header.Get("Www-Authenticate")
			_ = response.Body.Close()
			token, err = fetchRegistryToken(ctx, authHeader)
			if err != nil {
				return nil, err
			}
			continue
		}
		if response.StatusCode != http.StatusOK {
			_ = response.Body.Close()
			return nil, fmt.Errorf("registry tags request failed: %s", response.Status)
		}

		var payload struct {
			Tags []string `json:"tags"`
		}
		if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
			_ = response.Body.Close()
			return nil, fmt.Errorf("decode registry tags: %w", err)
		}
		linkHeader := response.Header.Get("Link")
		_ = response.Body.Close()

		for _, tag := range payload.Tags {
			if _, ok := seen[tag]; ok {
				continue
			}
			seen[tag] = struct{}{}
			tags = append(tags, tag)
		}
		nextURL = parseRegistryNextURL(linkHeader, ref.Registry)
	}

	sort.Strings(tags)
	return tags, nil
}

func fetchRegistryToken(ctx context.Context, header string) (string, error) {
	realm, params := parseRegistryAuthHeader(header)
	if realm == "" {
		return "", fmt.Errorf("unsupported registry auth header: %q", header)
	}
	tokenURL, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("parse auth realm: %w", err)
	}
	query := tokenURL.Query()
	for key, value := range params {
		query.Set(key, value)
	}
	tokenURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL.String(), nil)
	if err != nil {
		return "", err
	}
	response, err := registryHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry token request failed: %s", response.Status)
	}
	var payload struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return "", fmt.Errorf("decode registry token: %w", err)
	}
	if payload.Token == "" {
		return "", fmt.Errorf("registry token missing in response")
	}
	return payload.Token, nil
}

func parseRegistryAuthHeader(header string) (string, map[string]string) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(strings.ToLower(header), "bearer ") {
		return "", nil
	}
	fields := strings.Split(header[len("Bearer "):], ",")
	params := map[string]string{}
	realm := ""
	for _, field := range fields {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		if key == "realm" {
			realm = value
			continue
		}
		params[key] = value
	}
	return realm, params
}

func parseRegistryNextURL(linkHeader, registry string) string {
	if linkHeader == "" {
		return ""
	}
	start := strings.Index(linkHeader, "<")
	end := strings.Index(linkHeader, ">")
	if start == -1 || end == -1 || end <= start+1 {
		return ""
	}
	next := linkHeader[start+1 : end]
	if strings.HasPrefix(next, "http://") || strings.HasPrefix(next, "https://") {
		return next
	}
	return registryBaseURL(registry) + next
}

func fetchRegistryManifestDigest(ctx context.Context, ref imageReference, tag string) (string, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return "", fmt.Errorf("manifest tag is empty")
	}
	manifestURL := registryBaseURL(ref.Registry) + "/v2/" + ref.Repository + "/manifests/" + url.PathEscape(tag)

	headers := map[string]string{
		"Accept": strings.Join([]string{
			"application/vnd.oci.image.manifest.v1+json",
			"application/vnd.oci.image.index.v1+json",
			"application/vnd.docker.distribution.manifest.v2+json",
			"application/vnd.docker.distribution.manifest.list.v2+json",
		}, ", "),
	}

	response, err := doRegistryRequestWithAuth(ctx, http.MethodHead, manifestURL, headers)
	if err != nil {
		return "", err
	}
	statusCode := response.StatusCode
	digest := strings.TrimSpace(response.Header.Get("Docker-Content-Digest"))
	_ = response.Body.Close()
	if statusCode == http.StatusOK && digest != "" {
		return digest, nil
	}
	if statusCode != http.StatusOK && statusCode != http.StatusMethodNotAllowed {
		return "", fmt.Errorf("registry manifest request failed: %s", response.Status)
	}

	response, err = doRegistryRequestWithAuth(ctx, http.MethodGet, manifestURL, headers)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("registry manifest request failed: %s", response.Status)
	}
	digest = strings.TrimSpace(response.Header.Get("Docker-Content-Digest"))
	if digest != "" {
		return digest, nil
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read registry manifest: %w", err)
	}
	if len(body) == 0 {
		return "", fmt.Errorf("registry manifest body is empty")
	}

	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func doRegistryRequestWithAuth(ctx context.Context, method, requestURL string, headers map[string]string) (*http.Response, error) {
	token := initialRegistryToken()
	for attempts := 0; attempts < 3; attempts++ {
		request, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
		if err != nil {
			return nil, err
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}

		response, err := registryHTTPClient.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusUnauthorized {
			return response, nil
		}
		if registryAuthMode != "auto" {
			return response, nil
		}

		authHeader := response.Header.Get("Www-Authenticate")
		_ = response.Body.Close()
		token, err = fetchRegistryToken(ctx, authHeader)
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("registry request unauthorized after retries")
}

func initialRegistryToken() string {
	if registryAuthMode == "bearer" {
		return strings.TrimSpace(registryAuthToken)
	}
	return ""
}

func readRegistryTagsFromCache(ref imageReference) ([]string, bool) {
	entry, ok := readRegistryCacheEntry(ref)
	if !ok {
		return nil, false
	}
	if registryNowFunc().Sub(entry.FetchedAt) > registryCacheTTL {
		return nil, false
	}
	return entry.Tags, true
}

func readRegistryTagsFromCacheStale(ref imageReference) ([]string, bool) {
	entry, ok := readRegistryCacheEntry(ref)
	if !ok {
		return nil, false
	}
	return entry.Tags, true
}

func readRegistryCacheEntry(ref imageReference) (registryTagCacheEntry, bool) {
	path, err := registryCachePath(ref)
	if err != nil {
		return registryTagCacheEntry{}, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return registryTagCacheEntry{}, false
	}
	var entry registryTagCacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return registryTagCacheEntry{}, false
	}
	return entry, true
}

func writeRegistryTagsToCache(ref imageReference, tags []string) {
	path, err := registryCachePath(ref)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(registryTagCacheEntry{FetchedAt: registryNowFunc(), Tags: tags}, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o644)
}

func registryCachePath(ref imageReference) (string, error) {
	dir, err := registryCacheDir()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(ref.Registry + "/" + ref.Repository))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json"), nil
}

func defaultRegistryCacheDir() (string, error) {
	if override := strings.TrimSpace(registryCacheDirOverride); override != "" {
		return override, nil
	}
	if override := strings.TrimSpace(os.Getenv("PATCHPILOT_REGISTRY_CACHE_DIR")); override != "" {
		return override, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "patchpilot", "registry-tags"), nil
}
