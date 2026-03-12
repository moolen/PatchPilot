package fixer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	awsecr "github.com/aws/aws-sdk-go-v2/service/ecr"
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
	ecrAuthProvider          = fetchECRBasicCredential
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

func splitTagSuffix(tag string) (string, string) {
	index := strings.Index(tag, "-")
	if index == -1 {
		return tag, ""
	}
	return tag[:index], tag[index:]
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
	authorization := initialRegistryAuthorization()

	for nextURL != "" {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return nil, err
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
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
			authorization, err = fetchRegistryAuthorization(ctx, nextURL, authHeader)
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

func fetchRegistryAuthorization(ctx context.Context, requestURL, header string) (string, error) {
	challenge := parseRegistryAuthHeader(header)
	switch challenge.scheme {
	case "bearer":
		token, err := fetchRegistryBearerToken(ctx, challenge)
		if err != nil {
			return "", err
		}
		return "Bearer " + token, nil
	case "basic":
		credential, err := lookupRegistryBasicCredential(ctx, requestURL, challenge.realm)
		if err != nil {
			return "", err
		}
		return "Basic " + credential, nil
	default:
		return "", fmt.Errorf("unsupported registry auth header: %q", header)
	}
}

func fetchRegistryBearerToken(ctx context.Context, challenge registryAuthChallenge) (string, error) {
	if challenge.realm == "" {
		return "", fmt.Errorf("unsupported registry auth header: %q", challenge.rawHeader)
	}
	tokenURL, err := url.Parse(challenge.realm)
	if err != nil {
		return "", fmt.Errorf("parse auth realm: %w", err)
	}
	query := tokenURL.Query()
	for key, value := range challenge.params {
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

type registryAuthChallenge struct {
	rawHeader string
	scheme    string
	realm     string
	params    map[string]string
}

func parseRegistryAuthHeader(header string) registryAuthChallenge {
	header = strings.TrimSpace(header)
	if header == "" {
		return registryAuthChallenge{}
	}
	scheme := strings.ToLower(header)
	fields := ""
	if index := strings.IndexByte(header, ' '); index != -1 {
		scheme = strings.ToLower(strings.TrimSpace(header[:index]))
		fields = strings.TrimSpace(header[index+1:])
	}
	params := map[string]string{}
	for _, field := range strings.Split(fields, ",") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		if key != "" {
			params[key] = value
		}
	}
	realm := strings.TrimSpace(params["realm"])
	delete(params, "realm")
	return registryAuthChallenge{
		rawHeader: header,
		scheme:    scheme,
		realm:     realm,
		params:    params,
	}
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
	authorization := initialRegistryAuthorization()
	for attempts := 0; attempts < 3; attempts++ {
		request, err := http.NewRequestWithContext(ctx, method, requestURL, nil)
		if err != nil {
			return nil, err
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
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
		authorization, err = fetchRegistryAuthorization(ctx, requestURL, authHeader)
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("registry request unauthorized after retries")
}

func initialRegistryAuthorization() string {
	if registryAuthMode == "bearer" {
		token := strings.TrimSpace(registryAuthToken)
		if token == "" {
			return ""
		}
		return "Bearer " + token
	}
	return ""
}

type dockerConfig struct {
	Auths       map[string]dockerAuthEntry `json:"auths"`
	CredsStore  string                     `json:"credsStore"`
	CredHelpers map[string]string          `json:"credHelpers"`
}

type dockerAuthEntry struct {
	Auth     string `json:"auth"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func lookupRegistryBasicCredential(ctx context.Context, requestURL, realm string) (string, error) {
	hosts := registryAuthHosts(requestURL, realm)
	if len(hosts) == 0 {
		return "", fmt.Errorf("registry basic auth challenge missing host information")
	}

	cfg, err := loadDockerConfig()
	if err != nil {
		return "", err
	}
	for _, host := range hosts {
		credential, ok, err := dockerCredentialForHost(cfg, host)
		if err != nil {
			return "", err
		}
		if ok {
			logRegistryAuthPath("docker_credentials", host)
			return credential, nil
		}
	}
	for _, host := range hosts {
		credential, ok, err := ecrAuthProvider(ctx, host)
		if err != nil {
			return "", err
		}
		if ok {
			logRegistryAuthPath("aws_sdk_fallback", host)
			return credential, nil
		}
	}
	return "", fmt.Errorf("registry basic auth credentials not found for %s", strings.Join(hosts, ", "))
}

func registryAuthHosts(requestURL, realm string) []string {
	hosts := make([]string, 0, 2)
	seen := map[string]struct{}{}
	addHost := func(value string) {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		hosts = append(hosts, value)
	}
	if parsed, err := url.Parse(requestURL); err == nil {
		addHost(parsed.Host)
	}
	if parsed, err := url.Parse(realm); err == nil {
		addHost(parsed.Host)
	}
	return hosts
}

func loadDockerConfig() (dockerConfig, error) {
	if raw := strings.TrimSpace(os.Getenv("DOCKER_AUTH_CONFIG")); raw != "" {
		var cfg dockerConfig
		if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
			return dockerConfig{}, fmt.Errorf("parse DOCKER_AUTH_CONFIG: %w", err)
		}
		if cfg.Auths == nil {
			cfg.Auths = map[string]dockerAuthEntry{}
		}
		return cfg, nil
	}

	configPath, err := dockerConfigPath()
	if err != nil {
		return dockerConfig{}, err
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return dockerConfig{Auths: map[string]dockerAuthEntry{}}, nil
		}
		return dockerConfig{}, fmt.Errorf("read docker config %q: %w", configPath, err)
	}

	var cfg dockerConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return dockerConfig{}, fmt.Errorf("parse docker config %q: %w", configPath, err)
	}
	if cfg.Auths == nil {
		cfg.Auths = map[string]dockerAuthEntry{}
	}
	return cfg, nil
}

func dockerConfigPath() (string, error) {
	if override := strings.TrimSpace(os.Getenv("DOCKER_CONFIG")); override != "" {
		return filepath.Join(override, "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home dir for docker config: %w", err)
	}
	return filepath.Join(home, ".docker", "config.json"), nil
}

func dockerCredentialForHost(cfg dockerConfig, targetHost string) (string, bool, error) {
	targetHost = strings.ToLower(strings.TrimSpace(targetHost))
	if targetHost == "" {
		return "", false, nil
	}
	for key, auth := range cfg.Auths {
		if normalizeDockerAuthHost(key) != targetHost {
			continue
		}
		if credential, ok := dockerAuthCredential(auth); ok {
			return credential, true, nil
		}
	}
	helper := dockerCredentialHelperForHost(cfg, targetHost)
	if helper == "" {
		return "", false, nil
	}
	credential, ok, err := dockerCredentialFromHelper(helper, targetHost)
	if err != nil {
		return "", false, fmt.Errorf("resolve docker credential helper %q for %q: %w", helper, targetHost, err)
	}
	if ok {
		return credential, true, nil
	}
	return "", false, nil
}

func dockerCredentialHelperForHost(cfg dockerConfig, targetHost string) string {
	for key, helper := range cfg.CredHelpers {
		if normalizeDockerAuthHost(key) != targetHost {
			continue
		}
		return strings.TrimSpace(helper)
	}
	return strings.TrimSpace(cfg.CredsStore)
}

func dockerCredentialFromHelper(helper, targetHost string) (string, bool, error) {
	for _, server := range []string{targetHost, "https://" + targetHost} {
		credential, ok, err := invokeDockerCredentialHelper(helper, server)
		if err != nil {
			return "", false, err
		}
		if ok {
			return credential, true, nil
		}
	}
	return "", false, nil
}

func invokeDockerCredentialHelper(helper, server string) (string, bool, error) {
	helper = strings.TrimSpace(helper)
	if helper == "" {
		return "", false, nil
	}
	command := exec.Command("docker-credential-"+helper, "get")
	command.Stdin = strings.NewReader(server)
	output, err := command.Output()
	if err != nil {
		if _, isExitError := err.(*exec.ExitError); isExitError {
			return "", false, nil
		}
		if strings.Contains(strings.ToLower(err.Error()), "executable file not found") {
			return "", false, nil
		}
		return "", false, err
	}
	var response struct {
		Username string `json:"Username"`
		Secret   string `json:"Secret"`
	}
	if err := json.Unmarshal(output, &response); err != nil {
		return "", false, fmt.Errorf("decode helper response: %w", err)
	}
	if strings.TrimSpace(response.Username) == "" || strings.TrimSpace(response.Secret) == "" {
		return "", false, nil
	}
	return encodeBasicCredential(response.Username, response.Secret), true, nil
}

func normalizeDockerAuthHost(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return ""
	}
	if parsed, err := url.Parse(key); err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Host)
	}
	if slash := strings.IndexByte(key, '/'); slash != -1 {
		key = key[:slash]
	}
	return strings.ToLower(strings.TrimSpace(key))
}

func dockerAuthCredential(entry dockerAuthEntry) (string, bool) {
	if entry.Username != "" && entry.Password != "" {
		return encodeBasicCredential(entry.Username, entry.Password), true
	}
	decoded, ok := decodeDockerAuthEntry(entry.Auth)
	if !ok {
		return "", false
	}
	return encodeBasicCredential(decoded.username, decoded.password), true
}

type basicAuthValue struct {
	username string
	password string
}

func decodeDockerAuthEntry(raw string) (basicAuthValue, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return basicAuthValue{}, false
	}
	decodedBytes, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		decodedBytes, err = base64.RawStdEncoding.DecodeString(raw)
		if err != nil {
			return basicAuthValue{}, false
		}
	}
	decoded := string(decodedBytes)
	username, password, ok := strings.Cut(decoded, ":")
	if !ok || username == "" || password == "" {
		return basicAuthValue{}, false
	}
	return basicAuthValue{username: username, password: password}, true
}

func encodeBasicCredential(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func logRegistryAuthPath(mode, host string) {
	_, _ = fmt.Fprintf(os.Stderr, "[patchpilot] oci: auth_path=%s registry=%q\n", mode, strings.TrimSpace(host))
}

var privateECRHostPattern = regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com(\.cn)?$`)

func fetchECRBasicCredential(ctx context.Context, host string) (string, bool, error) {
	accountID, region, ok := parsePrivateECRHost(host)
	if !ok {
		return "", false, nil
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return "", false, fmt.Errorf("load aws config for ecr host %q: %w", host, err)
	}
	client := awsecr.NewFromConfig(awsCfg)
	response, err := client.GetAuthorizationToken(ctx, &awsecr.GetAuthorizationTokenInput{
		RegistryIds: []string{accountID},
	})
	if err != nil {
		return "", false, fmt.Errorf("fetch ecr authorization token for host %q: %w", host, err)
	}
	for _, auth := range response.AuthorizationData {
		token := ""
		if auth.AuthorizationToken != nil {
			token = strings.TrimSpace(*auth.AuthorizationToken)
		}
		if token == "" {
			continue
		}
		if auth.ProxyEndpoint != nil {
			endpointHost := normalizeDockerAuthHost(*auth.ProxyEndpoint)
			if endpointHost != "" && endpointHost != normalizeDockerAuthHost(host) {
				continue
			}
		}
		return token, true, nil
	}
	return "", false, nil
}

func parsePrivateECRHost(host string) (string, string, bool) {
	host = normalizeDockerAuthHost(host)
	matches := privateECRHostPattern.FindStringSubmatch(host)
	if len(matches) != 4 {
		return "", "", false
	}
	accountID := strings.TrimSpace(matches[1])
	region := strings.TrimSpace(matches[2])
	if accountID == "" || region == "" {
		return "", "", false
	}
	return accountID, region, true
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
