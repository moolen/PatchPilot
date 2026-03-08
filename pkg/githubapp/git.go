package githubapp

import (
	"fmt"
	"net/url"
	"path"
	"strings"
)

func repositoryCloneURL(baseWebURL, owner, repo, token string) (string, error) {
	if strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("installation token is empty")
	}
	base, err := url.Parse(strings.TrimSpace(baseWebURL))
	if err != nil {
		return "", fmt.Errorf("parse github web base url: %w", err)
	}
	if strings.TrimSpace(base.Scheme) == "" || strings.TrimSpace(base.Host) == "" {
		return "", fmt.Errorf("invalid github web base url: %q", baseWebURL)
	}

	base.Path = path.Join(base.Path, owner, repo) + ".git"
	base.User = url.UserPassword("x-access-token", token)
	return base.String(), nil
}
