package githubapp

import (
	"net/url"
	"testing"
)

func TestRepositoryCloneURL(t *testing.T) {
	cloneURL, err := repositoryCloneURL("https://github.example.com/base", "acme", "demo", "tok:with@chars")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	parsed, err := url.Parse(cloneURL)
	if err != nil {
		t.Fatalf("parse clone url: %v", err)
	}
	if parsed.Scheme != "https" {
		t.Fatalf("scheme = %q, want https", parsed.Scheme)
	}
	if parsed.Host != "github.example.com" {
		t.Fatalf("host = %q, want github.example.com", parsed.Host)
	}
	if parsed.Path != "/base/acme/demo.git" {
		t.Fatalf("path = %q, want /base/acme/demo.git", parsed.Path)
	}
	if parsed.User == nil {
		t.Fatalf("expected user info to be set")
	}
	if parsed.User.Username() != "x-access-token" {
		t.Fatalf("username = %q, want x-access-token", parsed.User.Username())
	}
	password, ok := parsed.User.Password()
	if !ok || password != "tok:with@chars" {
		t.Fatalf("password mismatch")
	}
}

func TestRepositoryCloneURLErrors(t *testing.T) {
	if _, err := repositoryCloneURL("::://bad-url", "acme", "demo", "token"); err == nil {
		t.Fatalf("expected parse error")
	}
	if _, err := repositoryCloneURL("https://github.com", "acme", "demo", ""); err == nil {
		t.Fatalf("expected token error")
	}
}
