package githubapp

import "testing"

func TestNormalizeRepositoryLabels(t *testing.T) {
	got := normalizeRepositoryLabels([]string{" PatchPilot ", "pilot-canary", "patchpilot", ""})
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2 (%#v)", len(got), got)
	}
	if got[0] != "patchpilot" || got[1] != "pilot-canary" {
		t.Fatalf("unexpected labels: %#v", got)
	}
}

func TestRepositoryMatchesLabelSelectors(t *testing.T) {
	labels := []string{"patchpilot", "team-a", "pilot-canary"}

	if !repositoryMatchesLabelSelectors(labels, []string{"pilot-*"}) {
		t.Fatal("expected wildcard selector to match")
	}
	if !repositoryMatchesLabelSelectors(labels, []string{"TEAM-A"}) {
		t.Fatal("expected exact selector to match case-insensitively")
	}
	if repositoryMatchesLabelSelectors(labels, []string{"team-b"}) {
		t.Fatal("expected non-matching selector to fail")
	}
	if repositoryMatchesLabelSelectors(nil, []string{"*"}) {
		t.Fatal("expected nil labels not to match")
	}
}
