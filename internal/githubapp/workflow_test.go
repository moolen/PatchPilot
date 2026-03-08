package githubapp

import "testing"

func TestRemoteBranchHeadFromLSRemote(t *testing.T) {
	t.Parallel()

	ref := "refs/heads/patchpilot/auto-fix-20260308-120000"
	output := "3c567be84d8f127b9f89a17f68ea8db611f2f50a\trefs/heads/main\n" +
		"9f8e3f3499c36afde8ece08f4f130f55557b42bd\t" + ref + "\n"

	got := remoteBranchHeadFromLSRemote(output, ref)
	if got != "9f8e3f3499c36afde8ece08f4f130f55557b42bd" {
		t.Fatalf("unexpected head sha: got %q", got)
	}
}

func TestRemoteBranchHeadFromLSRemoteNotFound(t *testing.T) {
	t.Parallel()

	ref := "refs/heads/patchpilot/auto-fix-20260308-120000"
	output := "3c567be84d8f127b9f89a17f68ea8db611f2f50a\trefs/heads/main\n"

	got := remoteBranchHeadFromLSRemote(output, ref)
	if got != "" {
		t.Fatalf("expected empty head sha when ref is absent, got %q", got)
	}
}
