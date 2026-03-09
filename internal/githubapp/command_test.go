package githubapp

import "testing"

func TestParseFixCommand(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantFound bool
		wantErr   bool
		want      FixCommand
	}{
		{
			name:      "no command",
			body:      "hello world",
			wantFound: false,
		},
		{
			name:      "basic command",
			body:      "/patchpilot fix",
			wantFound: true,
			want:      FixCommand{},
		},
		{
			name:      "policy and automerge",
			body:      "/patchpilot fix --policy .patchpilot.yaml --auto-merge",
			wantFound: true,
			want: FixCommand{
				PolicyPath: ".patchpilot.yaml",
				AutoMerge:  true,
			},
		},
		{
			name:      "policy mode merge",
			body:      "/patchpilot fix --policy /etc/patchpilot/central.yaml --policy-mode merge",
			wantFound: true,
			want: FixCommand{
				PolicyPath: "/etc/patchpilot/central.yaml",
				PolicyMode: "merge",
			},
		},
		{
			name:      "unknown option",
			body:      "/patchpilot fix --wat",
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "missing policy value",
			body:      "/patchpilot fix --policy",
			wantFound: true,
			wantErr:   true,
		},
		{
			name:      "invalid policy mode",
			body:      "/patchpilot fix --policy-mode invalid",
			wantFound: true,
			wantErr:   true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, found, err := ParseFixCommand(test.body)
			if found != test.wantFound {
				t.Fatalf("found = %t, want %t", found, test.wantFound)
			}
			if test.wantErr && err == nil {
				t.Fatalf("expected error")
			}
			if !test.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !test.wantErr && got != test.want {
				t.Fatalf("got %#v, want %#v", got, test.want)
			}
		})
	}
}
