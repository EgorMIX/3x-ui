package panel

import "testing"

func TestIsNewerVersionWithForkSuffix(t *testing.T) {
	cases := []struct {
		latest, current string
		want            bool
	}{
		{"v3.11.0-oidc.1", "3.11.0-oidc.1", false},
		{"v3.11.0-oidc.2", "3.11.0-oidc.1", true},
		{"v3.12.0-oidc.1", "3.11.0-oidc.2", true},
		{"v3.11.0-oidc.1", "3.11.0", true},
	}
	for _, c := range cases {
		if got := isNewerVersion(c.latest, c.current); got != c.want {
			t.Errorf("isNewerVersion(%q, %q) = %v, want %v", c.latest, c.current, got, c.want)
		}
	}
}
