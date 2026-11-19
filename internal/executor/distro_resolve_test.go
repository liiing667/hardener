package executor

import (
	"strings"
	"testing"

	"hardener/internal/config"
)

// loadProfileFixture loads the fixed Linux profile ruleset shared with the
// config package tests.
func loadProfileFixture(t *testing.T) config.Check {
	t.Helper()
	suites, err := config.LoadRuleset("../config/testdata/distro_profile_valid.yaml")
	if err != nil {
		t.Fatalf("legal distro-family-profile fixture rejected at load: %v", err)
	}
	return suites[0].Checks[0]
}

// A legal distro-family-profile override chain must resolve and run, not
// distro-skip: profile key first, generic distro next, family as fallback.
func TestRunCheckResolvesDistroProfileFallback(t *testing.T) {
	check := loadProfileFixture(t)
	cases := []struct {
		name    string
		chain   []string
		profile string
		wantKey string
	}{
		{"profile key wins", []string{"ubuntu", "debian"}, "server", "debian-server"},
		{"exact distro without profile", []string{"ubuntu", "debian"}, "", "ubuntu"},
		{"family fallback", []string{"linuxmint", "debian"}, "", "debian"},
		{"family fallback with unmatched profile", []string{"rocky", "rhel", "fedora"}, "server", "rocky"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &config.ExecContext{
				DistroName:    tc.chain[0],
				DistroFamily:  tc.chain,
				Profile:       tc.profile,
				SecurityLevel: "baseline",
			}
			result, ran := runCheck(ctx, ModeAudit, check, "baseline")
			if result.SkippedDistro {
				t.Fatalf("legal override chain distro-skipped: %+v", result)
			}
			if want := check.Distro[tc.wantKey].Command; ran.Command != want {
				t.Fatalf("resolved command = %q, want key %q (%q)", ran.Command, tc.wantKey, want)
			}
		})
	}
}

// The neutral distro skip must stay: a check whose distro map simply does
// not list the current distro is skipped, not failed, and stays out of the
// score.
func TestRunCheckKeepsNeutralDistroSkip(t *testing.T) {
	check := loadProfileFixture(t)
	ctx := &config.ExecContext{
		DistroName:    "freebsd",
		DistroFamily:  []string{"freebsd"},
		SecurityLevel: "baseline",
	}
	result, _ := runCheck(ctx, ModeAudit, check, "baseline")
	if !result.SkippedDistro || !strings.Contains(result.SkipReason, "not supported on distro") {
		t.Fatalf("expected neutral distro skip, got %+v", result)
	}
	if result.Error != "" || result.Passed {
		t.Fatalf("distro-skipped check must be neutral, got %+v", result)
	}
}
