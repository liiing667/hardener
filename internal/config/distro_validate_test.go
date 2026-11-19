package config

import (
	"strings"
	"testing"
)

// The fixtures under testdata/ are fixed Linux profile rulesets: one legal
// distro-family-profile fallback chain and one file per defect class that
// used to let a critical check silently disappear as distro-skipped.

func TestLoadRulesetAcceptsLegalDistroProfileFallback(t *testing.T) {
	suites, err := LoadRuleset("testdata/distro_profile_valid.yaml")
	if err != nil {
		t.Fatalf("legal distro-family-profile fixture rejected: %v", err)
	}
	if len(suites) != 2 {
		t.Fatalf("expected 2 suites, got %d", len(suites))
	}
}

func TestLoadRulesetRejectsUnreachableOverrides(t *testing.T) {
	cases := []struct {
		fixture string
		want    string
	}{
		{"testdata/distro_unknown_key.yaml", `"debain" is not a known distro ID or family`},
		{"testdata/distro_profile_no_fallback.yaml", `no generic fallback "debian"`},
		{"testdata/distro_contradictory_fix.yaml", `sets fix_sudo but neither the override nor the base check defines a fix`},
		{"testdata/distro_empty_map.yaml", `distro map is empty`},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			suites, err := LoadRuleset(tc.fixture)
			if err == nil {
				t.Fatalf("expected load to fail, got %d suites", len(suites))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

func TestSplitDistroOverrideKey(t *testing.T) {
	cases := []struct {
		key        string
		wantTarget string
		wantProf   string
		wantOK     bool
	}{
		{"debian", "debian", "", true},
		{"rocky", "rocky", "", true},
		{"debian-server", "debian", "server", true},
		{"opensuse-leap-server", "opensuse-leap", "server", true},
		{"debian-web-server", "debian", "web-server", true},
		{"archlinux", "archlinux", "", true},
		{"debain", "", "", false},
		{"debain-server", "", "", false},
		{"debian-", "", "", false},
		{"windows", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			target, profile, ok := splitDistroOverrideKey(tc.key)
			if target != tc.wantTarget || profile != tc.wantProf || ok != tc.wantOK {
				t.Fatalf("splitDistroOverrideKey(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.key, target, profile, ok, tc.wantTarget, tc.wantProf, tc.wantOK)
			}
		})
	}
}

// The legal fallback chain must keep resolving exactly as before: profile
// key first, then generic distro/family keys, and false when nothing in the
// chain matches (the neutral distro skip).
func TestResolveForDistroKeepsLegalFallback(t *testing.T) {
	suites, err := LoadRuleset("testdata/distro_profile_valid.yaml")
	if err != nil {
		t.Fatalf("fixture rejected: %v", err)
	}
	check := suites[0].Checks[0]

	resolved, ok := check.ResolveForDistro([]string{"ubuntu", "debian"}, "server")
	if !ok || resolved.Command != check.Distro["debian-server"].Command {
		t.Fatalf("ubuntu+server should resolve debian-server: ok=%v cmd=%q", ok, resolved.Command)
	}

	resolved, ok = check.ResolveForDistro([]string{"ubuntu", "debian"}, "")
	if !ok || resolved.Command != check.Distro["ubuntu"].Command {
		t.Fatalf("ubuntu without profile should resolve ubuntu: ok=%v cmd=%q", ok, resolved.Command)
	}

	resolved, ok = check.ResolveForDistro([]string{"linuxmint", "debian"}, "")
	if !ok || resolved.Command != check.Distro["debian"].Command {
		t.Fatalf("linuxmint should fall back to debian family: ok=%v cmd=%q", ok, resolved.Command)
	}

	resolved, ok = check.ResolveForDistro([]string{"almalinux", "rhel", "fedora"}, "")
	if !ok || resolved.Command != check.Distro["rhel"].Command {
		t.Fatalf("almalinux should fall back to rhel family: ok=%v cmd=%q", ok, resolved.Command)
	}

	if _, ok = check.ResolveForDistro([]string{"freebsd"}, ""); ok {
		t.Fatalf("unlisted distro must stay unsupported (neutral skip), not fail or match")
	}
}

func TestValidateDistroOverridesDetectsContradictions(t *testing.T) {
	tr := true
	base := Check{ID: "c", Command: "true", Expected: "0"}

	c := base
	c.FixSudo = &tr
	if probs := c.ValidateDistroOverrides(); len(probs) != 0 {
		t.Fatalf("universal check without distro map must be valid, got %v", probs)
	}

	c = base
	c.Distro = map[string]DistroOverride{"debian": {Sudo: &tr}}
	if probs := c.ValidateDistroOverrides(); len(probs) != 0 {
		t.Fatalf("sudo override with base command is legal, got %v", probs)
	}

	c = base
	c.Distro = map[string]DistroOverride{"debian-server": {Command: "true"}, "debian": {Command: "true"}}
	if probs := c.ValidateDistroOverrides(); len(probs) != 0 {
		t.Fatalf("profile key with generic fallback is legal, got %v", probs)
	}
}
