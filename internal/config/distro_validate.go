package config

import (
	"fmt"
	"sort"
	"strings"
)

// This file validates distro override maps at load time. A distro-map key
// that never matches (typo'd distro name, unknown target) or that only
// matches under a profile (no generic fallback) makes ResolveForDistro
// report the check as unsupported, so the whole check is distro-skipped and
// silently drops out of the score. Failing loudly while the ruleset loads
// turns that silent disappearance into an actionable error, while legal
// distro/family/profile keys and the neutral runtime distro skip stay
// untouched.

// ValidateSuitesDistroOverrides validates the distro map of every check in
// every suite and returns all problems as a single error. Both loading
// paths (LoadRuleset and LoadChecks) call it before returning suites.
func ValidateSuitesDistroOverrides(suites []TestSuite) error {
	var problems []string
	for _, s := range suites {
		for _, c := range s.Checks {
			for _, p := range c.ValidateDistroOverrides() {
				problems = append(problems, fmt.Sprintf("suite %q, check %q: %s", s.Title, c.ID, p))
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("invalid distro overrides:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// ValidateDistroOverrides returns one human-readable problem per defect in
// the check's distro map. A check without a distro map is universal and
// always valid.
func (c Check) ValidateDistroOverrides() []string {
	if c.Distro == nil {
		return nil
	}
	if len(c.Distro) == 0 {
		return []string{"distro map is empty: remove it or add at least one target"}
	}

	var problems []string

	// A base check that declares fix_sudo without any fix is contradictory
	// regardless of overrides.
	if c.FixSudo != nil && strings.TrimSpace(c.Fix) == "" {
		problems = append(problems, "sets fix_sudo but defines no fix")
	}

	// profileKeys collects the profile-qualified keys per target so a
	// missing generic fallback can be reported after the key loop.
	profileKeys := make(map[string][]string)

	for _, key := range sortedDistroKeys(c.Distro) {
		ov := c.Distro[key]

		target, profile, known := splitDistroOverrideKey(key)
		switch {
		case !known:
			problems = append(problems, fmt.Sprintf(
				"distro override key %q is not a known distro ID or family (nor <target>-<profile>): it can never match, so the check would be distro-skipped everywhere", key))
		case profile != "":
			profileKeys[target] = append(profileKeys[target], key)
		}

		// Contradictory sudo/fix combinations: fix_sudo with no fix to
		// privilege, or sudo with no command to run.
		if ov.FixSudo != nil && strings.TrimSpace(ov.Fix) == "" && strings.TrimSpace(c.Fix) == "" {
			problems = append(problems, fmt.Sprintf(
				"distro override %q sets fix_sudo but neither the override nor the base check defines a fix", key))
		}
		if ov.Sudo != nil && strings.TrimSpace(ov.Command) == "" && strings.TrimSpace(c.Command) == "" {
			problems = append(problems, fmt.Sprintf(
				"distro override %q sets sudo but neither the override nor the base check defines a command", key))
		}
	}

	for _, target := range sortedTargets(profileKeys) {
		if _, ok := c.Distro[target]; ok {
			continue
		}
		problems = append(problems, fmt.Sprintf(
			"profile override(s) %s have no generic fallback %q: without a matching --profile the check would be distro-skipped on %s",
			strings.Join(quoteAll(profileKeys[target]), ", "), target, target))
	}

	return problems
}

// splitDistroOverrideKey splits a distro-map key into its target (a known
// distro ID or family) and optional profile suffix. The longest known
// target wins, so "opensuse-leap-server" splits as opensuse-leap + server.
// ok is false when no known target matches — the key can never resolve.
func splitDistroOverrideKey(key string) (target, profile string, ok bool) {
	targets := knownDistroTargets()
	if targets[key] {
		return key, "", true
	}
	best := ""
	for t := range targets {
		if strings.HasPrefix(key, t+"-") && len(t) > len(best) {
			best = t
		}
	}
	if best == "" {
		return "", "", false
	}
	profile = key[len(best)+1:]
	if profile == "" {
		return "", "", false
	}
	return best, profile, true
}

func sortedDistroKeys(m map[string]DistroOverride) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedTargets(m map[string][]string) []string {
	targets := make([]string, 0, len(m))
	for t := range m {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	return targets
}

func quoteAll(s []string) []string {
	out := make([]string, len(s))
	for i, v := range s {
		out[i] = fmt.Sprintf("%q", v)
	}
	return out
}
