package config

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const snapshotTestRuleset = `---
title: Updates
labels:
- system
checksuites:
- id: updates-enabled
  description: Check updates.
  command: printf 1
  expected: 1
  security_level: baseline
---
title: Firewall
labels:
- network
checksuites:
- id: firewall-on
  description: Check firewall.
  command: printf on
  expected: on
  security_level: baseline
  distro:
    debian:
      command: printf debian-on
      expected: debian-on
`

func writeRuleset(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ruleset.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A run admits one snapshot: its source, content version, and check set are
// frozen and cannot be mutated from outside or by a later edit of the file.
func TestSnapshotFreezesSourceVersionAndCheckSet(t *testing.T) {
	path := writeRuleset(t, snapshotTestRuleset)

	snap, err := LoadRulesetSnapshot(path)
	if err != nil {
		t.Fatalf("LoadRulesetSnapshot: %v", err)
	}
	if snap.Source != path {
		t.Fatalf("source not frozen: %q", snap.Source)
	}
	sum := sha256.Sum256([]byte(snapshotTestRuleset))
	if want := hex.EncodeToString(sum[:]); snap.Version != want {
		t.Fatalf("version = %q, want sha256 of the parsed bytes %q", snap.Version, want)
	}
	if len(snap.Suites) != 2 || snap.ChecksTotal() != 2 {
		t.Fatalf("check set not frozen: %+v", snap.Suites)
	}

	// The frozen set cannot be mutated through the accessor.
	frozen := snap.FrozenSuites()
	frozen[0].Checks[0].Expected = "tampered"
	frozen[1].Title = "tampered"
	if snap.Suites[0].Checks[0].Expected != "1" || snap.Suites[1].Title != "Firewall" {
		t.Fatal("snapshot mutated through FrozenSuites")
	}

	// Editing the file after admission must not retroactively change the
	// admitted snapshot; a reload is a new snapshot with a new version.
	edited := strings.Replace(snapshotTestRuleset, "expected: 1", "expected: 2", 1)
	if err := os.WriteFile(path, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}
	reloaded, err := LoadRulesetSnapshot(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if reloaded.Version == snap.Version {
		t.Fatal("edited ruleset kept the old version")
	}
	if snap.Suites[0].Checks[0].Expected != "1" {
		t.Fatal("admitted snapshot changed when the file was edited")
	}
	if reloaded.Suites[0].Checks[0].Expected != "2" {
		t.Fatal("reloaded snapshot did not pick up the edited ruleset")
	}
}

// A failed load yields no snapshot at all — never half a ruleset.
func TestSnapshotLoadIsAllOrNothing(t *testing.T) {
	broken := snapshotTestRuleset + "\n---\ntitle: Broken\nchecksuites:\n- id: [unterminated\n"
	path := writeRuleset(t, broken)

	snap, err := LoadRulesetSnapshot(path)
	if err == nil {
		t.Fatalf("broken ruleset loaded: %+v", snap)
	}
	if snap.Suites != nil || snap.Version != "" {
		t.Fatalf("failed load left a partial snapshot: %+v", snap)
	}

	if _, err := LoadRulesetSnapshot(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing ruleset loaded")
	}
}

// Inputs that loaded before must keep loading: a single suite without any
// "---" separator, the legacy "checks" list key, and a header-only first
// document with preconditions.
func TestSnapshotKeepsSingleSuiteAndLegacyYAML(t *testing.T) {
	single := "title: Only\nchecksuites:\n- id: one\n  command: printf 1\n  expected: 1\n"
	legacyChecksKey := "title: Old\nchecks:\n- id: old\n  command: printf 1\n  expected: 1\n"
	header := "preconditions:\n  tools: [sh]\n---\n" + single

	for _, tc := range []struct {
		name    string
		content string
	}{
		{"single suite, no separators", single},
		{"legacy checks key", legacyChecksKey},
		{"header preconditions", header},
	} {
		snap, err := LoadRulesetSnapshot(writeRuleset(t, tc.content))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(snap.Suites) != 1 || snap.ChecksTotal() != 1 {
			t.Fatalf("%s: got %+v", tc.name, snap.Suites)
		}
	}
}

// Legal distro overrides survive freezing and still resolve; resolving must
// not mutate the snapshot.
func TestSnapshotPreservesDistroOverrides(t *testing.T) {
	snap, err := LoadRulesetSnapshot(writeRuleset(t, snapshotTestRuleset))
	if err != nil {
		t.Fatal(err)
	}

	suites := snap.FrozenSuites()
	resolved, ok := suites[1].Checks[0].ResolveForDistro([]string{"ubuntu", "debian"}, "")
	if !ok || resolved.Command != "printf debian-on" || resolved.Expected != "debian-on" {
		t.Fatalf("distro override lost in the frozen set: %+v", resolved)
	}
	if snap.Suites[1].Checks[0].Command != "printf on" {
		t.Fatal("snapshot mutated by distro resolution")
	}

	// The distro map itself is deep-copied.
	suites[1].Checks[0].Distro["debian"] = DistroOverride{Command: "tampered"}
	if snap.Suites[1].Checks[0].Distro["debian"].Command != "printf debian-on" {
		t.Fatal("snapshot distro map mutated through FrozenSuites")
	}
}
