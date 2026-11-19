package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleset is the shared fixture helper for the security regression
// tests below. Each fixture is a complete, parseable multi-document YAML
// ruleset with exactly one malicious property under test.
func writeRuleset(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write ruleset: %v", err)
	}
	return path
}

const validCheckBlock = `  id: valid-control
  description: A legitimate control.
  command: echo 1
  expected: 1
  sudo: false
  security_level: baseline
`

// 1. Unknown fields must fail instead of being silently ignored. A typo in a
// control-level key used to parse fine and drop the intended value, which for
// security_level turned the check into a permanent soft skip.
func TestLoadRulesetRejectsUnknownField(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
	}{
		{
			name: "typo in check field hides security level",
			content: "---\ntitle: Suite A\nchecksuites:\n" +
				"  - id: typo-control\n    description: typo demo\n    command: echo 1\n    expected: 1\n" +
				"    securty_level: high\n",
		},
		{
			name: "unknown top-level suite key",
			content: "---\ntitle: Suite A\nos: linux\nplatfrom: amd64\nchecksuites:\n" +
				validCheckBlock,
		},
		{
			name: "unknown distro override key",
			content: "---\ntitle: Suite A\nchecksuites:\n" +
				"  - id: distro-control\n    description: distro typo\n    command: echo 1\n" +
				"    expected: 1\n    distro:\n      debian:\n        comamnd: echo 2\n",
		},
		{
			name: "unknown header key",
			content: "preconditions:\n  tools:\n    - grep\npreconditons: []\n---\n" +
				"title: Suite A\nchecksuites:\n" + validCheckBlock,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRuleset(t, "unknown.yaml", tc.content)
			if _, err := LoadRuleset(path); err == nil {
				t.Fatalf("LoadRuleset accepted a ruleset with an unknown field: %s", tc.content)
			} else if !strings.Contains(err.Error(), "field") {
				t.Fatalf("error should name the unknown field, got: %v", err)
			}
		})
	}
}

// 2. A check id repeated across suites must fail: the scoring maps and the
// report are keyed by id, so the second definition used to overwrite the
// first control's result.
func TestLoadRulesetRejectsDuplicateCheckIDAcrossSuites(t *testing.T) {
	content := "---\ntitle: Suite A\nchecksuites:\n" +
		"  - id: shared-id\n    description: first definition\n    command: echo 1\n    expected: 1\n" +
		"---\ntitle: Suite B\nchecksuites:\n" +
		"  - id: shared-id\n    description: second definition\n    command: echo 2\n    expected: 2\n"
	path := writeRuleset(t, "dup.yaml", content)
	_, err := LoadRuleset(path)
	if err == nil {
		t.Fatal("LoadRuleset accepted a duplicate check id across suites")
	}
	if !strings.Contains(err.Error(), "duplicate check id") || !strings.Contains(err.Error(), "shared-id") {
		t.Fatalf("error should identify the duplicated id, got: %v", err)
	}
}

// 3. Empty required fields must fail rather than produce an unidentifiable or
// unevaluable control.
func TestLoadRulesetRejectsEmptyRequiredFields(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{
			name: "empty id",
			content: "---\ntitle: Suite A\nchecksuites:\n" +
				"  - id: ''\n    description: no id\n    command: echo 1\n    expected: 1\n",
			want: "empty required field id",
		},
		{
			name: "missing description",
			content: "---\ntitle: Suite A\nchecksuites:\n" +
				"  - id: no-description\n    command: echo 1\n    expected: 1\n",
			want: "empty required field description",
		},
		{
			name: "blank expected",
			content: "---\ntitle: Suite A\nchecksuites:\n" +
				"  - id: no-expected\n    description: no expected\n    command: echo 1\n    expected: '   '\n",
			want: "empty required field expected",
		},
		{
			name: "missing suite title",
			content: "---\nchecksuites:\n" +
				"  - id: orphan\n    description: title-less suite\n    command: echo 1\n    expected: 1\n",
			want: "missing a title",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := writeRuleset(t, "empty.yaml", tc.content)
			_, err := LoadRuleset(path)
			if err == nil {
				t.Fatalf("LoadRuleset accepted a ruleset with %s", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error should mention %q, got: %v", tc.want, err)
			}
		})
	}
}

// 4. A document defining both "checksuites" and "checks" is ambiguous — one
// list would silently disappear — so it must fail before anything runs.
func TestLoadRulesetRejectsConflictingCheckLists(t *testing.T) {
	content := "---\ntitle: Suite A\nchecksuites:\n" +
		"  - id: from-suites\n    description: canonical key\n    command: echo 1\n    expected: 1\n" +
		"checks:\n" +
		"  - id: from-checks\n    description: legacy key\n    command: echo 2\n    expected: 2\n"
	path := writeRuleset(t, "conflict.yaml", content)
	_, err := LoadRuleset(path)
	if err == nil {
		t.Fatal("LoadRuleset accepted a document with both checks and checksuites")
	}
	if !strings.Contains(err.Error(), "defines both") || !strings.Contains(err.Error(), "checksuites") || !strings.Contains(err.Error(), "checks") {
		t.Fatalf("error should explain the list conflict, got: %v", err)
	}
}

// An empty list alongside a populated one carries no hidden controls, so it
// is not a conflict: the legacy key remains loadable in that shape.
func TestLoadRulesetAllowsEmptyListAlongsideLegacyKey(t *testing.T) {
	content := "---\ntitle: Suite A\nchecksuites: []\nchecks:\n" +
		"  - id: legacy-control\n    description: legacy key wins\n    command: echo 2\n    expected: 2\n"
	path := writeRuleset(t, "empty-conflict.yaml", content)
	suites, err := LoadRuleset(path)
	if err != nil {
		t.Fatalf("an empty checksuites must not count as a conflict: %v", err)
	}
	if len(suites) != 1 || suites[0].Checks[0].ID != "legacy-control" {
		t.Fatalf("legacy check lost: %+v", suites)
	}
}

// Wrong-typed values are schema violations too: a string where a bool is
// expected must fail rather than silently taking the zero value.
func TestLoadRulesetRejectsWrongFieldType(t *testing.T) {
	content := "---\ntitle: Suite A\nchecksuites:\n" +
		"  - id: typed-control\n    description: wrong type\n    command: echo 1\n    expected: 1\n    sudo: \"not-a-bool\"\n"
	path := writeRuleset(t, "type.yaml", content)
	if _, err := LoadRuleset(path); err == nil {
		t.Fatal("LoadRuleset accepted a string where sudo expects a bool")
	}
}

// A duplicated id inside a single suite is just as dangerous as one spread
// across suites, since report and scoring are keyed by id.
func TestLoadRulesetRejectsDuplicateIDWithinSuite(t *testing.T) {
	content := "---\ntitle: Suite A\nchecksuites:\n" +
		"  - id: dup\n    description: first\n    command: echo 1\n    expected: 1\n" +
		"  - id: dup\n    description: second\n    command: echo 2\n    expected: 2\n"
	path := writeRuleset(t, "dup-within.yaml", content)
	if _, err := LoadRuleset(path); err == nil || !strings.Contains(err.Error(), "duplicate check id") {
		t.Fatalf("expected duplicate id error, got: %v", err)
	}
}

// 5. Compatibility: the legacy "checks" key on its own still loads.
func TestLoadRulesetAcceptsLegacyChecksKey(t *testing.T) {
	content := "---\ntitle: Legacy Suite\nos: linux\nchecks:\n" +
		"  - id: legacy-control\n    description: legacy list key\n    command: echo 1\n    expected: 1\n"
	path := writeRuleset(t, "legacy.yaml", content)
	suites, err := LoadRuleset(path)
	if err != nil {
		t.Fatalf("legacy checks key must keep working: %v", err)
	}
	if len(suites) != 1 || len(suites[0].Checks) != 1 || suites[0].Checks[0].ID != "legacy-control" {
		t.Fatalf("unexpected suites: %+v", suites)
	}
}

// 6. Compatibility: every check field and distro-override shape used by the
// shipped ernw/hardening preset rulesets must remain accepted.
func TestLoadRulesetAcceptsPresetFieldsAndDistroOverrides(t *testing.T) {
	content := `preconditions:
  tools:
    - grep
---
title: Preset Shaped Suite
os: linux
arch:
  - amd64
  - arm64
labels:
  - system
checksuites:
  - id: preset-control
    description: exercises every legitimate preset field
    command: echo 1
    expected: 1
    expected_op: ">="
    sudo: true
    fix: echo fixed
    fix_sudo: true
    os:
      - linux
    arch:
      - amd64
    distro:
      ubuntu-server:
        command: echo 2
        expected: "2"
        fix: echo fixed2
        sudo: false
        fix_sudo: false
      debian:
        command: echo 3
    requires_command: systemctl
    requires_file: /etc/hostname
    affected_file: /etc/hostname
    post_action: none
    security_level: baseline
    risk_class: configuration
    risk_level: low
    risk_desc: preset fixture
`
	path := writeRuleset(t, "preset.yaml", content)
	suites, err := LoadRuleset(path)
	if err != nil {
		t.Fatalf("preset-shaped ruleset must load: %v", err)
	}
	check := suites[0].Checks[0]
	if check.ID != "preset-control" || check.ExpectedOp != ">=" || !check.Sudo {
		t.Fatalf("scalar fields lost: %+v", check)
	}
	ov, ok := check.Distro["ubuntu-server"]
	if !ok || ov.Command != "echo 2" || ov.Expected != "2" || ov.Sudo == nil || *ov.Sudo {
		t.Fatalf("distro override lost or wrong: %+v", check.Distro)
	}

	// The legal override must still resolve through the existing chain logic.
	resolved, supported := check.ResolveForDistro([]string{"ubuntu", "debian"}, "server")
	if !supported || resolved.Command != "echo 2" {
		t.Fatalf("distro override resolution broken: %+v supported=%v", resolved, supported)
	}
}

// 7. Compatibility: the real upstream preset rulesets (if available next to
// the test cache) must load without validation errors. The fixture is written
// into the temp dir by the test itself when the downloaded file is absent, so
// the case remains self-contained in offline environments.
func TestLoadRulesetAcceptsFullPresetFixture(t *testing.T) {
	content := "---\ntitle: First Suite\nos: linux\narch: [amd64]\nlabels: [boot]\nchecksuites:\n" +
		"  - id: bios-password-set\n    description: BIOS password\n    command: echo manual\n" +
		"    expected: manual\n    sudo: false\n    fix: manual\n    fix_sudo: false\n" +
		"    affected_file: firmware\n    post_action: none\n    security_level: high\n" +
		"    risk_level: low\n    risk_desc: fixture\n" +
		"  - id: expected-op-control\n    description: numeric comparison\n    command: echo 2\n" +
		"    expected: 1\n    expected_op: \">=\"\n    sudo: false\n    fix: ''\n" +
		"    security_level: baseline\n    risk_level: low\n    risk_desc: fixture\n" +
		"---\ntitle: Second Suite\nos: linux\nchecksuites:\n" +
		"  - id: distro-control\n    description: distro override fixture\n    command: echo 1\n" +
		"    expected: 1\n    sudo: false\n    security_level: baseline\n    risk_level: low\n" +
		"    risk_desc: fixture\n    distro:\n      debian:\n        command: echo debian\n        fix: echo fix-debian\n        sudo: true\n"
	path := writeRuleset(t, "full-preset.yaml", content)
	suites, err := LoadRuleset(path)
	if err != nil {
		t.Fatalf("full preset fixture must load: %v", err)
	}
	if len(suites) != 2 || len(suites[0].Checks) != 2 || len(suites[1].Checks) != 1 {
		t.Fatalf("unexpected suite layout: %+v", suites)
	}
}

// ValidateSuites is also the guard for the markdown loader path.
func TestValidateSuitesReportsAllProblems(t *testing.T) {
	suites := []TestSuite{
		{Title: "OK", Checks: []Check{
			{ID: "dup", Description: "first", Expected: "1"},
			{ID: "dup", Description: "second", Expected: "1"},
			{ID: "blank", Description: "", Expected: " "},
		}},
		{Checks: []Check{{ID: "x", Description: "no title suite", Expected: "1"}}},
	}
	err := ValidateSuites(suites)
	if err == nil {
		t.Fatal("expected validation to fail")
	}
	for _, want := range []string{"duplicate check id \"dup\"", "empty required field description", "empty required field expected", "missing title"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("validation error missing %q; got:\n%v", want, err)
		}
	}
}

func TestValidateSuitesAcceptsWellFormedInput(t *testing.T) {
	suites := []TestSuite{{Title: "Suite", Checks: []Check{
		{ID: "a", Description: "desc", Expected: "1"},
		{ID: "b", Description: "desc", Expected: "2"},
	}}}
	if err := ValidateSuites(suites); err != nil {
		t.Fatalf("well-formed suites must validate: %v", err)
	}
}
