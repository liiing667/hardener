package executor

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"hardener/internal/config"
)

// The saved report names the admitted ruleset snapshot, so results from
// before and after a ruleset update — or a restart — cannot be confused.
func TestReportRecordsAdmittedRuleset(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	snap := config.NewRulesetSnapshot("/guides/ruleset.yaml", "0123456789abcdef0123456789abcdef",
		[]config.TestSuite{{Title: "S"}})
	results := []config.SuiteResult{{Title: "S", Checks: []config.CheckResult{{ID: "c", Passed: true}}}}
	MakeReportWithRuleset(config.SystemInfo{OS: "linux", Arch: "amd64", Distro: "debian"}, snap, results, "audit", false)

	matches, err := filepath.Glob(filepath.Join("reports", "audit-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("report not written: %v %v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	var saved config.AuditReport
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.RulesetSource != snap.Source || saved.RulesetVersion != snap.Version {
		t.Fatalf("ruleset provenance missing: %+v", saved)
	}
	if len(saved.SuiteResults) != 1 || saved.SuiteResults[0].Checks[0].ID != "c" {
		t.Fatalf("results lost: %+v", saved)
	}
}

// Reports written without an admitted ruleset keep their legacy shape: no
// provenance fields in the JSON.
func TestReportWithoutRulesetOmitsProvenance(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	MakeReportWithStatus(config.SystemInfo{OS: "linux"}, nil, "audit", false)

	matches, err := filepath.Glob(filepath.Join("reports", "audit-*.json"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("report not written: %v %v", matches, err)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("ruleset_source")) || bytes.Contains(data, []byte("ruleset_version")) {
		t.Fatalf("legacy report gained provenance fields: %s", data)
	}
}
