package executor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"hardener/internal/config"
	"hardener/report"
)

// loadOnlyReport chdirs into a temp dir, runs save, and loads the report it
// wrote below <tmp>/reports.
func loadOnlyReport(t *testing.T, save func()) config.AuditReport {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	save()
	entries, err := os.ReadDir(filepath.Join(dir, "reports"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("expected exactly one report in %s: %v", dir, err)
	}
	saved, err := report.Load(filepath.Join(dir, "reports", entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	return saved
}

// A run in which every check is skipped verifies nothing. It must surface as
// ErrNoChecksExecuted so the CLI marks the report incomplete and exits
// non-zero, instead of looking like a normal run with a 0% score.
func TestEmptyOverrideFixtureExecutesNothing(t *testing.T) {
	suites, err := config.LoadRuleset("testdata/empty_override_ruleset.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if len(suites) != 1 || len(suites[0].Checks) != 2 {
		t.Fatalf("fixture changed: %+v", suites)
	}
	ctx := &config.ExecContext{SecurityLevel: "baseline", DistroName: "fixture-test-distro"}
	results, passed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if !errors.Is(err, ErrNoChecksExecuted) {
		t.Fatalf("err = %v, want ErrNoChecksExecuted", err)
	}
	// The explicit skips are still recorded, with their reasons.
	for _, check := range results[0].Checks {
		if !check.SkippedDistro || !strings.Contains(check.SkipReason, "not supported on distro") {
			t.Fatalf("skip not preserved: %+v", check)
		}
	}
	if len(passed) != 0 {
		t.Fatalf("skipped checks entered the pass rate: %v", passed)
	}
}

// The other all-skipped shapes behave the same: nothing at the selected
// level, and every required tool missing.
func TestAllSkippedRunsExecuteNothing(t *testing.T) {
	for name, check := range map[string]config.Check{
		"level filtered out": {ID: "lvl", Command: "printf 1", Expected: "1", SecurityLevel: "high"},
		"tool missing":       {ID: "tool", Command: "printf 1", Expected: "1", SecurityLevel: "baseline", RequiresCommand: "hardener_nonexistent_test_command_91823"},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := &config.ExecContext{SecurityLevel: "baseline"}
			suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{check}}}
			_, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
			if !errors.Is(err, ErrNoChecksExecuted) {
				t.Fatalf("err = %v, want ErrNoChecksExecuted", err)
			}
		})
	}
}

// A mixed run keeps its explicit skips and stays a normal, successful run.
func TestMixedRunKeepsSkipsAndSucceeds(t *testing.T) {
	ctx := &config.ExecContext{SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{ID: "runs", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
		{ID: "skipped", Command: "printf 1", Expected: "1", SecurityLevel: "high"},
	}}}
	results, passed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Checks[1].Skipped || !strings.Contains(results[0].Checks[1].SkipReason, "security level") {
		t.Fatalf("explicit skip not preserved: %+v", results[0].Checks[1])
	}
	if !passed["runs"] || len(passed) != 1 {
		t.Fatalf("executed check missing from pass rate: %v", passed)
	}
}

// A stop requested before the first check is already an incomplete run; it
// must not be reclassified as no-checks-executed.
func TestStopBeforeFirstCheckIsNotNoChecksExecuted(t *testing.T) {
	ctx := &config.ExecContext{SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{ID: "c", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
	}}}
	_, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, func() bool { return true })
	if err != nil {
		t.Fatalf("stopped run misclassified: %v", err)
	}
}

// The no-checks report is a distinct, machine-readable incomplete state; the
// schema keeps its existing fields and the skip evidence.
func TestNoChecksExecutedReportIsIncomplete(t *testing.T) {
	sys := config.SystemInfo{OS: "linux", Arch: "amd64", Distro: "fixture"}
	results := []config.SuiteResult{{Title: "Category", Checks: []config.CheckResult{
		{ID: "skipped", Skipped: true, SkipReason: "requires security level \"high\"; selected level is \"baseline\""},
	}}}
	saved := loadOnlyReport(t, func() {
		MakeReportIncomplete(sys, results, "audit", IncompleteReasonNoChecksExecuted)
	})
	if !saved.Incomplete || saved.IncompleteReason != IncompleteReasonNoChecksExecuted {
		t.Fatalf("report not marked as no_checks_executed: %+v", saved)
	}
	if saved.ReportType != "audit" || saved.OS != "linux" || saved.Arch != "amd64" || saved.Distro != "fixture" ||
		len(saved.SuiteResults) != 1 || !saved.SuiteResults[0].Checks[0].Skipped ||
		saved.SuiteResults[0].Checks[0].SkipReason == "" {
		t.Fatalf("report schema or skip evidence regressed: %+v", saved)
	}
	if saved.Timestamp.IsZero() {
		t.Fatal("timestamp missing")
	}
}

// A normal run's report stays complete and carries no incomplete reason.
func TestNormalReportStaysComplete(t *testing.T) {
	saved := loadOnlyReport(t, func() {
		MakeReport(config.SystemInfo{OS: "linux", Arch: "amd64"}, []config.SuiteResult{{Title: "Category", Checks: []config.CheckResult{
			{ID: "ok", Passed: true, Output: "1"},
		}}}, "audit")
	})
	if saved.Incomplete || saved.IncompleteReason != "" {
		t.Fatalf("normal report marked incomplete: %+v", saved)
	}
}
