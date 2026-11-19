package executor

import (
	"strings"
	"testing"

	"hardener/internal/config"
)

func threeCheckSuites() []config.TestSuite {
	return []config.TestSuite{
		{Title: "First", Checks: []config.Check{
			{ID: "a1", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
			{ID: "a2", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
		}},
		{Title: "Second", Checks: []config.Check{
			{ID: "b1", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
			{ID: "b2", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
			{ID: "b3", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
		}},
	}
}

// A stop inside a suite must leave structured evidence of what ran, what did
// not, where the boundary sits and why. A boolean alone used to hide all of it.
func TestStopMidSuiteRecordsCoverageBoundaryAndReason(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	handle := &StopHandle{}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(),
		func(e RunEvent) {
			if e.Kind == CheckFinished && e.Check.ID == "a1" {
				handle.Request("user requested stop at the next check boundary")
			}
		}, handle)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Incomplete || status.Reason == "" {
		t.Fatalf("run not marked incomplete with reason: %+v", status)
	}
	if status.ExpectedChecks != 5 || status.ObservedChecks != 1 {
		t.Fatalf("run coverage wrong: %+v", status)
	}
	if status.Boundary == nil || status.Boundary.SuiteIndex != 0 || status.Boundary.CheckIndex != 1 ||
		status.Boundary.SuiteTitle != "First" {
		t.Fatalf("boundary does not point at the first unexecuted check: %+v", status.Boundary)
	}
	if len(results) != 2 {
		t.Fatalf("unstarted suite missing from report: %d suites", len(results))
	}
	first := results[0]
	if first.Status != config.SuitePartial || first.ExpectedChecks != 2 || first.ObservedChecks != 1 ||
		len(first.Checks) != 1 || first.IncompleteReason == "" {
		t.Fatalf("partial suite evidence wrong: %+v", first)
	}
	second := results[1]
	if second.Status != config.SuiteNotRun || second.ExpectedChecks != 3 || second.ObservedChecks != 0 ||
		len(second.Checks) != 0 || second.IncompleteReason == "" {
		t.Fatalf("not-run suite evidence wrong: %+v", second)
	}
}

// A stop observed between suites keeps every later suite in the report and
// records the boundary before the first check of the first skipped suite.
func TestStopBetweenSuitesMarksLaterSuitesNotRun(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	handle := &StopHandle{}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(),
		func(e RunEvent) {
			if e.Kind == SuiteFinished {
				handle.Request("sudo credential refresh failed; stopping after the current check")
			}
		}, handle)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Incomplete || !strings.Contains(status.Reason, "sudo") {
		t.Fatalf("stop reason lost: %+v", status)
	}
	if status.Boundary == nil || status.Boundary.SuiteIndex != 1 || status.Boundary.CheckIndex != -1 {
		t.Fatalf("between-suite boundary wrong: %+v", status.Boundary)
	}
	if results[0].Status != config.SuiteComplete || results[1].Status != config.SuiteNotRun {
		t.Fatalf("suite statuses wrong: %+v %+v", results[0], results[1])
	}
	if status.ExpectedChecks != 5 || status.ObservedChecks != 2 {
		t.Fatalf("coverage wrong: %+v", status)
	}
}

// Normal completion stays a complete run even when a stop was requested during
// the last check: observed equals expected, so no evidence may call it short.
func TestFullRunIsCompleteDespiteLateStopRequest(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	handle := &StopHandle{}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(),
		func(e RunEvent) {
			if e.Kind == CheckFinished && e.Check.ID == "b3" {
				handle.Request("user requested stop at the next check boundary")
			}
		}, handle)
	if err != nil {
		t.Fatal(err)
	}
	if status.Incomplete || status.Boundary != nil || status.Reason != "" {
		t.Fatalf("full run mislabelled incomplete: %+v", status)
	}
	if status.ExpectedChecks != 5 || status.ObservedChecks != 5 {
		t.Fatalf("coverage wrong: %+v", status)
	}
	for i, suite := range results {
		if suite.Status != config.SuiteComplete || suite.ObservedChecks != suite.ExpectedChecks {
			t.Fatalf("suite %d not complete: %+v", i, suite)
		}
	}
}

// The report header must make the shortening provable without trusting any
// boolean: aggregate coverage, a stop boundary and a reason are all present.
func TestBuildReportCarriesCoverageBoundaryAndReason(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	handle := &StopHandle{}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(),
		func(e RunEvent) {
			if e.Kind == CheckFinished && e.Check.ID == "a1" {
				handle.Request("user requested stop at the next check boundary")
			}
		}, handle)
	if err != nil {
		t.Fatal(err)
	}
	sys := config.SystemInfo{OS: "linux", Arch: "amd64", Distro: "test"}
	report := BuildReport(sys, results, "audit", status)
	if !report.Incomplete || report.IncompleteReason == "" {
		t.Fatalf("report missing incompleteness reason: %+v", report)
	}
	if report.ExpectedChecks != 5 || report.ObservedChecks != 1 {
		t.Fatalf("report coverage wrong: %+v", report)
	}
	if report.StopBoundary == nil || report.StopBoundary.SuiteIndex != 0 ||
		report.StopBoundary.CheckIndex != 1 || report.StopBoundary.Reason == "" {
		t.Fatalf("stop boundary evidence wrong: %+v", report.StopBoundary)
	}

	full := BuildReport(sys, threeCheckSuitesAsResults(t), "audit", RunStatus{})
	if full.Incomplete || full.StopBoundary != nil || full.IncompleteReason != "" {
		t.Fatalf("normal completion must stay clean: %+v", full)
	}
	if full.ExpectedChecks != 5 || full.ObservedChecks != 5 {
		t.Fatalf("full report coverage wrong: %+v", full)
	}
}

// Legacy bool stop signals still produce a reason, so evidence never degrades
// to a bare boolean for existing callers.
func TestBoolStopKeepsStructuredReason(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	stop := false
	_, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(),
		func(e RunEvent) {
			if e.Kind == CheckFinished && e.Check.ID == "a1" {
				stop = true
			}
		}, BoolStop(func() bool { return stop }))
	if err != nil {
		t.Fatal(err)
	}
	if !status.Incomplete || status.Reason != DefaultStopReason {
		t.Fatalf("legacy bool signal lost its reason: %+v", status)
	}
}

// A stop must not interrupt the running fix or its rollback backup. The fix
// result is retained as the last observed check and coverage stops after it.
func TestStopAfterRunningFixKeepsPartialEvidence(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/setting.conf"
	ctx := &config.ExecContext{BaseDir: dir, RunID: "test-run", SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{ID: "fix", Command: "printf 0", Expected: "1", Fix: "printf 1 > '" + path + "'", AffectedFile: path, SecurityLevel: "baseline"},
		{ID: "later", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
	}}}
	handle := &StopHandle{}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeFix, "linux", "amd64", suites,
		func(e RunEvent) {
			if e.Kind == CheckFinished {
				handle.Request("user requested stop at the next check boundary")
			}
		}, handle)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Incomplete || status.ObservedChecks != 1 || status.ExpectedChecks != 2 {
		t.Fatalf("fix-mode coverage wrong: %+v", status)
	}
	if !results[0].Checks[0].FixApplied {
		t.Fatalf("running fix result lost: %+v", results[0].Checks[0])
	}
}

func threeCheckSuitesAsResults(t *testing.T) []config.SuiteResult {
	t.Helper()
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	results, status, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", threeCheckSuites(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status.Incomplete {
		t.Fatalf("baseline run should be complete: %+v", status)
	}
	return results
}
