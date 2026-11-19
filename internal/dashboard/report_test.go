package dashboard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"hardener/internal/config"
)

func TestScoreThresholds(t *testing.T) {
	for _, n := range []int{0, 34} {
		if scoreColor(n) != red {
			t.Errorf("%d should be red", n)
		}
	}
	for _, n := range []int{35, 64} {
		if scoreColor(n) != amber {
			t.Errorf("%d should be orange", n)
		}
	}
	for _, n := range []int{65, 100} {
		if scoreColor(n) != green {
			t.Errorf("%d should be green", n)
		}
	}
	if scoreColor(-1) != muted {
		t.Fatal("unassessed score should be neutral")
	}
}

func TestResultReasons(t *testing.T) {
	for _, tc := range []struct {
		r           config.CheckResult
		level, text string
	}{
		{config.CheckResult{Skipped: true, SkipReason: "requires strict; selected baseline", Output: "old"}, "skip", "Reason: requires strict"},
		{config.CheckResult{SkippedMissing: true, Output: "required file missing"}, "skip", "Reason: required file missing"},
		{config.CheckResult{SkippedDistro: true}, "skip", "unsupported distribution"},
		{config.CheckResult{Skipped: true}, "skip", "level not recorded"},
		{config.CheckResult{Error: "permission denied", Output: "stderr"}, "error", "Error: permission denied"},
	} {
		level, text := resultMessage(tc.r)
		if level != tc.level || !strings.Contains(text, tc.text) {
			t.Fatalf("%s: %q", level, text)
		}
	}
}

func TestLoadReports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	for _, tc := range []struct {
		json  string
		valid bool
	}{
		{`{"report_type":"audit","suite_results":[]}`, true},
		{`{"report_type":"fix","incomplete":true,"suite_results":[{"title":"Updates","checks":[{"id":"one","skipped":true,"output":"requires strict"}]}]}`, true},
		{`{}`, false}, {`null`, false}, {`{"run-id":[]}`, false},
		{`{"report_type":"audit","suite_results":null}`, true},
		{`{"report_type":"audit","suite_results":[]} trailing`, false},
	} {
		if err := os.WriteFile(path, []byte(tc.json), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadSavedReport(path)
		if (err == nil) != tc.valid {
			t.Errorf("valid=%v: %s: %v", tc.valid, tc.json, err)
		}
	}
	if _, err := loadSavedReport(path + ".missing"); err == nil {
		t.Fatal("missing file accepted")
	}
}

func TestSavedReportNavigationAndOpen(t *testing.T) {
	saved := config.AuditReport{ReportType: "audit", Incomplete: true, SuiteResults: []config.SuiteResult{
		{Title: "First", Checks: []config.CheckResult{{ID: "first", Passed: true}}},
		{Title: "Second", Checks: make([]config.CheckResult, maxLogEntries+5)},
	}}
	saved.SuiteResults[1].Checks[maxLogEntries+4] = config.CheckResult{ID: "last", Skipped: true, Output: "higher security level"}
	path := filepath.Join(t.TempDir(), "saved report.json")
	data, _ := json.Marshal(saved)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m := testModel()
	m.done, m.width, m.height = true, 120, 36
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	m = next.(model)
	m.pathInput = path
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if !m.viewing || !m.incomplete || m.opening || m.totals().passed != 1 {
		t.Fatalf("incorrect import: %+v", m)
	}
	if view := m.View(); !strings.Contains(view, "PARTIAL REPORT") || strings.Contains(view, "H  HARDENER") || !strings.Contains(view, "RECORDED CHECKS") {
		t.Fatal("incorrect saved report presentation")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = next.(model)
	logs := m.reportLogs()
	if len(logs) != maxLogEntries+5 || !strings.Contains(logs[len(logs)-1].text, "last") {
		t.Fatal("report results truncated by live log limit")
	}
	m.opening, m.pathInput = true, path+".missing"
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if m.openError == "" || !m.opening || m.selected != 1 {
		t.Fatal("failed open should retain previous report")
	}
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if next.(model).opening {
		t.Fatal("escape must close path prompt")
	}
}

func TestOpenDoesNotInterruptActiveRun(t *testing.T) {
	m := testModel()
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	if next.(model).opening || next.(model).stopping {
		t.Fatal("open must wait until execution finishes")
	}
}

// A stopped run must be reconstructable from the report alone: per-suite
// expected/observed coverage, the not-run suite, explicit NOT RUN entries and
// the incompleteness reason are all visible instead of collapsing to a flag.
func TestSavedReportShowsCoverageBoundaryAndNotRunChecks(t *testing.T) {
	saved := config.AuditReport{
		ReportType:       "audit",
		Incomplete:       true,
		IncompleteReason: "user requested stop at the next check boundary",
		ExpectedChecks:   5,
		ObservedChecks:   1,
		StopBoundary:     &config.StopBoundary{Reason: "user requested stop at the next check boundary", SuiteIndex: 0, CheckIndex: 1},
		SuiteResults: []config.SuiteResult{
			{
				Title: "First", Status: config.SuitePartial, ExpectedChecks: 2, ObservedChecks: 1,
				IncompleteReason: "user requested stop at the next check boundary",
				Checks:           []config.CheckResult{{ID: "a1", Passed: true}},
			},
			{
				Title: "Second", Status: config.SuiteNotRun, ExpectedChecks: 3, ObservedChecks: 0,
				IncompleteReason: "user requested stop at the next check boundary",
			},
		},
	}
	path := filepath.Join(t.TempDir(), "partial.json")
	data, _ := json.Marshal(saved)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	m := testModel()
	m.done, m.width, m.height = true, 120, 36
	next, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("o")})
	m = next.(model)
	m.pathInput = path
	next, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(model)
	if !m.viewing || !m.incomplete || m.incompleteReason == "" {
		t.Fatalf("incomplete evidence not imported: %+v", m)
	}
	view := m.View()
	if !strings.Contains(view, "PARTIAL REPORT") || !strings.Contains(view, "1 / 5") {
		t.Fatalf("header does not show run-wide coverage: %s", view)
	}
	if !strings.Contains(view, "NOT RUN") || !strings.Contains(view, "1/2 observed") {
		t.Fatalf("suite states/coverage not shown: %s", view)
	}
	// The second suite never started; its three planned checks appear as
	// explicit NOT RUN entries rather than vanishing.
	m.selected = 1
	logs := m.reportLogs()
	if len(logs) != 3 {
		t.Fatalf("not-run checks not enumerated: %d", len(logs))
	}
	for _, entry := range logs {
		if entry.level != "stop" || !strings.Contains(entry.text, "NOT RUN") {
			t.Fatalf("unexpected not-run entry: %+v", entry)
		}
	}
	// The partial suite keeps its observed result and adds one NOT RUN entry
	// for the check cut off at the stop boundary.
	m.selected = 0
	logs = m.reportLogs()
	if len(logs) != 2 || logs[1].level != "stop" || !strings.Contains(logs[1].text, "NOT RUN") {
		t.Fatalf("partial suite does not show the unexecuted check: %+v", logs)
	}
}

// Legacy reports without the new fields keep rendering: coverage falls back to
// the stored checks and complete suites are not mislabelled partial.
func TestLegacyReportWithoutCoverageStillLoads(t *testing.T) {
	saved := config.AuditReport{ReportType: "audit", SuiteResults: []config.SuiteResult{
		{Title: "Old", Checks: []config.CheckResult{{ID: "x", Passed: true}, {ID: "y"}}},
	}}
	m := testModel()
	m.width, m.height = 120, 36
	m.setReport(saved, "legacy.json")
	if m.incomplete || m.suites[0].status != config.SuiteComplete || m.suites[0].total != 2 {
		t.Fatalf("legacy report misclassified: %+v", m.suites[0])
	}
	if len(m.reportLogs()) != 2 {
		t.Fatal("legacy checks must remain browsable")
	}
}
