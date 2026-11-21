package dashboard

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"

	"hardener/internal/config"
)

// The live header names the admitted ruleset snapshot, so the checks on
// screen are attributable to one ruleset version.
func TestRulesetProvenanceAppearsInHeader(t *testing.T) {
	suites := []config.TestSuite{{Title: "S", Checks: make([]config.Check, 1)}}
	m := newModel(Options{
		Mode: "audit", System: "linux / amd64", SecurityLevel: "baseline",
		Ruleset: "ruleset.yaml@0123456789ab",
	}, suites, nil, nil)
	m.width, m.height = 120, 36
	if view := ansi.Strip(m.View()); !strings.Contains(view, "ruleset.yaml@0123456789ab") {
		t.Fatal("admitted ruleset version not shown")
	}
}

// A saved report's recorded ruleset version is shown when browsing it.
func TestSavedReportShowsRecordedRulesetVersion(t *testing.T) {
	saved := config.AuditReport{
		ReportType:     "audit",
		RulesetSource:  "/guides/ruleset.yaml",
		RulesetVersion: "0123456789abcdef",
		SuiteResults:   []config.SuiteResult{{Title: "S", Checks: []config.CheckResult{{ID: "c", Passed: true}}}},
	}
	m := newModel(Options{Mode: "report"}, nil, nil, nil)
	m.width, m.height = 120, 36
	m.setReport(saved, "/tmp/report.json")
	if m.options.Ruleset != "ruleset.yaml@0123456789ab" {
		t.Fatalf("recorded ruleset version not picked up: %q", m.options.Ruleset)
	}
	if view := ansi.Strip(m.View()); !strings.Contains(view, "ruleset.yaml@0123456789ab") {
		t.Fatal("recorded ruleset version not shown")
	}
}
