package executor

import (
	"fmt"
	"hardener/internal/config"
	"hardener/internal/ui"
	"hardener/report"
	"time"
)

func MakeReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string) {
	MakeReportFromStatus(sys, suiteResults, reportType, RunStatus{})
}

// BuildReport assembles the saved report from the structured run outcome.
// Coverage is aggregated from the per-suite evidence rather than a single
// boolean: every selected suite (including never-started ones) is present,
// and observed < expected proves the run was shortened. A stop that was
// requested only during the final check leaves the run complete.
func BuildReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, status RunStatus) config.AuditReport {
	auditReport := config.AuditReport{
		Timestamp:    time.Now(),
		OS:           sys.OS,
		Arch:         sys.Arch,
		Distro:       sys.Distro,
		SuiteResults: suiteResults,
		ReportType:   reportType,
	}
	for _, suite := range suiteResults {
		auditReport.ExpectedChecks += suite.ExpectedChecks
		auditReport.ObservedChecks += suite.ObservedChecks
	}
	if status.ExpectedChecks != 0 {
		auditReport.ExpectedChecks = status.ExpectedChecks
	}
	if status.ObservedChecks != 0 {
		auditReport.ObservedChecks = status.ObservedChecks
	}
	if status.Boundary != nil && status.Incomplete {
		auditReport.Incomplete = true
		auditReport.IncompleteReason = status.Reason
		if auditReport.IncompleteReason == "" {
			auditReport.IncompleteReason = DefaultStopReason
		}
		auditReport.StopBoundary = &config.StopBoundary{
			Reason:     auditReport.IncompleteReason,
			SuiteIndex: status.Boundary.SuiteIndex,
			CheckIndex: status.Boundary.CheckIndex,
			SuiteTitle: status.Boundary.SuiteTitle,
		}
	}
	return auditReport
}

// MakeReportFromStatus persists a report that carries the run's coverage,
// stop boundary and incompleteness reason.
func MakeReportFromStatus(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, status RunStatus) {
	auditReport := BuildReport(sys, suiteResults, reportType, status)
	// Report the file Save wrote. The message used to name the binary's
	// directory, while reports go to the working directory.
	if path, err := report.Save(auditReport, ""); err != nil {
		msg := fmt.Sprintf("Failed to save report: %s\n", err)
		ui.PrintErrorMessage(msg)
	} else {
		msg := "\nSuccessfully saved " + reportType + " report to " + path + "\n"
		ui.PrintReport(msg)
	}
}

// MakeReportWithStatus keeps the legacy entry point for callers that only
// know whether the run stopped. Prefer MakeReportFromStatus, which records
// the boundary and reason instead of a bare boolean.
func MakeReportWithStatus(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool) {
	auditReport := config.AuditReport{
		Timestamp:    time.Now(),
		OS:           sys.OS,
		Arch:         sys.Arch,
		Distro:       sys.Distro,
		SuiteResults: suiteResults,
		ReportType:   reportType,
	}
	auditReport.ExpectedChecks, auditReport.ObservedChecks = coverage(suiteResults)
	if incomplete {
		auditReport.Incomplete = true
		auditReport.IncompleteReason = DefaultStopReason
	}
	// Report the file Save wrote. The message used to name the binary's
	// directory, while reports go to the working directory.
	if path, err := report.Save(auditReport, ""); err != nil {
		msg := fmt.Sprintf("Failed to save report: %s\n", err)
		ui.PrintErrorMessage(msg)
	} else {
		msg := "\nSuccessfully saved " + reportType + " report to " + path + "\n"
		ui.PrintReport(msg)
	}
}

func coverage(suiteResults []config.SuiteResult) (expected, observed int) {
	for _, suite := range suiteResults {
		expected += suite.ExpectedChecks
		observed += suite.ObservedChecks
	}
	return expected, observed
}
