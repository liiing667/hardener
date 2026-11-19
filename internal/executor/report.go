package executor

import (
	"fmt"
	"hardener/internal/config"
	"hardener/internal/ui"
	"hardener/report"
	"time"
)

// Incomplete-report reasons, recorded in AuditReport.IncompleteReason.
const (
	// IncompleteReasonStopped marks a run the user stopped between checks.
	IncompleteReasonStopped = "stopped"
	// IncompleteReasonNoChecksExecuted marks a run in which not a single
	// check executed, so the report verifies nothing.
	IncompleteReasonNoChecksExecuted = "no_checks_executed"
)

func MakeReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string) {
	makeReport(sys, suiteResults, reportType, false, "")
}

// MakeReportWithStatus explicitly marks reports from a stopped run as incomplete.
func MakeReportWithStatus(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool) {
	reason := ""
	if incomplete {
		reason = IncompleteReasonStopped
	}
	makeReport(sys, suiteResults, reportType, incomplete, reason)
}

// MakeReportIncomplete saves a report for a run that does not describe a
// complete, verifiable scan, with the reason recorded in the report.
func MakeReportIncomplete(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType, reason string) {
	makeReport(sys, suiteResults, reportType, true, reason)
}

func makeReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool, reason string) {
	auditReport := config.AuditReport{
		Incomplete:       incomplete,
		IncompleteReason: reason,
		Timestamp:        time.Now(),
		OS:               sys.OS,
		Arch:             sys.Arch,
		Distro:           sys.Distro,
		SuiteResults:     suiteResults,
		ReportType:       reportType,
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
