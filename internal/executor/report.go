package executor

import (
	"fmt"
	"hardener/internal/config"
	"hardener/internal/ui"
	"hardener/report"
	"time"
)

func MakeReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string) {
	MakeReportWithStatus(sys, suiteResults, reportType, false)
}

// MakeReportWithStatus explicitly marks reports from a stopped run as incomplete.
func MakeReportWithStatus(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool) {
	auditReport := BuildReport(sys, suiteResults, reportType, incomplete)
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

// BuildReport assembles the saved report from per-check evidence. A fix
// report stays incomplete while any remediation is pending, so a consumer
// cannot mistake a failed or interrupted verification for a hardened host.
func BuildReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool) config.AuditReport {
	auditReport := config.AuditReport{
		Incomplete:   incomplete,
		Timestamp:    time.Now(),
		OS:           sys.OS,
		Arch:         sys.Arch,
		Distro:       sys.Distro,
		SuiteResults: suiteResults,
		ReportType:   reportType,
	}
	seenLocations := make(map[string]bool)
	for _, suite := range suiteResults {
		for _, check := range suite.Checks {
			failureLocation := check.FailureLocation
			pending := check.Pending || (check.FixApplied && !check.FixVerified)
			stage := check.Stage
			failureStage := check.FailureStage
			if pending && failureLocation == "" {
				if failureStage == "" {
					failureStage = "verify"
				}
				failureLocation = fmt.Sprintf("check %s | stage %s | verification result missing",
					check.ID, failureStage)
			}
			if stage == "" && pending {
				stage = failureStage
			}
			hasEvidence := check.FixID != "" || check.FixResult != "" ||
				check.VerifyResult != "" || failureLocation != "" || pending
			if hasEvidence {
				auditReport.FixOutcomes = append(auditReport.FixOutcomes, config.FixOutcome{
					CheckID:         check.ID,
					FixID:           check.FixID,
					CompletionID:    check.CompletionID,
					Stage:           stage,
					FixResult:       check.FixResult,
					VerifyResult:    check.VerifyResult,
					FailureStage:    failureStage,
					FailureLocation: failureLocation,
					Completed:       check.FixApplied && check.FixVerified,
					Pending:         pending,
				})
			}
			if check.FixVerified {
				auditReport.FixVerified++
			}
			if pending {
				auditReport.FixPending++
				auditReport.Incomplete = true
				if auditReport.IncompleteReason == "" {
					auditReport.IncompleteReason = "fix verification pending"
				}
			}
			if check.FixResult == config.FixResultFailed && !check.FixVerified {
				auditReport.FixFailed++
				auditReport.Incomplete = true
				if auditReport.IncompleteReason == "" {
					auditReport.IncompleteReason = "fix failed"
				}
			}
			if failureLocation != "" && !seenLocations[failureLocation] {
				seenLocations[failureLocation] = true
				auditReport.FailureLocations = append(auditReport.FailureLocations, failureLocation)
			}
		}
	}
	return auditReport
}
