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
	generation, source, checkSetHash, mixed := ResultProvenance(suiteResults)
	hostHash, hostMixed := resultHostHash(suiteResults)
	if hostMixed {
		mixed = true
	}
	incompleteReason := ""
	for _, suite := range suiteResults {
		if suite.Incomplete {
			incomplete = true
			if incompleteReason == "" {
				incompleteReason = suite.IncompleteReason
			}
		}
	}
	if mixed {
		// Never publish a report that silently combines results from two host
		// generations. This is a last line of defense for callers that build
		// suite results outside RunSuitesObserved.
		incomplete = true
		incompleteReason = "mixed_run_generations"
		generation, source, checkSetHash, hostHash = "", "", "", ""
	} else if incomplete {
		if incompleteReason == "" {
			incompleteReason = "stopped"
		}
	}
	auditReport := config.AuditReport{
		Incomplete:       incomplete,
		IncompleteReason: incompleteReason,
		Generation:       generation,
		RunGeneration:    generation,
		HostGeneration:   generation,
		GenerationSource: source,
		FitSource:        source,
		CheckSetHash:     checkSetHash,
		HostHash:         hostHash,
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

func resultHostHash(suiteResults []config.SuiteResult) (string, bool) {
	hostHash := ""
	for _, suite := range suiteResults {
		if suite.HostHash == "" {
			continue
		}
		if hostHash == "" {
			hostHash = suite.HostHash
		} else if hostHash != suite.HostHash {
			return "", true
		}
	}
	return hostHash, false
}

// ResultGeneration returns the common generation of all recorded results. It
// returns "" when no generation was recorded (old reports) or when results
// from different generations were accidentally combined.
func ResultGeneration(suiteResults []config.SuiteResult) string {
	generation, _, _, mixed := ResultProvenance(suiteResults)
	if mixed {
		return ""
	}
	if _, hostMixed := resultHostHash(suiteResults); hostMixed {
		return ""
	}
	return generation
}

// ResultProvenance extracts the generation evidence carried by suite/check
// results. Legacy result sets with no generation fields are accepted and keep
// their previous report shape.
func ResultProvenance(suiteResults []config.SuiteResult) (generation, source, checkSetHash string, mixed bool) {
	hostHash := ""
	for _, suite := range suiteResults {
		for _, check := range suite.Checks {
			if check.Generation == "" {
				continue
			}
			if generation == "" {
				generation = check.Generation
			} else if generation != check.Generation {
				return "", "", "", true
			}
			if source == "" {
				source = check.FitSource
			}
		}
		if suite.Generation != "" {
			if generation == "" {
				generation = suite.Generation
			} else if generation != suite.Generation {
				return "", "", "", true
			}
		}
		if source == "" {
			source = suite.GenerationSource
		}
		if suite.CheckSetHash != "" {
			if checkSetHash == "" {
				checkSetHash = suite.CheckSetHash
			} else if checkSetHash != suite.CheckSetHash {
				return "", "", "", true
			}
		}
		if suite.HostHash != "" {
			if hostHash == "" {
				hostHash = suite.HostHash
			} else if hostHash != suite.HostHash {
				return "", "", "", true
			}
		}
	}
	return generation, source, checkSetHash, false
}
