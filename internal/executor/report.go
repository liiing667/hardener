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

// BuildReport assembles the report without writing it. It binds the visible
// summary to one run generation and cursor, and rejects mixed generations.
func BuildReport(sys config.SystemInfo, suiteResults []config.SuiteResult, reportType string, incomplete bool) config.AuditReport {
	generation, cursor, mixed := ResultProvenance(suiteResults)
	generationSequence := ResultGenerationSeq(suiteResults)
	incompleteReason := ""
	if mixed {
		// A report must never present results from different runs as one
		// immutable snapshot. Fail closed and keep the evidence explicit.
		incomplete = true
		incompleteReason = "mixed_run_generations"
		generation, cursor = "", 0
		generationSequence = 0
	} else if incomplete && generation != "" {
		incompleteReason = "stopped"
	}
	auditReport := config.AuditReport{
		Incomplete:       incomplete,
		IncompleteReason: incompleteReason,
		Generation:       generation,
		RunGeneration:    generation,
		GenerationID:     generation,
		SourceGeneration: generation,
		GenerationSource: generation,
		GenerationSeq:    generationSequence,
		Cursor:           cursor,
		EventCursor:      cursor,
		LastCursor:       cursor,
		MixedGenerations: mixed,
		Timestamp:        time.Now(),
		OS:               sys.OS,
		Arch:             sys.Arch,
		Distro:           sys.Distro,
		SuiteResults:     suiteResults,
		ReportType:       reportType,
	}
	return auditReport
}

// ResultGenerationSeq returns the highest generation sequence in a result
// set. It lets a restarted dashboard distinguish a newer run from a delayed
// event belonging to an older one.
func ResultGenerationSeq(suiteResults []config.SuiteResult) uint64 {
	var sequence uint64
	for _, suite := range suiteResults {
		if suite.GenerationSeq > sequence {
			sequence = suite.GenerationSeq
		}
		for _, check := range suite.Checks {
			if check.GenerationSeq > sequence {
				sequence = check.GenerationSeq
			}
		}
	}
	return sequence
}

// ResultProvenance returns the common generation and the highest committed
// event cursor carried by suite/check results. Legitimate old result sets
// have no provenance and therefore return empty values with mixed=false.
// Results from two generations are rejected rather than silently combined.
func ResultProvenance(suiteResults []config.SuiteResult) (generation string, cursor uint64, mixed bool) {
	for _, suite := range suiteResults {
		suiteGeneration := suite.Generation
		if suiteGeneration == "" {
			suiteGeneration = suite.SourceGeneration
		}
		if suiteGeneration == "" {
			suiteGeneration = suite.GenerationSource
		}
		if suiteGeneration == "" {
			suiteGeneration = suite.GenerationID
		}
		if suiteGeneration != "" {
			if generation == "" {
				generation = suiteGeneration
			} else if generation != suiteGeneration {
				return "", 0, true
			}
		}
		if suite.LastCursor > cursor {
			cursor = suite.LastCursor
		}
		if suite.Cursor > cursor {
			cursor = suite.Cursor
		}
		if suite.EventCursor > cursor {
			cursor = suite.EventCursor
		}
		for _, check := range suite.Checks {
			checkGeneration := check.Generation
			if checkGeneration == "" {
				checkGeneration = check.SourceGeneration
			}
			if checkGeneration == "" {
				checkGeneration = check.GenerationSource
			}
			if checkGeneration == "" {
				checkGeneration = check.GenerationID
			}
			if checkGeneration != "" {
				if generation == "" {
					generation = checkGeneration
				} else if generation != checkGeneration {
					return "", 0, true
				}
			}
			if check.Cursor > cursor {
				cursor = check.Cursor
			}
			if check.EventCursor > cursor {
				cursor = check.EventCursor
			}
		}
	}
	return generation, cursor, false
}

// ResultGeneration is the convenience form used by readers that only need to
// know whether a set of results belongs to one run.
func ResultGeneration(suiteResults []config.SuiteResult) string {
	generation, _, mixed := ResultProvenance(suiteResults)
	if mixed {
		return ""
	}
	return generation
}

// ResultCursor returns the last committed cursor in a result set, or zero for
// legacy results that were recorded before event cursors existed.
func ResultCursor(suiteResults []config.SuiteResult) uint64 {
	_, cursor, _ := ResultProvenance(suiteResults)
	return cursor
}
