package executor

import (
	"testing"

	"hardener/internal/config"
)

// Every event from an observed run must identify the same generation and
// carry a strictly increasing cursor. Result entries keep the cursor of the
// CheckFinished event that committed them.
func TestLocalEvidenceObservedRunPublishesGenerationAndCursor(t *testing.T) {
	ctx := &config.ExecContext{BaseDir: t.TempDir(), SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{ID: "one", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
		{ID: "two", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
	}}}

	var events []RunEvent
	results, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, func(event RunEvent) {
		events = append(events, event)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) == 0 {
		t.Fatal("no events observed")
	}
	generation := events[0].Generation
	if generation == "" || ctx.Generation != generation {
		t.Fatalf("generation not published: events=%q context=%q", generation, ctx.Generation)
	}
	var previous uint64
	for i, event := range events {
		if event.Generation != generation || event.GenerationID != generation {
			t.Fatalf("event %d lost its generation: %+v", i, event)
		}
		if event.Cursor == 0 || event.Cursor <= previous {
			t.Fatalf("event %d cursor is not monotonic: %d after %d", i, event.Cursor, previous)
		}
		previous = event.Cursor
		if event.Kind == CheckFinished && event.Result.Cursor != event.Cursor {
			t.Fatalf("result cursor differs from its event: %+v", event)
		}
	}
	if len(results) != 1 || results[0].Generation != generation || results[0].LastCursor != previous {
		t.Fatalf("suite evidence does not match the stream: %+v", results)
	}
	for _, check := range results[0].Checks {
		if check.Generation != generation || check.Cursor == 0 {
			t.Fatalf("check evidence lost: %+v", check)
		}
	}
}

// A retry gets a new generation so a restarted consumer cannot reuse the old
// cursor sequence or mix the two result sets.
func TestLocalEvidenceRetryStartsWithNewGeneration(t *testing.T) {
	ctx := &config.ExecContext{SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{ID: "one", Command: "printf 1", Expected: "1", SecurityLevel: "baseline"},
	}}}

	first, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstGeneration := first[0].Generation
	second, _, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if firstGeneration == "" || second[0].Generation == "" || firstGeneration == second[0].Generation {
		t.Fatalf("retry reused a generation: %q -> %q", firstGeneration, second[0].Generation)
	}
}

func TestLocalEvidenceResultProvenanceRejectsMixedGenerations(t *testing.T) {
	results := []config.SuiteResult{
		{Generation: "run-1", LastCursor: 3, Checks: []config.CheckResult{{Generation: "run-1", Cursor: 2}}},
		{Generation: "run-2", LastCursor: 4, Checks: []config.CheckResult{{Generation: "run-2", Cursor: 4}}},
	}
	if _, _, mixed := ResultProvenance(results); !mixed {
		t.Fatal("mixed generations were accepted")
	}
	report := BuildReport(config.SystemInfo{OS: "linux"}, results, "audit", false)
	if !report.Incomplete || !report.MixedGenerations || report.Generation != "" {
		t.Fatalf("mixed report was not failed closed: %+v", report)
	}
}
