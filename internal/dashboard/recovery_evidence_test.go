package dashboard

import (
	"testing"

	"hardener/internal/config"
	"hardener/internal/executor"
)

func recoveryEvidenceEvent32011(index int, generation string, cursor uint64, id string) executor.RunEvent {
	return executor.RunEvent{
		Kind:       executor.CheckFinished,
		SuiteIndex: 0,
		CheckIndex: index,
		Generation: generation,
		Cursor:     cursor,
		Result:     config.CheckResult{ID: id, Passed: true, Generation: generation, Cursor: cursor},
	}
}

// Replaying a complete event stream must not add the same check twice.
func TestLocalEvidenceDashboardReplayDoesNotDoubleCount(t *testing.T) {
	m := testModel()
	events := []executor.RunEvent{
		{Kind: executor.SuiteStarted, SuiteIndex: 0, Generation: "gen-1", Cursor: 1},
		recoveryEvidenceEvent32011(0, "gen-1", 2, "first"),
		recoveryEvidenceEvent32011(1, "gen-1", 3, "second"),
		{Kind: executor.SuiteFinished, SuiteIndex: 0, Generation: "gen-1", Cursor: 4},
	}
	for _, event := range events {
		m.applyEvent(event)
	}
	before := m.totals()
	if before.complete != 2 || before.passed != 2 || m.generation != "gen-1" || m.cursor != 4 {
		t.Fatalf("first pass was scored incorrectly: %+v generation=%q cursor=%d", before, m.generation, m.cursor)
	}
	for _, event := range events {
		m.applyEvent(event)
	}
	after := m.totals()
	if after != before {
		t.Fatalf("replay changed the score: %+v -> %+v", before, after)
	}
}

// Out-of-order events are applied by check identity, so the final score
// matches ordered delivery.
func TestLocalEvidenceDashboardHandlesOutOfOrderEvents(t *testing.T) {
	m := testModel()
	m.applyEvent(recoveryEvidenceEvent32011(0, "gen-1", 1, "first"))
	m.applyEvent(recoveryEvidenceEvent32011(2, "gen-1", 3, "third"))
	if got := m.totals().complete; got != 2 {
		t.Fatalf("received checks were not applied: %d", got)
	}
	m.applyEvent(recoveryEvidenceEvent32011(1, "gen-1", 2, "second"))
	if got := m.totals().complete; got != 3 || m.cursor != 3 || m.totals().passed != 3 {
		t.Fatalf("out-of-order replay did not converge: %+v cursor=%d", m.totals(), m.cursor)
	}
}

// A new generation is staged until it covers every planned check. A partial
// reconnect leaves the complete old snapshot visible instead of mixing old
// results with the received half of the new run.
func TestLocalEvidenceDashboardCommitsOnlyCompleteGeneration(t *testing.T) {
	m := testModel()
	for i := 0; i < m.suites[0].total; i++ {
		m.applyEvent(recoveryEvidenceEvent32011(i, "gen-1", uint64(i+1), "old"))
	}
	for i := 0; i < m.suites[1].total; i++ {
		event := recoveryEvidenceEvent32011(i, "gen-1", uint64(4+i), "old")
		event.SuiteIndex = 1
		m.applyEvent(event)
	}
	if m.totals().complete != 5 || m.generation != "gen-1" {
		t.Fatalf("old snapshot was not complete: %+v", m.totals())
	}

	// Only the second half of the new generation arrives.
	partial := recoveryEvidenceEvent32011(1, "gen-2", 2, "new")
	m.applyEvent(partial)
	if m.generation != "gen-1" || m.totals().complete != 5 || m.totals().passed != 5 {
		t.Fatalf("partial generation replaced or extended the old snapshot: %+v generation=%q", m.totals(), m.generation)
	}

	// The missing prefix arrives; the whole candidate is published once.
	for i := 0; i < m.suites[0].total; i++ {
		m.applyEvent(recoveryEvidenceEvent32011(i, "gen-2", uint64(i+1), "new"))
	}
	for i := 0; i < m.suites[1].total; i++ {
		event := recoveryEvidenceEvent32011(i, "gen-2", uint64(4+i), "new")
		event.SuiteIndex = 1
		m.applyEvent(event)
	}
	if m.generation != "gen-2" || m.totals().complete != 5 || m.totals().passed != 5 || m.cursor != 5 {
		t.Fatalf("complete generation was not committed: %+v generation=%q cursor=%d", m.totals(), m.generation, m.cursor)
	}
}
