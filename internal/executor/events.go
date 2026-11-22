package executor

import (
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"hardener/internal/config"
)

// RunEvent carries execution state independently of terminal rendering.
// Indices, rather than titles/IDs, keep duplicate ruleset labels distinct.
// Every event emitted by RunSuitesObserved also carries the admitted run
// generation and a stable, monotonically increasing cursor within it. A
// reconnecting consumer can therefore discard a replay it already applied
// and cannot mistake events from another run for the current one.
type RunEvent struct {
	Kind       EventKind
	SuiteIndex int
	CheckIndex int
	Generation    string `json:"generation,omitempty"`
	GenerationID  string `json:"generation_id,omitempty"`
	RunGeneration string `json:"run_generation,omitempty"`
	SourceGeneration string `json:"source_generation,omitempty"`
	GenerationSource string `json:"generation_source,omitempty"`
	GenerationSeq uint64 `json:"generation_seq,omitempty"`
	Cursor        uint64 `json:"cursor,omitempty"`
	EventCursor   uint64 `json:"event_cursor,omitempty"`
	Sequence      uint64 `json:"sequence,omitempty"`
	Seq           uint64 `json:"seq,omitempty"`
	// CheckID mirrors Check.ID (or Result.ID for finished checks) so event
	// evidence stays readable even when a consumer only has the event.
	CheckID string `json:"check_id,omitempty"`
	Suite      config.TestSuite
	Check      config.Check
	Result     config.CheckResult
}

type EventKind uint8

const (
	SuiteStarted EventKind = iota
	CheckStarted
	CheckFinished
	SuiteFinished
)

type Observer func(RunEvent)

func notify(observer Observer, event RunEvent) {
	if observer != nil {
		observer(event)
	}
}

var runGenerationCounter atomic.Uint64

// NewRunGeneration returns an identity for one observed execution. The
// counter guarantees that retries get a different identity even when they
// happen within the same clock tick.
func NewRunGeneration() string {
	generation, _ := newRunIdentity()
	return generation
}

func newRunIdentity() (string, uint64) {
	sequence := runGenerationCounter.Add(1)
	return fmt.Sprintf("run-%x-%x", time.Now().UTC().UnixNano(), sequence), sequence
}

// RunEvidence is the compact provenance a dashboard, report, or external
// consumer needs to correlate an event/result with one run.
type RunEvidence struct {
	Generation       string `json:"generation"`
	GenerationID     string `json:"generation_id,omitempty"`
	SourceGeneration string `json:"source_generation,omitempty"`
	GenerationSeq    uint64 `json:"generation_seq,omitempty"`
	CheckID          string `json:"check_id,omitempty"`
	Cursor           uint64 `json:"cursor"`
	EventCursor      uint64 `json:"event_cursor,omitempty"`
}

// Evidence returns the stable run/event identity carried by the event.
func (e RunEvent) Evidence() RunEvidence {
	generation := e.effectiveGeneration()
	cursor := e.Cursor
	if cursor == 0 {
		switch {
		case e.EventCursor > 0:
			cursor = e.EventCursor
		case e.Sequence > 0:
			cursor = e.Sequence
		case e.Seq > 0:
			cursor = e.Seq
		case e.Result.Cursor > 0:
			cursor = e.Result.Cursor
		}
	}
	checkID := e.CheckID
	if checkID == "" {
		checkID = e.Check.ID
	}
	if checkID == "" {
		checkID = e.Result.ID
	}
	generationSeq := e.GenerationSeq
	if generationSeq == 0 {
		generationSeq = e.Result.GenerationSeq
	}
	return RunEvidence{
		Generation:   generation,
		GenerationID: generation,
		SourceGeneration: generation,
		GenerationSeq: generationSeq,
		CheckID:      checkID,
		Cursor:       cursor,
		EventCursor:  cursor,
	}
}

// CursorKey is the exact identity of one event. It is stable for a replay and
// includes the generation so cursors from different runs never collide.
func (e RunEvent) CursorKey() string {
	generation := e.effectiveGeneration()
	cursor := e.effectiveCursor()
	if generation == "" || cursor == 0 {
		return fmt.Sprintf("%s\x00%d\x00%d\x00%d", generation, e.Kind, e.SuiteIndex, e.CheckIndex)
	}
	return generation + "\x00" + fmt.Sprintf("%d", cursor)
}

func (e RunEvent) effectiveGeneration() string {
	for _, generation := range []string{
		e.Generation, e.GenerationID, e.RunGeneration, e.SourceGeneration, e.GenerationSource,
		e.Result.Generation, e.Result.GenerationID, e.Result.SourceGeneration, e.Result.GenerationSource,
	} {
		if generation != "" {
			return generation
		}
	}
	return ""
}

func (e RunEvent) effectiveCursor() uint64 {
	if e.Cursor > 0 {
		return e.Cursor
	}
	switch {
	case e.EventCursor > 0:
		return e.EventCursor
	case e.Sequence > 0:
		return e.Sequence
	case e.Seq > 0:
		return e.Seq
	case e.Result.Cursor > 0:
		return e.Result.Cursor
	case e.Result.EventCursor > 0:
		return e.Result.EventCursor
	}
	return 0
}

// CheckKey identifies a check position within a run. Ruleset positions are
// stable for one generation, while IDs may legitimately repeat.
func (e RunEvent) CheckKey() string {
	return fmt.Sprintf("%s\x00%d\x00%d", e.effectiveGeneration(), e.SuiteIndex, e.CheckIndex)
}

func stopRequested(stop func() bool) bool {
	return stop != nil && stop()
}

// runJournal assigns one generation and a monotonic cursor to every event.
// It is deliberately independent of the terminal renderer.
type runJournal struct {
	generation string
	sequence   uint64
	cursor     uint64
	observer   Observer
	ctx        *config.ExecContext
}

func (j *runJournal) emit(event RunEvent) uint64 {
	if j == nil {
		notify(nil, event)
		return 0
	}
	j.cursor++
	event.Generation = j.generation
	event.GenerationID = j.generation
	event.RunGeneration = j.generation
	event.SourceGeneration = j.generation
	event.GenerationSource = j.generation
	event.GenerationSeq = j.sequence
	event.Cursor = j.cursor
	event.EventCursor = j.cursor
	event.Sequence = j.cursor
	event.Seq = j.cursor
	if j.ctx != nil {
		j.ctx.EventCursor = j.cursor
		j.ctx.Cursor = j.cursor
	}
	if event.CheckID == "" {
		event.CheckID = strings.TrimSpace(event.Check.ID)
		if event.CheckID == "" {
			event.CheckID = strings.TrimSpace(event.Result.ID)
		}
	}
	if event.Kind == CheckFinished {
		event.Result.Generation = j.generation
		event.Result.GenerationID = j.generation
		event.Result.SourceGeneration = j.generation
		event.Result.GenerationSource = j.generation
		event.Result.GenerationSeq = j.sequence
		event.Result.Cursor = j.cursor
		event.Result.EventCursor = j.cursor
	}
	notify(j.observer, event)
	return j.cursor
}

// FilterSuites applies the same label matching used by execution. The dashboard
// calls it before rendering so hidden suites cannot inflate its progress total.
func FilterSuites(suites []config.TestSuite, labels []string) []config.TestSuite {
	var selected []config.TestSuite
	for _, suite := range suites {
		if suiteMatchesLabels(suite, labels) {
			selected = append(selected, suite)
		}
	}
	return selected
}
