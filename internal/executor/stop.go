package executor

import (
	"fmt"
	"sync"
)

// DefaultStopReason is recorded when a stop signal cannot explain itself.
// It keeps a reason in the report even when legacy func() bool signals are
// used, instead of reducing the cancellation to a bare boolean.
const DefaultStopReason = "stop requested at a check boundary"

// StopSignal is queried between checks and between suites. A running check,
// fix and its rollback backup always complete first; the stop only takes
// effect at the next boundary. Reason explains who requested the stop and
// why, so the report does not have to infer it from a boolean.
type StopSignal interface {
	StopRequested() bool
	StopReason() string
}

// BoolStop adapts a legacy func() bool predicate. The reason defaults to
// DefaultStopReason, keeping coverage evidence complete for callers that do
// not track why the stop happened.
type BoolStop func() bool

func (b BoolStop) StopRequested() bool {
	if b == nil {
		return false
	}
	return b()
}

func (b BoolStop) StopReason() string { return DefaultStopReason }

// StopHandle is a concurrency-safe stop signal the UI (or any caller) can
// raise once with a reason. The zero value is ready to use.
type StopHandle struct {
	mu        sync.Mutex
	requested bool
	reason    string
}

// Request marks the run for a boundary stop with the given reason. An empty
// reason falls back to DefaultStopReason. The first reason wins: a user stop
// and, say, a sudo-refresh failure must not overwrite each other's evidence.
func (h *StopHandle) Request(reason string) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.requested {
		return
	}
	h.requested = true
	if reason == "" {
		reason = DefaultStopReason
	}
	h.reason = reason
}

func (h *StopHandle) StopRequested() bool {
	if h == nil {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.requested
}

func (h *StopHandle) StopReason() string {
	if h == nil {
		return DefaultStopReason
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.reason != "" {
		return h.reason
	}
	return DefaultStopReason
}

// RunStatus is the structured outcome of a RunSuitesObserved call. It carries
// the same evidence that ends up in the report header, so callers no longer
// re-derive completeness from a boolean sampled after the fact.
type RunStatus struct {
	// Incomplete is true only when a stop left planned checks unexecuted.
	// A run that reaches the end is complete even if a stop was latched
	// during the final check, because observed then equals expected.
	Incomplete bool
	// Reason is the stop reason when Incomplete; empty on a full run.
	Reason string
	// ExpectedChecks/ObservedChecks cover every selected suite, including
	// suites that never started.
	ExpectedChecks int
	ObservedChecks int
	// Boundary is where execution was cut off; nil on a full run.
	Boundary *Boundary
}

// Boundary identifies the first check that did not run.
type Boundary struct {
	SuiteIndex int
	CheckIndex int
	SuiteTitle string
}

func (b *Boundary) String() string {
	if b == nil {
		return "no boundary"
	}
	return fmt.Sprintf("suite %d check %d", b.SuiteIndex, b.CheckIndex)
}
