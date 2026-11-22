package dashboard

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"hardener/internal/config"
	"hardener/internal/executor"
	"hardener/internal/ui"
)

const maxLogEntries = 800

type suiteState struct {
	logs       []logEntry
	title      string
	total      int
	results    map[int]config.CheckResult
	done       bool
	generation string
	generationSeq uint64
	cursor     uint64
}

type counts struct {
	total, complete, passed, failed, errors, fixed, unverified, skipped, manual int
}

func (c counts) assessed() int { return c.passed + c.failed + c.errors + c.fixed + c.unverified }
func (c counts) percent() int {
	if c.assessed() == 0 {
		return -1
	}
	return 100 * c.passed / c.assessed()
}

func (s suiteState) counts() counts {
	c := counts{total: s.total, complete: len(s.results)}
	for _, result := range s.results {
		switch {
		case result.Skipped || result.SkippedDistro || result.SkippedMissing:
			c.skipped++
		case result.Manual:
			c.manual++
		case result.FixVerified:
			c.fixed++
		case result.FixApplied:
			// The fix command ran, but the re-run check still failed.
			c.unverified++
		case result.Error != "":
			c.errors++
		case result.Passed:
			c.passed++
		default:
			c.failed++
		}
	}
	return c
}

func (s suiteState) Evidence() executor.RunEvidence {
	return executor.RunEvidence{
		Generation:   s.generation,
		GenerationID: s.generation,
		SourceGeneration: s.generation,
		GenerationSeq: s.generationSeq,
		Cursor:       s.cursor,
		EventCursor:  s.cursor,
	}
}

func (s suiteState) evidence() executor.RunEvidence { return s.Evidence() }

func (m model) totals() counts {
	var total counts
	for _, suite := range m.suites {
		c := suite.counts()
		total.total += c.total
		total.complete += c.complete
		total.passed += c.passed
		total.failed += c.failed
		total.errors += c.errors
		total.fixed += c.fixed
		total.unverified += c.unverified
		total.skipped += c.skipped
		total.manual += c.manual
	}
	return total
}

// Evidence exposes the generation and last committed cursor shown by the
// dashboard. It is the same identity used by reports and saved reports.
func (m model) Evidence() executor.RunEvidence {
	return executor.RunEvidence{
		Generation:   m.generation,
		GenerationID: m.generationID,
		SourceGeneration: m.generation,
		GenerationSeq: m.generationSeq,
		Cursor:       m.cursor,
		EventCursor:  m.cursor,
	}
}

func (m model) evidence() executor.RunEvidence { return m.Evidence() }

type logEntry struct{ at, level, text string }
type readyMsg struct{}
type tickMsg time.Time
type finishedMsg struct {
	err     error
	stopped bool
}

type model struct {
	viewing, opening                      bool
	pathInput, openError, source, savedAt string
	incomplete, mixedGenerations          bool
	incompleteReason                      string
	options                               Options
	suites                                []suiteState
	logs                                  []logEntry
	generation, generationID              string
	generationSeq                         uint64
	cursor, eventCursor, lastCursor       uint64
	seenEvents                            map[string]struct{}
	deferredEvents                        map[string][]executor.RunEvent
	retiredGenerations                    map[string]struct{}
	startedSuites                         map[int]bool
	startedChecks                         map[int]map[int]bool
	width, height                         int
	active, selected, focus, logOffset    int
	follow, done, stopping                bool
	runErr                                error
	started                               time.Time
	finished                              time.Time
	frame                                 int
	ready                                 chan struct{}
	stop                                  func()
}

func newModel(options Options, suites []config.TestSuite, ready chan struct{}, stop func()) model {
	m := model{
		options:            options,
		active:             -1,
		follow:             true,
		started:            time.Now(),
		ready:              ready,
		stop:               stop,
		seenEvents:         make(map[string]struct{}),
		deferredEvents:     make(map[string][]executor.RunEvent),
		retiredGenerations: make(map[string]struct{}),
		startedSuites:      make(map[int]bool),
		startedChecks:      make(map[int]map[int]bool),
	}
	for _, suite := range suites {
		m.suites = append(m.suites, suiteState{title: cleanText(suite.Title), total: len(suite.Checks), results: make(map[int]config.CheckResult)})
	}
	return m
}

func (m model) Init() tea.Cmd {
	return tea.Batch(func() tea.Msg { return readyMsg{} }, tick())
}
func tick() tea.Cmd {
	return tea.Tick(150*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case readyMsg:
		if m.ready != nil {
			close(m.ready)
			m.ready = nil
		}
	case tea.WindowSizeMsg:
		initialSize := m.width == 0
		m.width, m.height = msg.Width, msg.Height
		if m.viewing && initialSize {
			m.logOffset = m.reportTopOffset()
		}
		m.logOffset = min(m.logOffset, max(0, len(m.logRows(m.logWidth()))-1))
	case tickMsg:
		m.frame++
		if !m.done {
			return m, tick()
		}
	case executor.RunEvent:
		m.applyEvent(msg)
	case ui.LogEntry:
		if m.active >= 0 && !m.suites[m.active].done && !m.done {
			m.addSuiteLog(m.active, msg.Level, msg.Message)
		} else {
			m.addLog(msg.Level, msg.Message)
		}
	case finishedMsg:
		m.done, m.stopping, m.runErr, m.finished = true, msg.stopped, msg.err, time.Now()
		if msg.err != nil {
			m.addLog("error", msg.err.Error())
		}
		if msg.stopped {
			m.addLog("stop", "Stopped between checks. Completed results remain visible here.")
		} else {
			m.addLog("done", "Run finished. Review the results; press q to return to your shell.")
		}
		if m.totals().fixed > 0 {
			m.addLog("info", "Fixed checks passed a re-check but count as passes only in the next audit. Run an audit again to measure the new hardening level.")
		}
	case tea.KeyMsg:
		if m.opening {
			return m.updateOpen(msg)
		}
		previous := m.selected
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			if m.done {
				return m, tea.Quit
			}
			if !m.stopping {
				m.stopping = true
				if m.stop != nil {
					m.stop()
				}
				m.addLog("stop", "Stop requested. Waiting for the current check and any rollback backup to finish…")
			}
		case "o":
			if m.done {
				m.opening = true
				m.pathInput = ""
				m.openError = ""
			} else {
				m.addLog("info", "Open a saved report after this run finishes.")
			}
		case "tab":
			m.focus = 1 - m.focus
		case "left", "h":
			m.focus = 0
		case "right", "l":
			m.focus = 1
		case "f":
			m.follow = true
			m.logOffset = 0
			if m.active >= 0 {
				m.selected = m.active
			}
		case "up", "k":
			m.scroll(-1)
		case "down", "j":
			m.scroll(1)
		case "pgup":
			m.scroll(-5)
		case "pgdown":
			m.scroll(5)
		case "g", "home":
			m.follow = false
			if m.focus == 0 {
				m.selected = 0
			} else {
				m.logOffset = max(0, len(m.logRows(m.logWidth()))-1)
			}
		case "G", "end":
			if m.focus == 0 {
				m.selected = max(0, len(m.suites)-1)
				m.follow = false
			} else {
				m.logOffset = 0
			}
		}
		if previous != m.selected {
			m.logOffset = 0
			if !m.follow || m.viewing {
				m.logOffset = m.reportTopOffset()
			}
		}
	}
	return m, nil
}

func (m *model) scroll(delta int) {
	if m.focus == 0 {
		m.follow = false
		m.selected = min(max(0, m.selected+delta), max(0, len(m.suites)-1))
	} else {
		m.follow = false
		m.logOffset = min(max(0, m.logOffset-delta), max(0, len(m.logRows(m.logWidth()))-1))
	}
}

// applyEvent consumes one observed event and reports whether it was
// accepted. A nil receiver or an event outside the dashboard's suite list is
// rejected. A staged generation is accepted (it belongs to the dashboard) but
// is not visible until it is complete.
func (m *model) applyEvent(event executor.RunEvent) bool {
	if m == nil {
		return false
	}
	if event.Generation == "" {
		event.Generation = event.GenerationID
	}
	if event.Generation == "" {
		event.Generation = event.RunGeneration
	}
	if event.Generation == "" {
		event.Generation = event.SourceGeneration
	}
	if event.Generation == "" {
		event.Generation = event.GenerationSource
	}
	if event.Generation == "" {
		event.Generation = event.Result.Generation
	}
	if event.Generation == "" {
		event.Generation = event.Result.SourceGeneration
	}
	if event.Generation == "" {
		event.Generation = event.Result.GenerationSource
	}
	if event.GenerationID == "" {
		event.GenerationID = event.Generation
	}
	if event.Cursor == 0 {
		switch {
		case event.EventCursor > 0:
			event.Cursor = event.EventCursor
		case event.Sequence > 0:
			event.Cursor = event.Sequence
		case event.Seq > 0:
			event.Cursor = event.Seq
		case event.Result.Cursor > 0:
			event.Cursor = event.Result.Cursor
		case event.Result.EventCursor > 0:
			event.Cursor = event.Result.EventCursor
		}
	}
	if event.SuiteIndex < 0 || event.SuiteIndex >= len(m.suites) {
		return false
	}
	if event.Kind > executor.SuiteFinished {
		return false
	}
	if (event.Kind == executor.CheckStarted || event.Kind == executor.CheckFinished) &&
		(event.CheckIndex < 0 || event.CheckIndex >= m.suites[event.SuiteIndex].total) {
		return false
	}
	if m.adoptGeneration(event) {
		return true
	}
	if event.Cursor > 0 {
		if m.seenEvents == nil {
			m.seenEvents = make(map[string]struct{})
		}
		key := event.CursorKey()
		if _, exists := m.seenEvents[key]; exists {
			return false
		}
		// Results are keyed by suite/check position, so applying an unseen
		// event is order-independent. The cursor is evidence of identity, not
		// a promise that the network delivered every preceding event; a
		// reconnect that only has the second half must not invent the missing
		// checks from an old summary.
		changed := m.applyEventNow(event)
		m.seenEvents[key] = struct{}{}
		if event.Cursor > m.cursor {
			m.cursor = event.Cursor
		}
		m.eventCursor, m.lastCursor = m.cursor, m.cursor
		return changed
	}
	return m.applyEventNow(event)
}

func (m *model) applyEventNow(event executor.RunEvent) bool {
	if m == nil || event.SuiteIndex < 0 || event.SuiteIndex >= len(m.suites) {
		return false
	}
	if (event.Kind == executor.CheckStarted || event.Kind == executor.CheckFinished) &&
		(event.CheckIndex < 0 || event.CheckIndex >= m.suites[event.SuiteIndex].total) {
		return false
	}
	suite := &m.suites[event.SuiteIndex]
	if event.Generation != "" {
		suite.generation = event.Generation
		if event.GenerationSeq > suite.generationSeq {
			suite.generationSeq = event.GenerationSeq
		}
	}
	if event.Cursor > suite.cursor {
		suite.cursor = event.Cursor
	}
	switch event.Kind {
	case executor.SuiteStarted:
		if m.startedSuites == nil {
			m.startedSuites = make(map[int]bool)
		}
		if m.startedSuites[event.SuiteIndex] {
			return false
		}
		m.startedSuites[event.SuiteIndex] = true
		m.active = event.SuiteIndex
		if m.follow {
			m.selected = m.active
			m.logOffset = 0
		}
		m.addSuiteLog(event.SuiteIndex, "suite", suite.title)
		return true
	case executor.CheckStarted:
		if m.startedChecks == nil {
			m.startedChecks = make(map[int]map[int]bool)
		}
		if m.startedChecks[event.SuiteIndex] == nil {
			m.startedChecks[event.SuiteIndex] = make(map[int]bool)
		}
		if m.startedChecks[event.SuiteIndex][event.CheckIndex] {
			return false
		}
		m.startedChecks[event.SuiteIndex][event.CheckIndex] = true
		m.addSuiteLog(event.SuiteIndex, "run", event.Check.ID+" · "+event.Check.Description)
		return true
	case executor.CheckFinished:
		if event.CheckIndex < 0 || event.CheckIndex >= suite.total {
			return false
		}
		if suite.results == nil {
			suite.results = make(map[int]config.CheckResult)
		}
		if _, exists := suite.results[event.CheckIndex]; exists {
			return false
		}
		result := event.Result
		if result.Generation == "" {
			result.Generation = event.Generation
		}
		if result.GenerationID == "" {
			result.GenerationID = event.Generation
		}
		if result.SourceGeneration == "" {
			result.SourceGeneration = event.Generation
		}
		if result.GenerationSource == "" {
			result.GenerationSource = event.Generation
		}
		if result.GenerationSeq == 0 {
			result.GenerationSeq = event.GenerationSeq
		}
		if result.Cursor == 0 {
			result.Cursor = event.Cursor
		}
		if result.EventCursor == 0 {
			result.EventCursor = event.Cursor
		}
		suite.results[event.CheckIndex] = result
		if m.startedChecks == nil {
			m.startedChecks = make(map[int]map[int]bool)
		}
		if m.startedChecks[event.SuiteIndex] == nil {
			m.startedChecks[event.SuiteIndex] = make(map[int]bool)
		}
		m.startedChecks[event.SuiteIndex][event.CheckIndex] = true
		level, text := resultMessage(event.Result)
		m.addSuiteLog(event.SuiteIndex, level, text)
		if suite.total > 0 && len(suite.results) == suite.total {
			suite.done = true
		}
		return true
	case executor.SuiteFinished:
		if suite.done {
			return false
		}
		suite.done = true
		return true
	}
	return false
}

// adoptGeneration binds the dashboard to exactly one run generation. Events
// from a replay of the current generation are accepted (the cursor/logical
// check checks discard duplicates). Events from a different generation start
// a clean snapshot instead of extending the previous run's results, so a
// reconnect that only received the second half cannot be completed with an
// old summary. Late events from a retired generation are ignored.
func (m *model) adoptGeneration(event executor.RunEvent) bool {
	if event.Generation == "" {
		return false
	}
	if m.generation == "" {
		if m.totals().complete > 0 {
			// The visible page contains legacy (pre-generation) results.
			// Stage the new run and replace them only when it is complete.
			m.deferEvent(event)
			m.commitDeferredIfComplete(event.Generation, event.GenerationSeq)
			return true
		}
		m.incomplete = false
		m.runErr = nil
		m.done = false
		m.viewing = false
		m.generation = event.Generation
		m.generationID = event.Generation
		m.generationSeq = event.GenerationSeq
		for i := range m.suites {
			m.suites[i].generation = event.Generation
		}
		return false
	}
	if event.Generation == m.generation {
		if event.GenerationSeq > m.generationSeq {
			m.generationSeq = event.GenerationSeq
		}
		return false
	}
	if m.retiredGenerations != nil {
		if _, retired := m.retiredGenerations[event.Generation]; retired {
			return true
		}
	}
	// Events that carry a monotonic generation sequence are ordered. A lower
	// sequence is stale and must not replace the current snapshot.
	if event.GenerationSeq != 0 && m.generationSeq != 0 && event.GenerationSeq < m.generationSeq {
		if m.retiredGenerations == nil {
			m.retiredGenerations = make(map[string]struct{})
		}
		m.retiredGenerations[event.Generation] = struct{}{}
		return true
	}
	// A different generation is a candidate snapshot, not an increment to
	// the current one. Stage it until every planned check has arrived, then
	// replace the visible snapshot atomically. A reconnect that only received
	// the second half therefore leaves the complete old snapshot in place
	// instead of filling the missing checks from old results.
	if m.totals().complete > 0 {
		m.deferEvent(event)
		m.commitDeferredIfComplete(event.Generation, event.GenerationSeq)
		return true
	}
	m.resetForGeneration(event.Generation, event.GenerationSeq)
	return false
}

func (m *model) deferEvent(event executor.RunEvent) {
	if m.deferredEvents == nil {
		m.deferredEvents = make(map[string][]executor.RunEvent)
	}
	for _, existing := range m.deferredEvents[event.Generation] {
		if existing.Cursor > 0 && existing.Cursor == event.Cursor {
			return
		}
		if existing.Cursor == 0 && existing.Kind == event.Kind &&
			existing.SuiteIndex == event.SuiteIndex && existing.CheckIndex == event.CheckIndex {
			return
		}
	}
	m.deferredEvents[event.Generation] = append(m.deferredEvents[event.Generation], event)
}

// commitDeferredIfComplete atomically publishes a candidate generation once
// it covers every planned check. Until then the old complete snapshot stays
// visible. This is the recovery commit boundary for a reconnect or restart.
func (m *model) commitDeferredIfComplete(generation string, sequence uint64) bool {
	events := m.deferredEvents[generation]
	if len(events) == 0 {
		return false
	}
	if sequence != 0 && m.generationSeq != 0 && sequence < m.generationSeq {
		if m.retiredGenerations == nil {
			m.retiredGenerations = make(map[string]struct{})
		}
		m.retiredGenerations[generation] = struct{}{}
		delete(m.deferredEvents, generation)
		return false
	}
	total := m.totals().total
	seenChecks := make(map[string]struct{})
	for _, event := range events {
		if event.Kind == executor.CheckFinished && event.SuiteIndex >= 0 && event.SuiteIndex < len(m.suites) &&
			event.CheckIndex >= 0 && event.CheckIndex < m.suites[event.SuiteIndex].total {
			seenChecks[event.CheckKey()] = struct{}{}
		}
	}
	if total > 0 && len(seenChecks) < total {
		return false
	}
	m.resetForGeneration(generation, sequence)
	sort.SliceStable(events, func(i, j int) bool {
		return events[i].Cursor < events[j].Cursor
	})
	for _, event := range events {
		if m.seenEvents == nil {
			m.seenEvents = make(map[string]struct{})
		}
		if event.Cursor > 0 {
			m.seenEvents[event.CursorKey()] = struct{}{}
		}
		m.applyEventNow(event)
		if event.Cursor > m.cursor {
			m.cursor = event.Cursor
		}
	}
	m.eventCursor, m.lastCursor = m.cursor, m.cursor
	delete(m.deferredEvents, generation)
	return true
}

func (m *model) resetForGeneration(generation string, sequence uint64) {
	if m.generation != "" && m.generation != generation {
		if m.retiredGenerations == nil {
			m.retiredGenerations = make(map[string]struct{})
		}
		m.retiredGenerations[m.generation] = struct{}{}
	}
	m.generation, m.generationID, m.generationSeq = generation, generation, sequence
	m.cursor, m.eventCursor, m.lastCursor = 0, 0, 0
	m.seenEvents = make(map[string]struct{})
	m.startedSuites = make(map[int]bool)
	m.startedChecks = make(map[int]map[int]bool)
	m.logs = nil
	m.active = -1
	m.incomplete = false
	m.mixedGenerations = false
	m.incompleteReason = ""
	m.runErr = nil
	m.done = false
	m.viewing = false
	m.stopping = false
	m.follow = true
	m.logOffset = 0
	if m.selected < 0 || m.selected >= len(m.suites) {
		m.selected = 0
	}
	for i := range m.suites {
		m.suites[i].logs = nil
		m.suites[i].results = make(map[int]config.CheckResult)
		m.suites[i].done = false
		m.suites[i].generation = generation
		m.suites[i].generationSeq = sequence
		m.suites[i].cursor = 0
	}
}

func (m *model) addLog(level, text string) { m.appendLog(-1, level, text) }

func (m *model) addSuiteLog(index int, level, text string) { m.appendLog(index, level, text) }

func (m *model) appendLog(index int, level, text string) {
	oldRows := 0
	if m.logOffset > 0 {
		oldRows = len(m.logRows(m.logWidth()))
	}
	text = cleanText(text)
	if len(text) > 4096 {
		text = string([]rune(text)[:min(1024, len([]rune(text)))]) + "…"
	}
	lines := strings.Split(text, "\n")
	if len(lines) > 10 {
		lines = append(lines[:10], "… output truncated in dashboard; see report")
	}
	text = strings.Join(lines, "\n")
	buffer := &m.logs
	if index >= 0 && index < len(m.suites) {
		buffer = &m.suites[index].logs
	} else {
		text = "[RUN] " + text
	}
	*buffer = append(*buffer, logEntry{time.Now().Format("15:04:05"), level, text})
	if len(*buffer) > maxLogEntries {
		*buffer = (*buffer)[len(*buffer)-maxLogEntries:]
	}

	if m.logOffset > 0 {
		m.logOffset = max(0, m.logOffset+len(m.logRows(m.logWidth()))-oldRows)
	}
}

// Remove terminal escapes and control characters from command/ruleset text.
func cleanText(text string) string {
	text = ansi.Strip(text)
	return strings.Map(func(r rune) rune {
		if r == '\n' {
			return r
		}
		if r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, strings.TrimSpace(text))
}

func percentage(n int) string {
	if n < 0 {
		return "—"
	}
	return fmt.Sprintf("%d%%", n)
}
