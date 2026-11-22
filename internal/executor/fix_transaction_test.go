package executor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"hardener/internal/config"
)

func writeUID32012File(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

// A fix whose command succeeds but whose re-check fails must stay pending.
// The fix result and the failed verification remain item-level evidence.
func TestUID32012FixVerificationFailureStaysPendingWithEvidence(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	ready := filepath.Join(dir, "ready")
	writeUID32012File(t, setting, "0")

	ctx := &config.ExecContext{BaseDir: dir, RunID: "run-1", SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{{
		ID:            "needs-retry",
		SecurityLevel: "baseline",
		Command:       "test -f '" + ready + "' && cat '" + setting + "' || printf 0",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}}}}

	results, _, fixes, err := RunSuitesObserved(ctx, ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0].Checks[0]
	if !result.FixApplied || result.FixVerified || result.Passed {
		t.Fatalf("failed re-check published a completed item: %+v", result)
	}
	if !result.Pending || result.Stage != config.FixStageVerify {
		t.Fatalf("pending verification stage missing: %+v", result)
	}
	if result.FixResult != config.FixResultApplied || result.VerifyResult != config.VerifyResultFailed {
		t.Fatalf("fix and verification results not kept separately: %+v", result)
	}
	if result.FixID == "" || result.FixID != result.FixGeneration || result.FixEvidence == nil {
		t.Fatalf("fix identity missing: %+v", result)
	}
	if !strings.Contains(result.FailureLocation, "stage verify") ||
		!strings.Contains(result.FailureLocation, "needs-retry") ||
		!strings.Contains(result.FailureLocation, setting) {
		t.Fatalf("failure location does not point at the verification: %q", result.FailureLocation)
	}
	if fixes["needs-retry"] {
		t.Fatalf("unverified fix entered the fix score: %v", fixes)
	}

	data, err := os.ReadFile(FixJournalPath(dir))
	if err != nil {
		t.Fatalf("fix transaction was not persisted before the command: %v", err)
	}
	var journal fixJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		t.Fatal(err)
	}
	tx := journal.Transactions[result.FixID]
	if tx == nil || tx.Completed || !tx.Pending || tx.BeforeChecksum == "" {
		t.Fatalf("journal lost the candidate or its pre-fix state: %+v", tx)
	}
	if tx.FixResult != config.FixResultApplied || tx.VerifyResult != config.VerifyResultFailed {
		t.Fatalf("journal lost the fix or verification result: %+v", tx)
	}
}

// A retry that finds the check passing completes the same fix identity from
// the persisted successful fix result. It must not create a fresh pass.
func TestUID32012RetryCompletesSameFixIdentityAfterRestart(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	ready := filepath.Join(dir, "ready")
	writeUID32012File(t, setting, "0")

	check := config.Check{
		ID:            "needs-retry",
		SecurityLevel: "baseline",
		Command:       "test -f '" + ready + "' && cat '" + setting + "' || printf 0",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{check}}}

	first, _, _, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-1", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstResult := first[0].Checks[0]
	if firstResult.FixVerified || firstResult.FixID == "" {
		t.Fatalf("first attempt should be pending: %+v", firstResult)
	}

	// The verification gate changes before the retry. This models the post
	// action completing while the process was stopped.
	writeUID32012File(t, ready, "ready")
	second, _, fixes, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-2", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondResult := second[0].Checks[0]
	if !secondResult.FixApplied || !secondResult.FixVerified || secondResult.Passed {
		t.Fatalf("retry did not complete the fix: %+v", secondResult)
	}
	if secondResult.Pending || secondResult.Stage != config.FixStageComplete || secondResult.Status != "fixed" {
		t.Fatalf("retry published the wrong stage: %+v", secondResult)
	}
	if secondResult.FixID != firstResult.FixID {
		t.Fatalf("retry changed the completion identity: %q -> %q", firstResult.FixID, secondResult.FixID)
	}
	if secondResult.FixResult != config.FixResultApplied || secondResult.VerifyResult != config.VerifyResultPassed {
		t.Fatalf("retry lost fix or verification evidence: %+v", secondResult)
	}
	if !fixes["needs-retry"] {
		t.Fatalf("verified retry did not count as fixed: %v", fixes)
	}
}

// A process that stopped during verification leaves a complete fix result but
// no verification result. The next run must finish that same transaction from
// the persisted fix outcome, without looking like a fresh pass.
func TestUID32012PendingFixOutcomeCompletesAfterRestart(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	writeUID32012File(t, setting, "1")

	check := config.Check{
		ID:            "interrupted-verify",
		SecurityLevel: "baseline",
		Command:       "cat '" + setting + "'",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}
	tx := newFixTransaction(check)
	tx.BeforeExists = true
	tx.BeforeChecksum = "recorded-before-state"
	tx.FixResult = config.FixResultApplied
	tx.FixOutput = "fix completed"
	tx.VerifyResult = config.VerifyResultPending
	tx.Stage = config.FixStageVerify
	tx.Pending = true
	journal := &fixJournal{Version: fixJournalVersion, Transactions: map[string]*fixTransaction{tx.ID: tx}}
	if err := saveFixJournal(dir, journal); err != nil {
		t.Fatal(err)
	}

	results, _, fixes, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-after-restart", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64",
		[]config.TestSuite{{Title: "Category", Checks: []config.Check{check}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0].Checks[0]
	if !result.FixApplied || !result.FixVerified || result.Passed || result.Pending {
		t.Fatalf("pending fix outcome was not completed after restart: %+v", result)
	}
	if result.FixID != tx.ID || result.Stage != config.FixStageComplete ||
		result.FixResult != config.FixResultApplied || result.VerifyResult != config.VerifyResultPassed {
		t.Fatalf("restart changed the completion identity or evidence: %+v", result)
	}
	if !fixes["interrupted-verify"] {
		t.Fatalf("restart completion did not count as fixed: %v", fixes)
	}
}

// A fix command that fails after changing the target leaves a passing check.
// That pass must not turn the failed fix into a completed item on retry.
func TestUID32012RetryDoesNotPublishPassAfterFailedFix(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	writeUID32012File(t, setting, "0")

	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{{
		ID:            "partial-fix",
		SecurityLevel: "baseline",
		Command:       "cat '" + setting + "'",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'; exit 1",
		AffectedFile:  setting,
	}}}}

	first, _, fixes, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-1", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := first[0].Checks[0]
	if result.FixApplied || result.FixVerified || result.Passed {
		t.Fatalf("failed fix published completion: %+v", result)
	}
	if !result.Pending || result.FixResult != config.FixResultFailed ||
		result.VerifyResult != config.VerifyResultPassed || result.Stage != config.FixStageFix {
		t.Fatalf("failed fix evidence is incomplete: %+v", result)
	}
	if !strings.Contains(result.FailureLocation, "stage fix") {
		t.Fatalf("failure location does not point at the fix: %q", result.FailureLocation)
	}
	if fixes["partial-fix"] {
		t.Fatalf("failed fix entered the fix score: %v", fixes)
	}

	// The target is now already modified, so a retry sees a passing check.
	// It must still refuse to publish the failed transaction as complete.
	retry, retryPassed, retryFixes, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-2", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	retryResult := retry[0].Checks[0]
	if retryResult.Passed || retryResult.FixApplied || retryResult.FixVerified || !retryResult.Pending {
		t.Fatalf("retry treated the modified file as a verified fix: %+v", retryResult)
	}
	if retryResult.FixID != result.FixID ||
		retryResult.FixResult != config.FixResultFailed ||
		retryResult.VerifyResult != config.VerifyResultPassed {
		t.Fatalf("retry lost the pending fix identity or evidence: %+v", retryResult)
	}
	if retryPassed["partial-fix"] {
		t.Fatalf("pending fix entered the pass rate: %v", retryPassed)
	}
	if retryFixes["partial-fix"] {
		t.Fatalf("pending fix entered the fix score: %v", retryFixes)
	}
}

// A retry whose check still fails reruns the fix, but keeps the original
// identity and pre-fix evidence for that remediation.
func TestUID32012RetryRerunsFixUnderSameIdentity(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	writeUID32012File(t, setting, "0")

	check := config.Check{
		ID:            "still-failing",
		SecurityLevel: "baseline",
		Command:       "cat '" + setting + "'",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}
	tx := newFixTransaction(check)
	tx.BeforeExists = true
	tx.BeforeChecksum = "original-before-state"
	tx.FixResult = config.FixResultApplied
	tx.VerifyResult = config.VerifyResultFailed
	tx.Stage = config.FixStageVerify
	tx.Pending = true
	tx.FailureStage = config.FixStageVerify
	tx.FailureLocation = "check still-failing | stage verify | previous attempt"
	journal := &fixJournal{Version: fixJournalVersion, Transactions: map[string]*fixTransaction{tx.ID: tx}}
	if err := saveFixJournal(dir, journal); err != nil {
		t.Fatal(err)
	}

	results, _, fixes, err := RunSuitesObserved(
		&config.ExecContext{BaseDir: dir, RunID: "run-retry", SecurityLevel: "baseline"},
		ModeFix, "linux", "amd64",
		[]config.TestSuite{{Title: "Category", Checks: []config.Check{check}}}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0].Checks[0]
	if !result.FixApplied || !result.FixVerified || result.Passed || result.Pending {
		t.Fatalf("retry did not finish the still-failing fix: %+v", result)
	}
	if result.FixID != tx.ID || result.Stage != config.FixStageComplete {
		t.Fatalf("retry changed identity or stage: %+v", result)
	}
	if !fixes["still-failing"] {
		t.Fatalf("retry fix not counted: %v", fixes)
	}

	reloaded, err := loadFixJournal(dir)
	if err != nil {
		t.Fatal(err)
	}
	updated := reloaded.Transactions[tx.ID]
	if updated == nil || !updated.Completed || updated.BeforeChecksum != "original-before-state" {
		t.Fatalf("retry lost the original pre-fix evidence: %+v", updated)
	}
	if updated.Attempts < 2 {
		t.Fatalf("retry did not record a second attempt: %+v", updated)
	}
}

// Two overlapping runs share one identity. The second run must observe the
// completed result under the journal lock instead of running the fix again.
func TestUID32012ConcurrentRunsRunFixOnce(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	counter := filepath.Join(dir, "fix-count")
	writeUID32012File(t, setting, "0")

	check := config.Check{
		ID:            "shared-fix",
		SecurityLevel: "baseline",
		Command:       "cat '" + setting + "'",
		Expected:      "1",
		Fix:           "printf x >> '" + counter + "'; printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{check}}}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	results := make(chan config.CheckResult, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got, _, _, err := RunSuitesObserved(
				&config.ExecContext{BaseDir: dir, RunID: fmt.Sprintf("run-%d", i), SecurityLevel: "baseline"},
				ModeFix, "linux", "amd64", suites, nil, nil)
			if err != nil {
				errs <- err
				return
			}
			results <- got[0].Checks[0]
		}(i)
	}
	wg.Wait()
	close(errs)
	close(results)
	for err := range errs {
		t.Fatal(err)
	}

	runs, err := os.ReadFile(counter)
	if err != nil {
		t.Fatal(err)
	}
	if string(runs) != "x" {
		t.Fatalf("fix command ran %d times for one identity", len(runs))
	}
	for result := range results {
		if !result.FixApplied || !result.FixVerified || result.Pending {
			t.Fatalf("concurrent run did not publish the completed fix: %+v", result)
		}
	}
}

// The report keeps the item-level fix result, verification result and stage,
// and points at the exact check and phase that failed.
func TestUID32012FixReportKeepsItemEvidenceAndFailureLocation(t *testing.T) {
	dir := t.TempDir()
	setting := filepath.Join(dir, "setting.conf")
	ready := filepath.Join(dir, "ready")
	writeUID32012File(t, setting, "0")

	ctx := &config.ExecContext{BaseDir: dir, RunID: "run-1", SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{{
		ID:            "reported",
		SecurityLevel: "baseline",
		Command:       "test -f '" + ready + "' && cat '" + setting + "' || printf 0",
		Expected:      "1",
		Fix:           "printf 1 > '" + setting + "'",
		AffectedFile:  setting,
	}}}}
	results, _, _, err := RunSuitesObserved(ctx, ModeFix, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	saved := BuildReport(config.SystemInfo{OS: "linux", Arch: "amd64", Distro: "test"},
		results, "fix", false)
	if !saved.Incomplete || saved.IncompleteReason == "" {
		t.Fatalf("pending fix report is not marked incomplete: %+v", saved)
	}
	if saved.FixPending != 1 || len(saved.FixOutcomes) != 1 || len(saved.FailureLocations) != 1 {
		t.Fatalf("report-level fix evidence missing: %+v", saved)
	}
	outcome := saved.FixOutcomes[0]
	if outcome.CheckID != "reported" || outcome.FixResult != config.FixResultApplied ||
		outcome.VerifyResult != config.VerifyResultFailed || outcome.FailureStage != config.FixStageVerify {
		t.Fatalf("report outcome lost item evidence: %+v", outcome)
	}
	if !strings.Contains(outcome.FailureLocation, "stage verify") ||
		!strings.Contains(outcome.FailureLocation, setting) {
		t.Fatalf("report failure location is not specific: %q", outcome.FailureLocation)
	}

	data, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	jsonText := string(data)
	for _, key := range []string{"fix_result", "verify_result", "stage", "failure_location", "fix_outcomes"} {
		if !strings.Contains(jsonText, `"`+key+`"`) {
			t.Fatalf("report JSON missing %q: %s", key, jsonText)
		}
	}
}

// Read-only runs keep their previous result shape: a passing check stays a
// pass without fix evidence, and no fix transaction file is created.
func TestUID32012AuditRunKeepsPlainPassWithoutFixState(t *testing.T) {
	dir := t.TempDir()
	ctx := &config.ExecContext{BaseDir: dir, RunID: "audit-1", SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{{
		ID:            "plain-pass",
		SecurityLevel: "baseline",
		Command:       "printf 1",
		Expected:      "1",
	}}}}

	results, passed, fixes, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	result := results[0].Checks[0]
	if !result.Passed || result.FixID != "" || result.FixResult != "" || result.VerifyResult != "" ||
		result.Pending || result.Stage != config.FixStageCheck {
		t.Fatalf("audit result changed shape: %+v", result)
	}
	if !passed["plain-pass"] || len(fixes) != 0 {
		t.Fatalf("audit score changed: passed=%v fixes=%v", passed, fixes)
	}
	if _, err := os.Stat(FixJournalPath(dir)); !os.IsNotExist(err) {
		t.Fatalf("audit wrote fix transaction state: %v", err)
	}
}
