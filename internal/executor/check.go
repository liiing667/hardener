package executor

import (
	"fmt"
	"hardener/internal/config"
	"hardener/internal/ui"
	"hardener/rollback"
	"os"
	"os/exec"
	"strings"
	"time"
)

// runCheck runs one check and, in fix mode, its fix. It also returns the check
// with the distro overrides that were applied, so callers report the command
// and expected value that actually ran.
func runCheck(ctx *config.ExecContext, mode RunMode, check config.Check, security_level string) (config.CheckResult, config.Check) {
	if !config.DetermineSecurityFit(security_level, check.SecurityLevel) {
		reason := fmt.Sprintf("requires security level %q; selected level is %q", check.SecurityLevel, security_level)
		if !config.IsSecurityLevel(check.SecurityLevel) {
			reason = fmt.Sprintf("unknown security level %q (known: %s)", check.SecurityLevel, strings.Join(config.SecurityLevels, ", "))
		}
		return config.CheckResult{
			ID:          check.ID,
			Description: check.Description,
			Output:      reason,
			SkipReason:  reason,
			Skipped:     true,
			Stage:       config.FixStageCheck,
			Status:      "skipped",
		}, check
	}

	sys := config.SystemInfo{OS: ctx.OSName, Arch: ctx.ArchName}
	if ok, reason := config.IsCheckApplicable(check, sys); !ok {
		return config.CheckResult{
			ID:            check.ID,
			Description:   check.Description,
			Output:        reason,
			SkipReason:    reason,
			SkippedDistro: true,
			Stage:         config.FixStageCheck,
			Status:        "skipped",
		}, check
	}

	// Build the distro lookup chain: [DistroName, ...DistroFamily].
	// DistroFamily already starts with the ID when populated by run.go,
	// but we defensively include DistroName first in case a caller has only
	// set DistroName without family detection.
	chain := ctx.DistroFamily
	if len(chain) == 0 || (len(chain) > 0 && chain[0] != ctx.DistroName) {
		chain = append([]string{ctx.DistroName}, chain...)
	}

	resolved, supported := check.ResolveForDistro(chain, ctx.Profile)
	if !supported {
		return config.CheckResult{
			ID:            check.ID,
			Description:   check.Description,
			Output:        fmt.Sprintf("not supported on distro %q", ctx.DistroName),
			SkipReason:    fmt.Sprintf("not supported on distro %q", ctx.DistroName),
			SkippedDistro: true,
			Stage:         config.FixStageCheck,
			Status:        "skipped",
		}, check
	}
	check = resolved

	if check.RequiresCommand != "" {
		probe := exec.Command("sh", "-c", "command -v "+check.RequiresCommand+" >/dev/null 2>&1")
		probe.Env = HardenerCmdEnv()
		if err := probe.Run(); err != nil {
			ui.PrintSkippedMissing(check.ID, check.RequiresCommand)
			return config.CheckResult{
				ID:             check.ID,
				Description:    check.Description,
				Output:         fmt.Sprintf("required command %q not found", check.RequiresCommand),
				SkipReason:     fmt.Sprintf("required command %q not found", check.RequiresCommand),
				SkippedMissing: true,
				Stage:          config.FixStageCheck,
				Status:         "skipped",
			}, check
		}
	}

	if check.RequiresFile != "" {
		// Only skip on true "not found" — a permission error means the file
		// probably exists but the audit process can't stat it without sudo.
		if _, err := os.Lstat(check.RequiresFile); err != nil && os.IsNotExist(err) {
			ui.PrintSkippedMissing(check.ID, check.RequiresFile)
			return config.CheckResult{
				ID:             check.ID,
				Description:    check.Description,
				Output:         fmt.Sprintf("required file %q not present", check.RequiresFile),
				SkipReason:     fmt.Sprintf("required file %q not present", check.RequiresFile),
				SkippedMissing: true,
				Stage:          config.FixStageCheck,
				Status:         "skipped",
			}, check
		}
	}

	passed, output, err := RunCheck(check)

	if err != nil {
		// Keep whatever the command actually produced and attach the error as
		// context. Replacing the output with the error string made every
		// failure render as the same "command exited with code 1" line, which
		// hid the difference between a genuine finding, a broken command, a
		// permission problem and a failed sudo.
		if strings.TrimSpace(output) != "" {
			output = fmt.Sprintf("%s (%v)", output, err)
		} else {
			output = err.Error()
		}
		passed = false
	}

	// Built after the error branch, so Passed and Output are each assigned
	// exactly once and cannot drift apart.
	result := config.CheckResult{
		ID:          check.ID,
		Description: check.Description,
		Passed:      passed,
		Output:      output,
		Manual:      isManualAction(check.Command),
		Stage:       config.FixStageCheck,
	}
	if err != nil {
		result.Error = err.Error()
	}
	switch {
	case result.Manual:
		result.Status = "manual"
	case passed:
		result.Status = "passed"
	default:
		result.Status = "failed"
	}

	if passed {
		if mode == ModeFix && !ctx.DryRun && strings.TrimSpace(check.Fix) != "" && !result.Manual {
			result = reconcileFixPass(ctx, check, result, output)
		}
		return result, check
	}

	if strings.TrimSpace(check.Fix) != "" {
		switch {
		case ctx.DryRun:
			printPlannedFix(check)
		case mode == ModeFix:
			if isManualAction(check.Fix) {
				applied, out, fixErr := RunFix(ctx, check)
				result.FixApplied = applied
				result.FixResult = config.FixResultManual
				result.FixOutput = out
				result.VerifyResult = config.VerifyResultNotRun
				result.VerificationResult = config.VerifyResultNotRun
				result.Stage = config.FixStageCheck
				result.Status = "pending"
				result.Pending = true
				result.Output = out
				result.FailureStage = config.FixStageFix
				result.FailureLocation = fixFailureLocation(check, "manual action required")
				result.Location = result.FailureLocation
				if fixErr != nil {
					result.Error = fixErr.Error()
				}
			} else {
				result = runFixTransaction(ctx, check, result)
			}
		}
	}

	return result, check
}

// reconcileFixPass handles a passing check in fix mode. A previous incomplete
// fix with a successful command is completed by this re-check under the same
// ID. A pending fix without a successful command stays pending: the pass alone
// must not turn a failed or interrupted remediation into a completed item.
func reconcileFixPass(ctx *config.ExecContext, check config.Check, result config.CheckResult, output string) config.CheckResult {
	fixJournalMu.Lock()
	defer fixJournalMu.Unlock()
	return reconcileFixPassLocked(ctx, check, result, output)
}

func reconcileFixPassLocked(ctx *config.ExecContext, check config.Check, result config.CheckResult, output string) config.CheckResult {
	journal, err := loadFixJournal(ctx.BaseDir)
	if err != nil {
		return fixStateFailure(ctx, check, result, err)
	}
	tx := journal.Transactions[fixTransactionID(check)]
	if tx == nil {
		return result
	}

	now := time.Now().UTC()
	tx.RunID = ctx.RunID
	tx.UpdatedAt = now
	tx.VerifyResult = config.VerifyResultPassed
	tx.VerifyOutput = output
	tx.VerifyError = ""
	result.VerifyResult = config.VerifyResultPassed
	result.VerificationResult = config.VerifyResultPassed
	result.VerifyOutput = output
	result.FixID = tx.ID
	result.FixGeneration = tx.ID
	result.FixResult = tx.FixResult
	result.FixOutput = tx.FixOutput
	result.FixError = tx.FixError
	result.FixApplied = tx.FixResult == config.FixResultApplied

	if tx.Completed {
		result.Passed = false
		result.FixApplied = true
		result.FixVerified = true
		result.Pending = false
		result.Stage = config.FixStageComplete
		result.Status = "fixed"
		result.Output = fmt.Sprintf("Fix %s was already completed; the re-check passes: %s", tx.ID, output)
		applyFixEvidence(&result, tx.evidence(check))
		result.Passed = false
		result.FixApplied = true
		result.FixVerified = true
		result.Pending = false
		result.Stage = config.FixStageComplete
		result.Status = "fixed"
		ui.PrintFixed(fmt.Sprintf("Fix for check %s already verified (transaction %s).", check.ID, tx.ID))
		return result
	}

	if tx.FixResult == config.FixResultApplied {
		tx.Completed = true
		tx.Pending = false
		tx.Stage = config.FixStageComplete
		tx.FailureStage = ""
		tx.FailureLocation = ""
		if err := saveFixJournal(ctx.BaseDir, journal); err != nil {
			tx.Completed = false
			tx.Pending = true
			tx.Stage = config.FixStageState
			tx.FailureStage = config.FixStageState
			tx.FailureLocation = fmt.Sprintf("check %s | stage state | journal %s | %v",
				check.ID, FixJournalPath(ctx.BaseDir), err)
			applyFixEvidence(&result, tx.evidence(check))
			markFixEvidenceNotDurable(ctx, check, &result, err)
			return result
		}
		result.Passed = false
		result.FixApplied = true
		result.FixVerified = true
		result.Pending = false
		result.Stage = config.FixStageComplete
		result.Status = "fixed"
		result.Output = fmt.Sprintf("Fix %s was applied earlier; the re-check after retry passes: %s", tx.ID, output)
		applyFixEvidence(&result, tx.evidence(check))
		result.Passed = false
		result.FixApplied = true
		result.FixVerified = true
		result.Pending = false
		result.Stage = config.FixStageComplete
		result.Status = "fixed"
		ui.PrintFixed(fmt.Sprintf("Fix for check %s verified after retry (transaction %s).", check.ID, tx.ID))
		return result
	}

	tx.Pending = true
	tx.Completed = false
	tx.Stage = config.FixStageFix
	tx.FixResult = valueOrPending(tx.FixResult)
	if tx.FailureStage == "" {
		tx.FailureStage = config.FixStageFix
	}
	if tx.FailureLocation == "" {
		tx.FailureLocation = pendingFixLocation(check, tx)
	}
	result.Passed = false
	result.FixApplied = false
	result.FixVerified = false
	result.Pending = true
	result.Stage = config.FixStageFix
	result.Status = "pending"
	result.FailureStage = tx.FailureStage
	result.FailureLocation = tx.FailureLocation
	result.Location = tx.FailureLocation
	result.Output = fmt.Sprintf("Fix %s is pending (%s); the re-check passes, but no successful fix result was recorded, so completion is not published.",
		tx.ID, valueOrPending(tx.FixResult))
	result.Output += "\nFailure: " + tx.FailureLocation
	if err := saveFixJournal(ctx.BaseDir, journal); err != nil {
		applyFixEvidence(&result, tx.evidence(check))
		markFixEvidenceNotDurable(ctx, check, &result, err)
		return result
	}
	applyFixEvidence(&result, tx.evidence(check))
	result.Passed = false
	result.FixApplied = false
	result.FixVerified = false
	result.Pending = true
	result.Stage = config.FixStageFix
	result.Status = "pending"
	return result
}

// runFixTransaction executes one remediation attempt. The candidate and its
// pre-fix state are written before the fix command runs, and the result stays
// pending unless both the fix command and the re-check succeed.
func runFixTransaction(ctx *config.ExecContext, check config.Check, result config.CheckResult) config.CheckResult {
	fixJournalMu.Lock()
	defer fixJournalMu.Unlock()

	journal, err := loadFixJournal(ctx.BaseDir)
	if err != nil {
		return fixStateFailure(ctx, check, result, err)
	}
	id := fixTransactionID(check)
	tx := journal.Transactions[id]
	// Another run may have completed this check after the baseline check ran
	// but before this transaction acquired the journal lock. Re-check under
	// the lock and publish that completion instead of running the fix twice.
	if tx != nil {
		if passed, output, checkErr := RunCheck(check); checkErr == nil && passed {
			return reconcileFixPassLocked(ctx, check, result, output)
		}
	}
	if tx == nil {
		tx = newFixTransaction(check)
		tx.Attempts = 0
		journal.Transactions[id] = tx
	} else {
		// The same identity is reused across a retry or restart. A completed
		// record is reopened because this check is failing again.
		tx.Completed = false
		tx.Pending = true
		tx.Stage = config.FixStageFix
		tx.FixResult = config.FixResultPending
		tx.FixOutput = ""
		tx.FixError = ""
		tx.VerifyResult = config.VerifyResultPending
		tx.VerifyOutput = ""
		tx.VerifyError = ""
		tx.FailureStage = ""
		tx.FailureLocation = ""
	}
	tx.CheckID = check.ID
	tx.Target = check.AffectedFile
	tx.CheckCommand = check.Command
	tx.Expected = check.Expected
	tx.PostAction = check.PostAction
	tx.FixCommand = strings.TrimSpace(check.Fix)
	tx.RunID = ctx.RunID
	tx.UpdatedAt = time.Now().UTC()
	if tx.StartedAt.IsZero() {
		tx.StartedAt = tx.UpdatedAt
	}
	// The candidate must be durable before any command can change the host.
	if err := saveFixJournal(ctx.BaseDir, journal); err != nil {
		return fixStateFailure(ctx, check, result, err)
	}

	attempt := runFixAttempt(ctx, check, func(txn *rollback.Txn) error {
		recordPreFixState(tx, check, txn)
		tx.RunID = ctx.RunID
		return saveFixJournal(ctx.BaseDir, journal)
	})

	result.FixID = tx.ID
	result.FixGeneration = tx.ID
	switch {
	case attempt.Manual:
		tx.FixResult = config.FixResultManual
		tx.FixOutput = attempt.Output
		tx.FixError = ""
		tx.VerifyResult = config.VerifyResultNotRun
		tx.Stage = config.FixStageFix
		tx.Pending = true
		tx.Completed = false
		tx.FailureStage = config.FixStageFix
		tx.FailureLocation = fixFailureLocation(check, "manual action required")
		result.FixResult = config.FixResultManual
		result.FixOutput = attempt.Output
		result.VerifyResult = config.VerifyResultNotRun
		result.VerificationResult = config.VerifyResultNotRun
		result.FixApplied = false
		result.FixVerified = false
		result.Pending = true
		result.Stage = config.FixStageFix
		result.Status = "pending"
		result.FailureStage = tx.FailureStage
		result.FailureLocation = tx.FailureLocation
		result.Location = tx.FailureLocation
		result.Output = attempt.Output
	case attempt.PrepareError != nil || attempt.BackupError != nil:
		fixErr := attempt.PrepareError
		if fixErr == nil {
			fixErr = attempt.BackupError
		}
		tx.FixResult = config.FixResultFailed
		tx.FixError = fixErr.Error()
		tx.VerifyResult = config.VerifyResultNotRun
		tx.Stage = config.FixStageFix
		tx.Pending = true
		tx.Completed = false
		tx.FailureStage = config.FixStageFix
		tx.FailureLocation = fixFailureLocation(check, fixErr.Error())
		result.FixResult = config.FixResultFailed
		result.FixError = fixErr.Error()
		result.Error = fixErr.Error()
		result.VerifyResult = config.VerifyResultNotRun
		result.VerificationResult = config.VerifyResultNotRun
		result.FixApplied = false
		result.FixVerified = false
		result.Pending = true
		result.Stage = config.FixStageFix
		result.Status = "pending"
		result.FailureStage = tx.FailureStage
		result.FailureLocation = tx.FailureLocation
		result.Location = tx.FailureLocation
		result.Output = fmt.Sprintf("Fix failed: %v", fixErr)
	default:
		result.FixResult = config.FixResultFailed
		if attempt.Applied {
			result.FixResult = config.FixResultApplied
		}
		result.FixApplied = attempt.Applied
		result.FixOutput = attempt.Output
		result.Output = attempt.Output
		tx.FixResult = result.FixResult
		tx.FixOutput = attempt.Output
		tx.Stage = config.FixStageFix
		tx.Pending = true
		tx.Completed = false
		tx.UpdatedAt = time.Now().UTC()
		if attempt.CommandError != nil {
			tx.FixError = attempt.CommandError.Error()
			result.FixError = tx.FixError
		}
		// Persist the fix command outcome before verification starts, so a
		// restart during the re-check still knows that the fix itself
		// completed and can resume under the same identity.
		if err := saveFixJournal(ctx.BaseDir, journal); err != nil {
			applyFixEvidence(&result, tx.evidence(check))
			markFixEvidenceNotDurable(ctx, check, &result, err)
			return result
		}
		verifyFix(check, &result)
		switch {
		case !attempt.Applied:
			result.FixVerified = false
			result.Pending = true
			result.Stage = config.FixStageFix
			result.Status = "pending"
			result.FailureStage = config.FixStageFix
			if attempt.CommandError != nil {
				result.FailureLocation = fixFailureLocation(check, attempt.CommandError.Error())
			} else {
				result.FailureLocation = fixFailureLocation(check, "fix command did not complete successfully")
			}
			result.Location = result.FailureLocation
			msg := fmt.Sprintf("Fix for check %s did not complete.", check.ID)
			if result.VerifyResult == config.VerifyResultPassed {
				msg += " The re-check passes, but no successful fix result was recorded, so completion is not published."
			} else {
				msg += fmt.Sprintf(" The re-check result is %s.", valueOrPending(result.VerifyResult))
			}
			result.Output = msg
			result.Output += "\nFailure: " + result.FailureLocation
		case result.FixVerified:
			result.Stage = config.FixStageComplete
			result.Status = "fixed"
			result.Pending = false
			result.FailureStage = ""
			result.FailureLocation = ""
			result.Location = ""
		default:
			result.Stage = config.FixStageVerify
			result.Status = "pending"
			result.Pending = true
		}
	}

	syncTransactionFromResult(tx, check, result)
	if err := saveFixJournal(ctx.BaseDir, journal); err != nil {
		applyFixEvidence(&result, tx.evidence(check))
		markFixEvidenceNotDurable(ctx, check, &result, err)
		return result
	}
	applyFixEvidence(&result, tx.evidence(check))
	result.FixApplied = attempt.Applied
	result.FixVerified = result.Pending == false && result.FixApplied && result.Stage == config.FixStageComplete
	return result
}

func valueOrPending(value string) string {
	if strings.TrimSpace(value) == "" {
		return config.FixResultPending
	}
	return value
}

// printPlannedFix reports what fix mode would do for a failing check, without
// running the fix or writing a rollback record.
func printPlannedFix(check config.Check) {
	if isManualAction(check.Fix) {
		ui.PrintInfo(fmt.Sprintf("Dry run: %s needs manual action: %s", check.ID, strings.TrimSpace(check.Fix)))
		return
	}
	privilege := ""
	if fixUsesSudo(check) {
		privilege = " (with sudo)"
	}
	ui.PrintInfo(fmt.Sprintf("Dry run: %s would be fixed%s with: %s", check.ID, privilege, strings.TrimSpace(check.Fix)))
}

// verifyFix re-runs the check after a fix attempt. Exit code 0 alone says
// nothing about the resulting state: a fix can succeed and still leave the
// check failing, e.g. until its post_action (a reboot, a service restart) has
// happened. A re-check that passes after a failed fix is evidence of the
// current state, never evidence that the failed fix completed.
func verifyFix(check config.Check, result *config.CheckResult) {
	passed, output, err := RunCheck(check)
	result.VerifyOutput = output
	result.VerifyResult = config.VerifyResultFailed
	if err != nil {
		result.VerifyResult = config.VerifyResultError
		result.VerifyError = err.Error()
	} else if passed {
		result.VerifyResult = config.VerifyResultPassed
	}
	result.VerificationResult = result.VerifyResult
	result.Stage = config.FixStageVerify

	if result.FixApplied && err == nil && passed {
		result.FixVerified = true
		result.Stage = config.FixStageComplete
		result.Status = "fixed"
		ui.PrintFixed(fmt.Sprintf("Fix for check %s verified: the check now passes.", check.ID))
		return
	}

	got := output
	if err != nil {
		got = strings.TrimSpace(fmt.Sprintf("%s (%v)", output, err))
	}
	if result.FixApplied {
		msg := fmt.Sprintf("Fix for check %s ran, but the check still fails (expected %q, got %q).", check.ID, check.Expected, got)
		if pa := strings.TrimSpace(check.PostAction); pa != "" && !strings.EqualFold(pa, "none") {
			msg += " It may take effect after the post action: " + pa
		}
		ui.PrintErrorMessage(msg)
		if strings.TrimSpace(result.Output) != "" {
			msg += "\nFix output: " + result.Output
		}
		result.Output = msg
	}
	result.Pending = true
	result.Status = "pending"
	result.FailureStage = config.FixStageVerify
	result.FailureLocation = verifyFailureLocation(check, got, err)
	result.Location = result.FailureLocation
	if strings.TrimSpace(result.Output) != "" {
		result.Output += "\nFailure: " + result.FailureLocation
	} else {
		result.Output = "Failure: " + result.FailureLocation
	}
}
