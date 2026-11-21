package executor

import (
	"fmt"
	"hardener/internal/config"
	"hardener/internal/ui"
	"strings"
)

// runCheck runs one check and, in fix mode, its fix. It also returns the check
// with the distro overrides that were applied, so callers report the command
// and expected value that actually ran.
func runCheck(ctx *config.ExecContext, mode RunMode, check config.Check, security_level string) (config.CheckResult, config.Check) {
	generation := ctx.EnsureGeneration(config.TestSuite{Checks: []config.Check{check}})
	generation.ObserveCheck(check)
	return runAdmittedCheck(ctx, mode, generation.Admit(check, security_level))
}

// runAdmittedCheck executes a check whose applicability, distro/profile
// overrides and prerequisite probes were all frozen at run admission.
func runAdmittedCheck(ctx *config.ExecContext, mode RunMode, decision config.AdmissionDecision) (config.CheckResult, config.Check) {
	check := decision.Check
	if decision.Unexecuted() {
		result := config.CheckResult{
			ID:          check.ID,
			Description: check.Description,
			Output:      decision.SkipReason,
			SkipReason:  decision.SkipReason,
			Generation:  decision.Generation,
			FitSource:   decision.Source,
		}
		switch {
		case decision.SkippedMissing:
			result.SkippedMissing = true
			ui.PrintSkippedMissing(check.ID, admittedMissingPrerequisite(check, decision.SkipReason))
		case decision.SkippedDistro:
			result.SkippedDistro = true
		default:
			result.Skipped = true
		}
		return result, check
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
		Generation:  decision.Generation,
		FitSource:   decision.Source,
	}
	if err != nil {
		result.Error = err.Error()
	}

	if !passed && strings.TrimSpace(check.Fix) != "" {
		switch {
		case ctx.DryRun:
			printPlannedFix(check)
		case mode == ModeFix:
			ok, out, fixErr := RunFix(ctx, check)
			result.FixApplied = ok
			if fixErr != nil {
				result.Output = fmt.Sprintf("Fix failed: %v", fixErr)
				result.Error = fixErr.Error()
			} else {
				result.Output = out
			}
			if ok {
				verifyFix(check, &result)
			}
		}
	}

	return result, check
}

// admittedMissingPrerequisite keeps the established "Skipped missing: <name>" log
// line while the structured reason stays in the result.
func admittedMissingPrerequisite(check config.Check, reason string) string {
	if check.RequiresCommand != "" {
		return check.RequiresCommand
	}
	if check.RequiresFile != "" {
		return check.RequiresFile
	}
	return reason
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

// verifyFix re-runs the check after a fix whose command exited 0. Exit code 0
// alone says nothing about the resulting state: a fix can succeed and still
// leave the check failing, e.g. until its post_action (a reboot, a service
// restart) has happened.
func verifyFix(check config.Check, result *config.CheckResult) {
	passed, output, err := RunCheck(check)
	result.FixVerified = err == nil && passed
	if result.FixVerified {
		ui.PrintFixed(fmt.Sprintf("Fix for check %s verified: the check now passes.", check.ID))
		return
	}
	got := output
	if err != nil {
		got = strings.TrimSpace(fmt.Sprintf("%s (%v)", output, err))
	}
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
