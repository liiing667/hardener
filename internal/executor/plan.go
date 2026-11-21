package executor

import (
	"hardener/internal/config"
)

// runPlan is the immutable check set accepted at the start of a run. It
// contains both the host/precondition generation and the already-resolved
// checks, so a host change during execution cannot make a new check appear in
// an older score.
type runPlan struct {
	Generation *config.HostGeneration
	Suites     []plannedSuite
}

type plannedSuite struct {
	// Index is the position in the caller's suite slice, not the position in
	// the label-filtered plan. Observer events use it to stay aligned with the
	// dashboard's selected-suite list.
	Index  int
	Suite  config.TestSuite
	Checks []plannedCheck
}

type plannedCheck struct {
	Index    int
	Decision config.AdmissionDecision
}

// newRunPlan starts a new generation and freezes every decision that can
// change during a run: security-level fit, OS/arch applicability, the
// distro/profile override and prerequisite probes.
func newRunPlan(ctx *config.ExecContext, suites []config.TestSuite, securityLevel string) *runPlan {
	selectedSuites, selectedIndexes := selectPlannedSuites(suites, ctx.Labels)
	generation := ctx.BeginGeneration(selectedSuites...)

	plan := &runPlan{Generation: generation}
	for planIndex, suite := range selectedSuites {
		frozenSuite := clonePlanSuite(suite)
		planned := plannedSuite{
			Index: selectedIndexes[planIndex],
			Suite: frozenSuite,
		}
		planned.Checks = make([]plannedCheck, 0, len(frozenSuite.Checks))
		for checkIndex, check := range frozenSuite.Checks {
			decision := generation.Admit(check, securityLevel)
			planned.Checks = append(planned.Checks, plannedCheck{
				Index:    checkIndex,
				Decision: decision,
			})
		}
		plan.Suites = append(plan.Suites, planned)
	}
	return plan
}

func selectPlannedSuites(suites []config.TestSuite, labels []string) ([]config.TestSuite, []int) {
	selected := make([]config.TestSuite, 0, len(suites))
	indexes := make([]int, 0, len(suites))
	for index, suite := range suites {
		if !suiteMatchesLabels(suite, labels) {
			continue
		}
		selected = append(selected, suite)
		indexes = append(indexes, index)
	}
	return selected, indexes
}

func clonePlanSuite(suite config.TestSuite) config.TestSuite {
	cloned := suite
	cloned.Labels = clonePlanStrings(suite.Labels)
	cloned.Arch = clonePlanStrings(suite.Arch)
	if suite.Checks != nil {
		cloned.Checks = make([]config.Check, 0, len(suite.Checks))
		for _, check := range suite.Checks {
			cloned.Checks = append(cloned.Checks, clonePlanCheck(check))
		}
	}
	return cloned
}

func clonePlanCheck(check config.Check) config.Check {
	cloned := check
	cloned.OS = clonePlanStrings(check.OS)
	cloned.Arch = clonePlanStrings(check.Arch)
	if check.FixSudo != nil {
		fixSudo := *check.FixSudo
		cloned.FixSudo = &fixSudo
	}
	if check.Distro != nil {
		cloned.Distro = make(map[string]config.DistroOverride, len(check.Distro))
		for name, override := range check.Distro {
			if override.Sudo != nil {
				sudo := *override.Sudo
				override.Sudo = &sudo
			}
			if override.FixSudo != nil {
				fixSudo := *override.FixSudo
				override.FixSudo = &fixSudo
			}
			cloned.Distro[name] = override
		}
	}
	return cloned
}

func clonePlanStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}
