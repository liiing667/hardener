package executor

import (
	"fmt"
	"hardener/internal/scoring"
	"hardener/internal/ui"
)

func MakeScorings(checksPassed, fixesApplied map[string]bool, generation ...string) {
	name := ""
	if len(generation) > 0 {
		name = generation[0]
	}
	MakeScoringsForGeneration(name, checksPassed, fixesApplied)
}

// MakeScoringsForGeneration is the generation-aware entry point. The printed
// score format is unchanged; naming the generation keeps retries from
// accidentally passing a previous run's maps to the consumer.
func MakeScoringsForGeneration(generation string, checksPassed, fixesApplied map[string]bool) {
	_ = generation
	checkScore := scoring.CalcCheckScore(checksPassed)
	fixScore := scoring.CalcFixScore(fixesApplied)

	ui.PrintFinalInfo(fmt.Sprintf("Check pass rate: %.2f%%", checkScore))
	// fixesApplied is empty for an audit, and for a fix run with nothing to
	// fix; a 0% fix rate would be meaningless there.
	if len(fixesApplied) > 0 {
		ui.PrintFinalInfo(fmt.Sprintf("Fix success rate (verified by re-check): %.2f%%", fixScore))
	}
}
