package executor

import (
	"os"
	"path/filepath"
	"testing"

	"hardener/internal/config"
)

// The admitted plan must not add a check to the score merely because an
// earlier check created its required file.
func TestUID32010RunPlanFreezesRequiresFileAcrossMidRunChange(t *testing.T) {
	dir := t.TempDir()
	gate := filepath.Join(dir, "gate")
	ctx := &config.ExecContext{BaseDir: dir, SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{
		{
			ID:            "creates-gate",
			SecurityLevel: "baseline",
			Command:       "touch '" + gate + "'",
			Expected:      "",
		},
		{
			ID:            "gated",
			SecurityLevel: "baseline",
			Command:       "printf 1",
			Expected:      "1",
			RequiresFile:  gate,
		},
	}}}

	results, passed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.Generation == "" || ctx.Snapshot == nil {
		t.Fatal("run did not expose its accepted generation")
	}
	if _, err := os.Stat(gate); err != nil {
		t.Fatalf("first check did not create the gate: %v", err)
	}
	if len(results) != 1 || len(results[0].Checks) != 2 {
		t.Fatalf("unexpected result shape: %+v", results)
	}
	gated := results[0].Checks[1]
	if !gated.SkippedMissing || gated.Generation == "" {
		t.Fatalf("new prerequisite entered the old run: %+v", gated)
	}
	if _, scored := passed["gated"]; scored {
		t.Fatalf("mid-run check entered the score: %v", passed)
	}
	if !passed["creates-gate"] || len(passed) != 1 {
		t.Fatalf("unexpected score inputs: %v", passed)
	}
}

// A retry must publish a new generation and a score computed from that
// generation's check set, never from the previous run's skipped checks.
func TestUID32010RetryStartsNewGenerationAndRescore(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	ctx := &config.ExecContext{SecurityLevel: "baseline"}
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{{
		ID:            "gated",
		SecurityLevel: "baseline",
		Command:       "printf 1",
		Expected:      "1",
		RequiresFile:  gate,
	}}}}

	first, firstPassed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || !first[0].Checks[0].SkippedMissing || len(firstPassed) != 0 {
		t.Fatalf("first generation was not admitted with a missing prerequisite: %+v %v", first, firstPassed)
	}

	if err := os.WriteFile(gate, []byte("present"), 0o600); err != nil {
		t.Fatal(err)
	}
	second, secondPassed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(second) != 1 || second[0].Checks[0].SkippedMissing {
		t.Fatalf("retry did not re-admit the check: %+v", second)
	}
	if !secondPassed["gated"] || len(secondPassed) != 1 {
		t.Fatalf("retry score mixed generations: %v", secondPassed)
	}
	if first[0].Generation == "" || second[0].Generation == "" || first[0].Generation == second[0].Generation {
		t.Fatalf("retry reused the prior generation: %q -> %q", first[0].Generation, second[0].Generation)
	}
}

// Changing distro/profile in an observer is a host change during the same
// run. Every check must keep using the override resolved at admission.
func TestUID32010MidRunDistroChangeKeepsAdmittedOverrides(t *testing.T) {
	ctx := &config.ExecContext{
		SecurityLevel: "baseline",
		DistroName:    "ubuntu",
		DistroFamily:  []string{"ubuntu", "debian"},
		Profile:       "server",
	}
	override := func() config.Check {
		return config.Check{
			SecurityLevel: "baseline",
			Expected:      "1",
			Command:       "printf 0",
			Distro: map[string]config.DistroOverride{
				"ubuntu-server": {Command: "printf 1", Expected: "1"},
				"debian-server": {Command: "printf 0", Expected: "1"},
			},
		}
	}
	first, second := override(), override()
	first.ID, second.ID = "first", "second"
	suites := []config.TestSuite{{Title: "Category", Checks: []config.Check{first, second}}}

	results, passed, _, err := RunSuitesObserved(ctx, ModeAudit, "linux", "amd64", suites, func(event RunEvent) {
		if event.Kind == CheckFinished && event.CheckIndex == 0 {
			ctx.DistroName = "debian"
			ctx.DistroFamily = []string{"debian"}
		}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range results[0].Checks {
		if !check.Passed {
			t.Fatalf("override changed during the run: %+v", check)
		}
	}
	if !passed["first"] || !passed["second"] || len(passed) != 2 {
		t.Fatalf("unexpected score inputs after distro change: %v", passed)
	}
}

func TestUID32010ResultProvenanceRejectsMixedGenerations(t *testing.T) {
	same := []config.SuiteResult{
		{Title: "A", Generation: "run-1", GenerationSource: "admission_snapshot", CheckSetHash: "checks-1"},
		{Title: "B", Generation: "run-1", GenerationSource: "admission_snapshot", CheckSetHash: "checks-1"},
	}
	generation, source, hash, mixed := ResultProvenance(same)
	if mixed || generation != "run-1" || source != "admission_snapshot" || hash != "checks-1" {
		t.Fatalf("same-generation provenance rejected: %q %q %q %v", generation, source, hash, mixed)
	}

	mixedResults := append([]config.SuiteResult(nil), same...)
	mixedResults[1].Generation = "run-2"
	if _, _, _, mixed := ResultProvenance(mixedResults); !mixed {
		t.Fatal("mixed generations were accepted")
	}
}

// Legacy result sets without generation fields keep working.
func TestUID32010ResultProvenanceAcceptsLegacyResults(t *testing.T) {
	generation, source, hash, mixed := ResultProvenance([]config.SuiteResult{{
		Title:  "Legacy",
		Checks: []config.CheckResult{{ID: "old", Passed: true}},
	}})
	if mixed || generation != "" || source != "" || hash != "" {
		t.Fatalf("legacy results changed shape: %q %q %q %v", generation, source, hash, mixed)
	}
}
