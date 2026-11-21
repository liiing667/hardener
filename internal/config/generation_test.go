package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A prerequisite observed at admission stays absent for the whole generation,
// even if another process creates it while checks are running.
func TestUID32010HostGenerationFreezesFilePreconditions(t *testing.T) {
	gate := filepath.Join(t.TempDir(), "gate")
	check := Check{
		ID:            "gated",
		SecurityLevel: "baseline",
		Command:       "printf 1",
		Expected:      "1",
		RequiresFile:  gate,
	}
	ctx := &ExecContext{SecurityLevel: "baseline"}
	generation := NewHostGeneration(ctx, []TestSuite{{Checks: []Check{check}}})

	if err := os.WriteFile(gate, []byte("now present"), 0o600); err != nil {
		t.Fatal(err)
	}

	decision := generation.Admit(check, "baseline")
	if !decision.SkippedMissing || !strings.Contains(decision.SkipReason, "required file") {
		t.Fatalf("mid-run file creation changed the admitted check set: %+v", decision)
	}

	// A retry is a new generation and must observe the new host state.
	retry := NewHostGeneration(ctx, []TestSuite{{Checks: []Check{check}}})
	if decision := retry.Admit(check, "baseline"); !decision.Fit || decision.SkippedMissing {
		t.Fatalf("new generation did not re-probe the file: %+v", decision)
	}
}

// Distro, family and profile are part of the generation. Mutating the context
// after admission cannot change which override applies to later checks.
func TestUID32010HostGenerationFreezesDistroProfileOverride(t *testing.T) {
	check := Check{
		ID:            "override",
		SecurityLevel: "baseline",
		Command:       "printf universal",
		Expected:      "universal",
		Distro: map[string]DistroOverride{
			"ubuntu-server": {Command: "printf ubuntu-profile", Expected: "ubuntu-profile"},
			"debian":        {Command: "printf debian", Expected: "debian"},
		},
	}
	ctx := &ExecContext{
		SecurityLevel: "baseline",
		DistroName:    "ubuntu",
		DistroFamily:  []string{"ubuntu", "debian"},
		Profile:       "server",
	}
	generation := NewHostGeneration(ctx, []TestSuite{{Checks: []Check{check}}})

	ctx.DistroName = "debian"
	ctx.DistroFamily = []string{"debian"}
	ctx.Profile = "client"

	decision := generation.Admit(check, "baseline")
	if !decision.Fit || decision.Check.Command != "printf ubuntu-profile" || decision.Check.Expected != "ubuntu-profile" {
		t.Fatalf("override drifted after admission: %+v", decision)
	}
}

func TestUID32010FreezeSecurityFitRecordsReasonAtAdmission(t *testing.T) {
	if fits, _ := FreezeSecurityFit("high", "optional"); fits {
		t.Fatal("optional check was admitted at high")
	}
	_, reason := FreezeSecurityFit("high", "optional")
	if !strings.Contains(reason, "requires security level") {
		t.Fatalf("missing fit reason: %q", reason)
	}
	_, reason = FreezeSecurityFit("optional", "hihg")
	if !strings.Contains(reason, "unknown security level") {
		t.Fatalf("missing unknown-level reason: %q", reason)
	}
}
