package config

import (
	"time"
)

// DistroOverride holds the fields that differ on a specific Linux distribution.
// Only non-zero fields override the top-level Check values.
type DistroOverride struct {
	Command  string `yaml:"command,omitempty"`
	Expected string `yaml:"expected,omitempty"`
	Fix      string `yaml:"fix,omitempty"`
	Sudo     *bool  `yaml:"sudo,omitempty"`
	FixSudo  *bool  `yaml:"fix_sudo,omitempty"`
}

type Check struct {
	ID              string                    `yaml:"id"`
	Description     string                    `yaml:"description"`
	Command         string                    `yaml:"command,omitempty"`
	Expected        string                    `yaml:"expected"`
	ExpectedOp      string                    `yaml:"expected_op,omitempty"`
	Sudo            bool                      `yaml:"sudo"`
	Fix             string                    `yaml:"fix,omitempty"`
	FixSudo         *bool                     `yaml:"fix_sudo,omitempty"`
	OS              []string                  `yaml:"os,omitempty"`
	Arch            []string                  `yaml:"arch,omitempty"`
	Distro          map[string]DistroOverride `yaml:"distro,omitempty"`
	RequiresCommand string                    `yaml:"requires_command,omitempty"`
	// RequiresFile skips the check with a missing-command state when the
	// given path does not exist. Useful for checks that inspect files that
	// are absent on some distros (e.g. /etc/hosts.allow, /etc/login.defs).
	RequiresFile  string `yaml:"requires_file,omitempty"`
	AffectedFile  string `yaml:"affected_file,omitempty"`
	PostAction    string `yaml:"post_action,omitempty"`
	SecurityLevel string `yaml:"security_level,omitempty"`
	RiskClass     string `yaml:"risk_class,omitempty"`
	RiskLevel     string `yaml:"risk_level,omitempty"`
	RiskDesc      string `yaml:"risk_desc,omitempty"`
}

// ResolveForDistro returns a copy of the check with distro-specific overrides applied.
//
// Lookup order (most specific → least specific):
//  1. "<distro>-<profile>" (e.g. "debian-server")
//  2. "<family>-<profile>" for each family in the chain
//  3. "<distro>"
//  4. "<family>" for each family in the chain (e.g. "debian" for Ubuntu,
//     "rhel" for Rocky, "suse" for openSUSE, "arch" for Manjaro)
//
// The distroChain must start with the concrete distro ID; subsequent entries
// are broader families supplied by DetectDistroFamily(). Returns false when
// the check has a distro map but no key in the chain matches, so the caller
// can skip it with a distro_skipped state.
func (c Check) ResolveForDistro(distroChain []string, profile string) (Check, bool) {
	if len(c.Distro) == 0 {
		return c, true // universal check — no distro map
	}
	if len(distroChain) == 0 {
		return c, false
	}
	if profile != "" {
		for _, d := range distroChain {
			if ov, ok := c.Distro[d+"-"+profile]; ok {
				return applyDistroOverride(c, ov), true
			}
		}
	}
	for _, d := range distroChain {
		if ov, ok := c.Distro[d]; ok {
			return applyDistroOverride(c, ov), true
		}
	}
	return c, false
}

func applyDistroOverride(c Check, ov DistroOverride) Check {
	if ov.Command != "" {
		c.Command = ov.Command
	}
	if ov.Expected != "" {
		c.Expected = ov.Expected
	}
	if ov.Fix != "" {
		c.Fix = ov.Fix
	}
	if ov.Sudo != nil {
		c.Sudo = *ov.Sudo
	}
	if ov.FixSudo != nil {
		c.FixSudo = ov.FixSudo
	}
	return c
}

type TestSuite struct {
	Title  string   `yaml:"title"`
	Labels []string `yaml:"labels"`
	OS     string   `yaml:"os,omitempty"`
	Arch   []string `yaml:"arch,omitempty"`
	Checks []Check  `yaml:"checksuites"`
}

// Fix stages name the last phase a check reached. They are stored in reports
// so a consumer can tell a failed fix from a fix whose re-check failed.
const (
	FixStageCheck    = "check"
	FixStageFix      = "fix"
	FixStageVerify   = "verify"
	FixStageComplete = "complete"
	FixStageState    = "state"
)

// Fix result values describe the fix command outcome, never the re-check.
const (
	FixResultApplied = "applied"
	FixResultFailed  = "failed"
	FixResultManual  = "manual"
	FixResultPending = "pending"
	FixResultNotRun  = "not_run"
)

// Verification result values describe the re-run check after the fix.
const (
	VerifyResultPassed  = "passed"
	VerifyResultFailed  = "failed"
	VerifyResultError   = "error"
	VerifyResultPending = "pending"
	VerifyResultNotRun  = "not_run"
)

// FixEvidence is the per-check transaction record shared by the executor and
// the saved report. A completed check carries a successful fix result and a
// passing verification result under the same ID.
type FixEvidence struct {
	ID              string `json:"id,omitempty"`
	Generation      string `json:"generation,omitempty"`
	CompletionID    string `json:"completion_id,omitempty"`
	Stage           string `json:"stage,omitempty"`
	CheckCommand    string `json:"check_command,omitempty"`
	Expected        string `json:"expected,omitempty"`
	PostAction      string `json:"post_action,omitempty"`
	FixResult       string `json:"fix_result,omitempty"`
	FixCommand      string `json:"fix_command,omitempty"`
	FixOutput       string `json:"fix_output,omitempty"`
	FixError        string `json:"fix_error,omitempty"`
	VerifyResult    string `json:"verify_result,omitempty"`
	VerifyCommand   string `json:"verify_command,omitempty"`
	VerifyOutput    string `json:"verify_output,omitempty"`
	VerifyError     string `json:"verify_error,omitempty"`
	Target          string `json:"target,omitempty"`
	BeforeExists    bool   `json:"before_exists"`
	BeforeChecksum  string `json:"before_checksum,omitempty"`
	BeforePerm      uint32 `json:"before_perm,omitempty"`
	FailureStage    string `json:"failure_stage,omitempty"`
	FailureLocation string `json:"failure_location,omitempty"`
	Pending         bool   `json:"pending,omitempty"`
	Completed       bool   `json:"completed,omitempty"`
	Attempts        int    `json:"attempts,omitempty"`
}

// Individual check result
type CheckResult struct {
	// Structured status for reports and dashboards; never infer errors from output text.
	SkipReason  string `json:"skip_reason,omitempty"`
	Error       string `json:"error,omitempty"`
	Manual      bool   `json:"manual,omitempty"`
	ID          string `json:"id"`
	Description string `json:"description"`
	Passed      bool   `json:"passed"`
	// FixApplied means the fix command exited 0. FixVerified means the check
	// was re-run afterwards and passed; only that counts as fixed.
	FixApplied  bool `json:"fix_applied"`
	FixVerified bool `json:"fix_verified,omitempty"`
	// Stage is the last phase this item reached: check, fix, verify, complete
	// or state. Status summarises the item without replacing the boolean
	// fields older consumers already read.
	Stage  string `json:"stage,omitempty"`
	Status string `json:"status,omitempty"`
	// FixID is the durable identity shared by the fix attempt and its
	// verification across failure, retry and restart. FixGeneration repeats it
	// for consumers that name the same value a generation.
	FixID         string `json:"fix_id,omitempty"`
	FixGeneration string `json:"fix_generation,omitempty"`
	CompletionID  string `json:"completion_id,omitempty"`
	FixResult     string `json:"fix_result,omitempty"`
	FixOutput     string `json:"fix_output,omitempty"`
	FixError      string `json:"fix_error,omitempty"`
	VerifyResult  string `json:"verify_result,omitempty"`
	// VerificationResult is the long-form alias of VerifyResult.
	VerificationResult string       `json:"verification_result,omitempty"`
	VerifyOutput       string       `json:"verify_output,omitempty"`
	VerifyError        string       `json:"verify_error,omitempty"`
	FailureStage       string       `json:"failure_stage,omitempty"`
	FailureLocation    string       `json:"failure_location,omitempty"`
	Location           string       `json:"location,omitempty"`
	Pending            bool         `json:"pending,omitempty"`
	FixEvidence        *FixEvidence `json:"fix_evidence,omitempty"`
	Output             string       `json:"output"`
	Skipped            bool         `json:"skipped"`
	SkippedDistro      bool         `json:"skipped_distro"`
	SkippedMissing     bool         `json:"skipped_missing"`
}

// Suite result
type SuiteResult struct {
	Title  string        `json:"title"`
	Checks []CheckResult `json:"checks"`
}

// FixOutcome is the report-level index of a per-check fix transaction.
type FixOutcome struct {
	CheckID         string `json:"check_id"`
	FixID           string `json:"fix_id,omitempty"`
	CompletionID    string `json:"completion_id,omitempty"`
	Stage           string `json:"stage,omitempty"`
	FixResult       string `json:"fix_result,omitempty"`
	VerifyResult    string `json:"verify_result,omitempty"`
	FailureStage    string `json:"failure_stage,omitempty"`
	FailureLocation string `json:"failure_location,omitempty"`
	Completed       bool   `json:"completed"`
	Pending         bool   `json:"pending,omitempty"`
}

// Full audit report
type AuditReport struct {
	Incomplete       bool          `json:"incomplete,omitempty"`
	IncompleteReason string        `json:"incomplete_reason,omitempty"`
	Timestamp        time.Time     `json:"timestamp"`
	OS               string        `json:"os"`
	Arch             string        `json:"arch"`
	Distro           string        `json:"distro"`
	SuiteResults     []SuiteResult `json:"suite_results"`
	ReportType       string        `json:"report_type"`
	// FixOutcomes indexes the per-check fix evidence so a report consumer can
	// find every pending or completed remediation without walking all checks.
	FixOutcomes      []FixOutcome `json:"fix_outcomes,omitempty"`
	FixPending       int          `json:"fix_pending,omitempty"`
	FixVerified      int          `json:"fix_verified,omitempty"`
	FixFailed        int          `json:"fix_failed,omitempty"`
	FailureLocations []string     `json:"failure_locations,omitempty"`
}

type SystemInfo struct {
	OS     string
	Arch   string
	Distro string
}

// === ROLLBACK TYPES ===

type DeltaEntry struct {
	RunID     string `json:"run_id"`
	Timestamp string `json:"timestamp"`
	FilePath  string `json:"file_path"`
	Checksum  string `json:"checksum"`
	Delta     string `json:"delta"`
	Perm      uint32 `json:"perm"`

	// The fields below were added after v1.2; entries without them are
	// complete records of a file that existed before the fix.

	// ID links a write-ahead record to its completion.
	ID      string `json:"id,omitempty"`
	CheckID string `json:"check_id,omitempty"`
	// Kind is "" for a file and EntryKindSysctl for a live kernel value.
	Kind string `json:"kind,omitempty"`
	// Pending marks a record written before the fix ran that was never
	// completed, e.g. because the process ended while the fix was running.
	Pending bool `json:"pending,omitempty"`
	// Created means the file did not exist before the fix; Removed means
	// the fix deleted a file that existed.
	Created bool `json:"created,omitempty"`
	Removed bool `json:"removed,omitempty"`
	// PostChecksum is the SHA-256 of what the fix left behind. Rollback
	// refuses to touch a file whose content no longer matches it.
	PostChecksum string `json:"post_checksum,omitempty"`
	// Before is the base64 pre-fix content: the whole file while a record is
	// pending, or the previous value of a sysctl entry.
	Before string `json:"before,omitempty"`
}

const EntryKindSysctl = "sysctl"
