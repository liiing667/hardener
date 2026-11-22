package executor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"hardener/internal/config"
	"hardener/rollback"
)

const (
	fixJournalFile    = "fix-transactions.json"
	fixJournalVersion = 1
)

// fixJournalMu serialises read-modify-write cycles. A fix keeps its check,
// target and pre-fix state across a process restart through this file.
var fixJournalMu sync.Mutex

type fixJournal struct {
	Version      int                        `json:"version"`
	Transactions map[string]*fixTransaction `json:"transactions"`
}

type fixTransaction struct {
	ID              string    `json:"id"`
	CheckID         string    `json:"check_id"`
	Target          string    `json:"target,omitempty"`
	BeforeExists    bool      `json:"before_exists"`
	BeforeChecksum  string    `json:"before_checksum,omitempty"`
	BeforePerm      uint32    `json:"before_perm,omitempty"`
	CheckCommand    string    `json:"check_command,omitempty"`
	Expected        string    `json:"expected,omitempty"`
	PostAction      string    `json:"post_action,omitempty"`
	FixCommand      string    `json:"fix_command,omitempty"`
	FixResult       string    `json:"fix_result,omitempty"`
	FixOutput       string    `json:"fix_output,omitempty"`
	FixError        string    `json:"fix_error,omitempty"`
	VerifyResult    string    `json:"verify_result,omitempty"`
	VerifyOutput    string    `json:"verify_output,omitempty"`
	VerifyError     string    `json:"verify_error,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	FailureStage    string    `json:"failure_stage,omitempty"`
	FailureLocation string    `json:"failure_location,omitempty"`
	Pending         bool      `json:"pending,omitempty"`
	Completed       bool      `json:"completed,omitempty"`
	Attempts        int       `json:"attempts,omitempty"`
	RunID           string    `json:"run_id,omitempty"`
	StartedAt       time.Time `json:"started_at,omitempty"`
	UpdatedAt       time.Time `json:"updated_at,omitempty"`
}

// FixJournalPath returns the durable fix transaction store for a run's base
// directory. Exported so tests and operators can point at the same file.
func FixJournalPath(baseDir string) string {
	return filepath.Join(baseDir, fixJournalFile)
}

func loadFixJournal(baseDir string) (*fixJournal, error) {
	path := FixJournalPath(baseDir)
	journal := &fixJournal{
		Version:      fixJournalVersion,
		Transactions: make(map[string]*fixTransaction),
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return journal, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read fix transactions %s: %w", path, err)
	}
	if strings.TrimSpace(string(data)) == "" {
		return journal, nil
	}
	if err := json.Unmarshal(data, journal); err != nil {
		return nil, fmt.Errorf("parse fix transactions %s: %w", path, err)
	}
	if journal.Version == 0 {
		journal.Version = fixJournalVersion
	}
	if journal.Version > fixJournalVersion {
		return nil, fmt.Errorf("fix transactions %s use unsupported version %d", path, journal.Version)
	}
	if journal.Transactions == nil {
		journal.Transactions = make(map[string]*fixTransaction)
	}
	for id, tx := range journal.Transactions {
		if tx == nil {
			delete(journal.Transactions, id)
			continue
		}
		if tx.ID == "" {
			tx.ID = id
		}
	}
	return journal, nil
}

func saveFixJournal(baseDir string, journal *fixJournal) error {
	if journal == nil {
		return fmt.Errorf("fix transaction set is nil")
	}
	journal.Version = fixJournalVersion
	if journal.Transactions == nil {
		journal.Transactions = make(map[string]*fixTransaction)
	}
	data, err := json.MarshalIndent(journal, "", "  ")
	if err != nil {
		return fmt.Errorf("encode fix transactions: %w", err)
	}
	data = append(data, '\n')

	path := FixJournalPath(baseDir)
	f, err := os.CreateTemp(filepath.Dir(path), ".hardener-fixes-*")
	if err != nil {
		return fmt.Errorf("create fix transaction file for %s: %w", path, err)
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	defer f.Close()

	if err := f.Chmod(0600); err != nil {
		return fmt.Errorf("set permissions for %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write fix transaction file for %s: %w", path, err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync fix transaction file for %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close fix transaction file for %s: %w", path, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace fix transaction file %s: %w", path, err)
	}
	return nil
}

// fixTransactionID freezes the check, target and fix command as the identity
// of one remediation. A retry with the same resolved ruleset reuses it; an
// edited check or target gets a new identity.
func fixTransactionID(check config.Check) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "check:%s\n", check.ID)
	fmt.Fprintf(hash, "command:%s\n", check.Command)
	fmt.Fprintf(hash, "expected:%s\n", check.Expected)
	fmt.Fprintf(hash, "expected_op:%s\n", check.ExpectedOp)
	fmt.Fprintf(hash, "fix:%s\n", check.Fix)
	fmt.Fprintf(hash, "affected_file:%s\n", check.AffectedFile)
	fmt.Fprintf(hash, "post_action:%s\n", check.PostAction)
	fmt.Fprintf(hash, "requires_command:%s\n", check.RequiresCommand)
	fmt.Fprintf(hash, "requires_file:%s\n", check.RequiresFile)
	fmt.Fprintf(hash, "sudo:%t\n", check.Sudo)
	if check.FixSudo != nil {
		fmt.Fprintf(hash, "fix_sudo:%t\n", *check.FixSudo)
	}
	sum := hash.Sum(nil)
	return "fix-" + hex.EncodeToString(sum[:16])
}

func newFixTransaction(check config.Check) *fixTransaction {
	now := time.Now().UTC()
	return &fixTransaction{
		ID:           fixTransactionID(check),
		CheckID:      check.ID,
		Target:       check.AffectedFile,
		CheckCommand: check.Command,
		Expected:     check.Expected,
		PostAction:   check.PostAction,
		FixCommand:   strings.TrimSpace(check.Fix),
		FixResult:    config.FixResultPending,
		VerifyResult: config.VerifyResultPending,
		Stage:        config.FixStageFix,
		Pending:      true,
		Attempts:     1,
		StartedAt:    now,
		UpdatedAt:    now,
	}
}

func recordPreFixState(tx *fixTransaction, check config.Check, txn *rollback.Txn) {
	if tx == nil {
		return
	}
	if txn != nil {
		if target := txn.File(); target != "" {
			tx.Target = target
		}
		exists, checksum, perm := txn.PreState()
		if tx.BeforeChecksum == "" {
			tx.BeforeExists = exists
			tx.BeforeChecksum = checksum
			tx.BeforePerm = perm
		}
	}
	if tx.Target == "" {
		tx.Target = check.AffectedFile
	}
	if tx.FixCommand == "" {
		tx.FixCommand = strings.TrimSpace(check.Fix)
	}
	tx.CheckCommand = check.Command
	tx.Expected = check.Expected
	tx.PostAction = check.PostAction
	tx.Attempts++
	tx.Stage = config.FixStageFix
	tx.FixResult = config.FixResultPending
	tx.FixOutput = ""
	tx.FixError = ""
	tx.VerifyResult = config.VerifyResultPending
	tx.VerifyOutput = ""
	tx.VerifyError = ""
	tx.FailureStage = ""
	tx.FailureLocation = ""
	tx.Pending = true
	tx.Completed = false
	tx.UpdatedAt = time.Now().UTC()
}

func (tx *fixTransaction) evidence(check config.Check) *config.FixEvidence {
	if tx == nil {
		return nil
	}
	target := tx.Target
	if target == "" {
		target = check.AffectedFile
	}
	return &config.FixEvidence{
		ID:              tx.ID,
		Generation:      tx.ID,
		CompletionID:    tx.ID,
		Stage:           tx.Stage,
		CheckCommand:    tx.CheckCommand,
		Expected:        tx.Expected,
		PostAction:      tx.PostAction,
		FixResult:       tx.FixResult,
		FixCommand:      tx.FixCommand,
		FixOutput:       tx.FixOutput,
		FixError:        tx.FixError,
		VerifyResult:    tx.VerifyResult,
		VerifyCommand:   check.Command,
		VerifyOutput:    tx.VerifyOutput,
		VerifyError:     tx.VerifyError,
		Target:          target,
		BeforeExists:    tx.BeforeExists,
		BeforeChecksum:  tx.BeforeChecksum,
		BeforePerm:      tx.BeforePerm,
		FailureStage:    tx.FailureStage,
		FailureLocation: tx.FailureLocation,
		Pending:         tx.Pending,
		Completed:       tx.Completed,
		Attempts:        tx.Attempts,
	}
}

func applyFixEvidence(result *config.CheckResult, evidence *config.FixEvidence) {
	if result == nil || evidence == nil {
		return
	}
	result.FixID = evidence.ID
	result.FixGeneration = evidence.Generation
	result.CompletionID = evidence.CompletionID
	result.FixResult = evidence.FixResult
	result.FixOutput = evidence.FixOutput
	result.FixError = evidence.FixError
	result.VerifyResult = evidence.VerifyResult
	result.VerificationResult = evidence.VerifyResult
	result.VerifyOutput = evidence.VerifyOutput
	result.VerifyError = evidence.VerifyError
	result.FailureStage = evidence.FailureStage
	result.FailureLocation = evidence.FailureLocation
	result.Location = evidence.FailureLocation
	result.Pending = evidence.Pending
	result.FixEvidence = evidence
}

func syncTransactionFromResult(tx *fixTransaction, check config.Check, result config.CheckResult) {
	if tx == nil {
		return
	}
	tx.CheckID = check.ID
	if tx.Target == "" {
		tx.Target = check.AffectedFile
	}
	if tx.FixCommand == "" {
		tx.FixCommand = strings.TrimSpace(check.Fix)
	}
	tx.CheckCommand = check.Command
	tx.Expected = check.Expected
	tx.PostAction = check.PostAction
	tx.Stage = result.Stage
	tx.FixResult = result.FixResult
	tx.FixOutput = result.FixOutput
	tx.FixError = result.FixError
	tx.VerifyResult = result.VerifyResult
	tx.VerifyOutput = result.VerifyOutput
	tx.VerifyError = result.VerifyError
	tx.FailureStage = result.FailureStage
	tx.FailureLocation = result.FailureLocation
	tx.Pending = result.Pending
	tx.Completed = result.FixApplied && result.FixVerified && result.Stage == config.FixStageComplete
	tx.UpdatedAt = time.Now().UTC()
}

func remediationTarget(check config.Check) string {
	if strings.TrimSpace(check.AffectedFile) != "" {
		return check.AffectedFile
	}
	return "(none)"
}

func fixFailureLocation(check config.Check, detail string) string {
	return fmt.Sprintf("check %s | stage fix | fix command %q | target %s | %s",
		check.ID, strings.TrimSpace(check.Fix), remediationTarget(check), detail)
}

func verifyFailureLocation(check config.Check, got string, err error) string {
	detail := fmt.Sprintf("expected %q, got %q", check.Expected, got)
	if err != nil {
		detail = fmt.Sprintf("%s (%v)", detail, err)
	}
	return fmt.Sprintf("check %s | stage verify | command %q | target %s | %s",
		check.ID, strings.TrimSpace(check.Command), remediationTarget(check), detail)
}

func pendingFixLocation(check config.Check, tx *fixTransaction) string {
	if tx != nil && tx.FailureLocation != "" {
		return tx.FailureLocation
	}
	if tx != nil && tx.FixError != "" {
		return fixFailureLocation(check, tx.FixError)
	}
	return fixFailureLocation(check, "fix has no successful completion evidence")
}

func fixStateFailure(ctx *config.ExecContext, check config.Check, result config.CheckResult, err error) config.CheckResult {
	result.Passed = false
	result.FixVerified = false
	result.Pending = true
	result.Status = "pending"
	result.Stage = config.FixStageState
	result.FailureStage = config.FixStageState
	result.FailureLocation = fmt.Sprintf("check %s | stage state | journal %s | %v",
		check.ID, FixJournalPath(ctx.BaseDir), err)
	result.Location = result.FailureLocation
	result.Error = err.Error()
	msg := fmt.Sprintf("Fix state for check %s is not durable: %v; refusing to publish completion.", check.ID, err)
	if strings.TrimSpace(result.Output) != "" {
		msg += "\nLast output: " + result.Output
	}
	result.Output = msg
	return result
}

func markFixEvidenceNotDurable(ctx *config.ExecContext, check config.Check, result *config.CheckResult, err error) {
	if result == nil {
		return
	}
	result.FixVerified = false
	result.Passed = false
	result.Pending = true
	result.Status = "pending"
	result.Stage = config.FixStageState
	result.FailureStage = config.FixStageState
	result.FailureLocation = fmt.Sprintf("check %s | stage state | journal %s | %v",
		check.ID, FixJournalPath(ctx.BaseDir), err)
	result.Location = result.FailureLocation
	msg := fmt.Sprintf("Fix for check %s was not published because its transaction could not be saved: %v.", check.ID, err)
	result.Output = msg
	if result.Error == "" {
		result.Error = err.Error()
	}
	if result.FixEvidence != nil {
		result.FixEvidence.Completed = false
		result.FixEvidence.Pending = true
		result.FixEvidence.Stage = result.Stage
		result.FixEvidence.FailureStage = result.FailureStage
		result.FixEvidence.FailureLocation = result.FailureLocation
	}
}
