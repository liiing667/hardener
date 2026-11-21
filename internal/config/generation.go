package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// Generation sources recorded in reports. They describe where the applicability
// decision came from, not where the ruleset came from.
const (
	GenerationSourceAdmission = "admission_snapshot"
	GenerationSourceLive      = "live_probe"
)

// HostGeneration is the immutable admission state for one run. Check
// applicability, distro/profile overrides and prerequisite probes are all
// resolved against this object, so a change to /etc/os-release, PATH or a
// requires_file path in the middle of a run cannot move a check into an older
// score.
type HostGeneration struct {
	ID            string    `json:"id"`
	Source        string    `json:"source"`
	CapturedAt    time.Time `json:"captured_at"`
	OSName        string    `json:"os,omitempty"`
	ArchName      string    `json:"arch,omitempty"`
	DistroName    string    `json:"distro,omitempty"`
	DistroFamily  []string  `json:"distro_family,omitempty"`
	Profile       string    `json:"profile,omitempty"`
	SecurityLevel string    `json:"security_level,omitempty"`
	CheckSetHash  string    `json:"check_set_hash,omitempty"`
	HostHash      string    `json:"host_hash,omitempty"`
	// Commands and Files hold the one-time probe result. ObserveCheck fills a
	// missing entry before admission; Admit never probes the live host.
	Commands map[string]bool `json:"commands,omitempty"`
	Files    map[string]bool `json:"files,omitempty"`
}

// RunGeneration is a descriptive alias for the same admission snapshot.
type RunGeneration = HostGeneration

// HostSnapshot is a descriptive alias for the same admission snapshot.
type HostSnapshot = HostGeneration

// AdmissionDecision is the frozen result of deciding whether one check belongs
// to a run. Check is the distro/profile-resolved check when it can run.
type AdmissionDecision struct {
	Check         Check
	Generation    string
	Source        string
	SecurityLevel string
	Fit           bool
	Skipped       bool
	SkippedDistro bool
	SkippedMissing bool
	SkipReason    string
}

// Unexecuted reports whether the decision removes the check from execution.
func (d AdmissionDecision) Unexecuted() bool {
	return d.Skipped || d.SkippedDistro || d.SkippedMissing
}

var generationSequence atomic.Uint64

// NewHostGeneration snapshots the host fields and all prerequisite probes
// needed by suites. It does not execute any check.
func NewHostGeneration(ctx *ExecContext, suites []TestSuite) *HostGeneration {
	if ctx == nil {
		ctx = &ExecContext{}
	}

	generation := &HostGeneration{
		Source:        GenerationSourceAdmission,
		CapturedAt:    time.Now().UTC(),
		OSName:        ctx.OSName,
		ArchName:      ctx.ArchName,
		DistroName:    ctx.DistroName,
		DistroFamily:  cloneGenerationStringSlice(ctx.DistroFamily),
		Profile:       ctx.Profile,
		SecurityLevel: NormalizeSecurityLevel(ctx.SecurityLevel),
		Commands:      make(map[string]bool),
		Files:         make(map[string]bool),
	}
	generation.CheckSetHash = FingerprintSuites(suites)
	generation.ObserveSuites(suites)
	generation.HostHash = fingerprintHost(generation)
	generation.ID = nextGenerationID(ctx, generation)
	return generation
}

// NewRunGeneration is an alias for NewHostGeneration.
func NewRunGeneration(ctx *ExecContext, suites []TestSuite) *HostGeneration {
	return NewHostGeneration(ctx, suites)
}

// ObserveSuites records every prerequisite named by the supplied suites. It is
// safe to call more than once: an observed command or file is never re-probed.
func (g *HostGeneration) ObserveSuites(suites []TestSuite) {
	if g == nil {
		return
	}
	for _, suite := range suites {
		for _, check := range suite.Checks {
			g.ObserveCheck(check)
		}
	}
}

// ObserveCheck records the check's prerequisite probe exactly once.
func (g *HostGeneration) ObserveCheck(check Check) {
	if g == nil {
		return
	}
	if g.Commands == nil {
		g.Commands = make(map[string]bool)
	}
	if g.Files == nil {
		g.Files = make(map[string]bool)
	}

	changed := false
	if command := strings.TrimSpace(check.RequiresCommand); command != "" {
		if _, exists := g.Commands[check.RequiresCommand]; !exists {
			g.Commands[check.RequiresCommand] = commandAvailable(command)
			changed = true
		}
	}
	if path := strings.TrimSpace(check.RequiresFile); path != "" {
		if _, exists := g.Files[check.RequiresFile]; !exists {
			g.Files[check.RequiresFile] = preconditionFilePresent(check.RequiresFile)
			changed = true
		}
	}
	if changed {
		g.HostHash = fingerprintHost(g)
	}
}

// Admit freezes all applicability decisions for one check against this
// generation. The returned check has distro/profile overrides applied when
// the check is executable.
func (g *HostGeneration) Admit(check Check, securityLevel string) AdmissionDecision {
	if securityLevel == "" && g != nil {
		securityLevel = g.SecurityLevel
	}
	decision := AdmissionDecision{
		Check:         cloneAdmittedCheck(check),
		Source:        GenerationSourceAdmission,
		SecurityLevel: securityLevel,
	}
	if g != nil {
		decision.Generation = g.ID
		decision.Source = g.Source
		if decision.Source == "" {
			decision.Source = GenerationSourceAdmission
		}
	}

	if fits, reason := FreezeSecurityFit(securityLevel, check.SecurityLevel); !fits {
		decision.Skipped = true
		decision.SkipReason = reason
		return decision
	}

	sys := SystemInfo{}
	distroName := ""
	distroFamily := []string(nil)
	profile := ""
	if g != nil {
		sys = SystemInfo{OS: g.OSName, Arch: g.ArchName}
		distroName = g.DistroName
		distroFamily = g.DistroFamily
		profile = g.Profile
	}

	if ok, reason := IsCheckApplicable(check, sys); !ok {
		decision.SkippedDistro = true
		decision.SkipReason = reason
		return decision
	}

	chain := append([]string(nil), distroFamily...)
	if len(chain) == 0 || chain[0] != distroName {
		chain = append([]string{distroName}, chain...)
	}
	resolved, supported := check.ResolveForDistro(chain, profile)
	if !supported {
		reason := fmt.Sprintf("not supported on distro %q", distroName)
		decision.SkippedDistro = true
		decision.SkipReason = reason
		return decision
	}
	decision.Check = cloneAdmittedCheck(resolved)

	if resolved.RequiresCommand != "" {
		available := g.commandObserved(resolved.RequiresCommand)
		if !available {
			reason := fmt.Sprintf("required command %q not found", resolved.RequiresCommand)
			decision.SkippedMissing = true
			decision.SkipReason = reason
			return decision
		}
	}

	if resolved.RequiresFile != "" {
		present := g.fileObserved(resolved.RequiresFile)
		if !present {
			reason := fmt.Sprintf("required file %q not present", resolved.RequiresFile)
			decision.SkippedMissing = true
			decision.SkipReason = reason
			return decision
		}
	}

	decision.Fit = true
	return decision
}

func cloneAdmittedCheck(check Check) Check {
	cloned := check
	cloned.OS = cloneGenerationStringSlice(check.OS)
	cloned.Arch = cloneGenerationStringSlice(check.Arch)
	if check.FixSudo != nil {
		fixSudo := *check.FixSudo
		cloned.FixSudo = &fixSudo
	}
	if check.Distro != nil {
		cloned.Distro = make(map[string]DistroOverride, len(check.Distro))
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

func cloneGenerationStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string{}, values...)
}

func (g *HostGeneration) commandObserved(command string) bool {
	if g == nil {
		return commandAvailable(command)
	}
	if available, exists := g.Commands[command]; exists {
		return available
	}
	// A prerequisite that was not observed before admission is not part of
	// this generation. Probing it here would let a command created by an
	// earlier check enter the admitted set after the fact.
	return false
}

func (g *HostGeneration) fileObserved(path string) bool {
	if g == nil {
		return preconditionFilePresent(path)
	}
	if present, exists := g.Files[path]; exists {
		return present
	}
	return false
}

// FingerprintSuites returns a stable identity for the admitted check set. The
// hash changes when fields that affect execution or reporting are edited.
func FingerprintSuites(suites []TestSuite) string {
	hash := sha256.New()
	for suiteIndex, suite := range suites {
		fmt.Fprintf(hash, "suite:%d|title:%q|os:%q|arch:%v|labels:%v\n",
			suiteIndex, suite.Title, suite.OS, suite.Arch, suite.Labels)
		for checkIndex, check := range suite.Checks {
			encoded, err := json.Marshal(check)
			if err != nil {
				encoded = []byte(fmt.Sprintf("%#v", check))
			}
			fmt.Fprintf(hash, "check:%d|%s\n", checkIndex, encoded)
		}
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func fingerprintHost(generation *HostGeneration) string {
	hash := sha256.New()
	fmt.Fprintf(hash, "os:%s|arch:%s|distro:%s|family:%v|profile:%s|level:%s\n",
		generation.OSName, generation.ArchName, generation.DistroName,
		generation.DistroFamily, generation.Profile, generation.SecurityLevel)

	commands := make([]string, 0, len(generation.Commands))
	for command := range generation.Commands {
		commands = append(commands, command)
	}
	sort.Strings(commands)
	for _, command := range commands {
		fmt.Fprintf(hash, "command:%s=%t\n", command, generation.Commands[command])
	}

	files := make([]string, 0, len(generation.Files))
	for path := range generation.Files {
		files = append(files, path)
	}
	sort.Strings(files)
	for _, path := range files {
		fmt.Fprintf(hash, "file:%s=%t\n", path, generation.Files[path])
	}
	return hex.EncodeToString(hash.Sum(nil))
}

func nextGenerationID(ctx *ExecContext, generation *HostGeneration) string {
	sequence := generationSequence.Add(1)
	hash := sha256.New()
	fmt.Fprintf(hash, "run:%s|seq:%d|host:%s|checks:%s|at:%d\n",
		ctx.RunID, sequence, generation.HostHash, generation.CheckSetHash,
		generation.CapturedAt.UnixNano())
	return "run-" + hex.EncodeToString(hash.Sum(nil)[:16])
}

// commandAvailable mirrors the executor PATH handling for prerequisite probes:
// the command must resolve on PATH or in one of the sbin directories hardener
// adds to every check command.
func commandAvailable(command string) bool {
	raw := command
	command = strings.TrimSpace(command)
	if command == "" {
		return raw == ""
	}
	if filepath.IsAbs(command) {
		_, err := os.Stat(command)
		return err == nil
	}
	if _, err := exec.LookPath(command); err == nil {
		return true
	}
	for _, directory := range []string{"/usr/local/sbin", "/usr/sbin", "/sbin"} {
		if _, err := os.Stat(filepath.Join(directory, command)); err == nil {
			return true
		}
	}
	return false
}

func preconditionFilePresent(path string) bool {
	if path == "" {
		return true
	}
	_, err := os.Lstat(path)
	// Match runCheck: a permission error means the file probably exists but
	// cannot be stat'ed without sudo, so only a real "not found" skips it.
	return err == nil || !os.IsNotExist(err)
}

