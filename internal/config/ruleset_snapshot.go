package config

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// RulesetSnapshot is one completely loaded ruleset, frozen at admission:
// where it came from (Source), which content version it is (Version, the
// SHA-256 of the exact bytes that were parsed), and the full set of suites
// and checks that version produced (Suites).
//
// A run admits exactly one snapshot, so the checks it executes, the totals
// the dashboard renders, and the report it writes all describe the same
// ruleset version. A ruleset edited on disk, a retried load, or a restarted
// process can never blend two versions — or two halves of one load — into a
// single run.
type RulesetSnapshot struct {
	Source   string
	Version  string
	Suites   []TestSuite
	LoadedAt time.Time
}

// LoadRulesetSnapshot loads a standalone ruleset.yaml into a frozen
// snapshot. The file is read once; the version hashes the same bytes the
// parser saw, and any read or parse error fails the whole load — a snapshot
// never contains half a ruleset.
func LoadRulesetSnapshot(path string) (RulesetSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RulesetSnapshot{}, fmt.Errorf("cannot read ruleset file %q: %w", path, err)
	}
	suites, err := parseRuleset(data, path)
	if err != nil {
		return RulesetSnapshot{}, err
	}
	return NewRulesetSnapshot(path, rulesetVersion(data), suites), nil
}

// LoadGuideSnapshot loads a markdown guide directory into a frozen snapshot.
// The version covers every guide file in the directory, so editing any file
// between two loads changes the version.
func LoadGuideSnapshot(dir string, sys SystemInfo) (RulesetSnapshot, error) {
	suites, version, err := loadChecks(dir, sys)
	if err != nil {
		return RulesetSnapshot{}, err
	}
	return NewRulesetSnapshot(dir, version, suites), nil
}

// NewRulesetSnapshot freezes suites into a snapshot of source at version.
// The suites are deep-copied, so later edits of the caller's slice cannot
// reach into the snapshot.
func NewRulesetSnapshot(source, version string, suites []TestSuite) RulesetSnapshot {
	return RulesetSnapshot{
		Source:   source,
		Version:  version,
		Suites:   CloneSuites(suites),
		LoadedAt: time.Now().UTC(),
	}
}

// rulesetVersion hashes the exact bytes a ruleset was parsed from.
func rulesetVersion(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ShortVersion returns the first 12 hex characters of Version, the usual
// display form of a content hash. An empty Version stays empty.
func (s RulesetSnapshot) ShortVersion() string {
	const n = 12
	if len(s.Version) <= n {
		return s.Version
	}
	return s.Version[:n]
}

// ChecksTotal is the number of checks across all suites in the snapshot.
func (s RulesetSnapshot) ChecksTotal() int {
	total := 0
	for _, suite := range s.Suites {
		total += len(suite.Checks)
	}
	return total
}

// FrozenSuites returns a deep copy of the snapshot's suites. Callers may
// filter, reorder, or select from the copy; the snapshot itself stays the
// immutable record of what was admitted.
func (s RulesetSnapshot) FrozenSuites() []TestSuite {
	return CloneSuites(s.Suites)
}

// CloneSuites deep-copies suites, including every check's os/arch lists and
// distro override map, so a frozen ruleset cannot be mutated through a
// shared slice or map.
func CloneSuites(suites []TestSuite) []TestSuite {
	if suites == nil {
		return nil
	}
	out := make([]TestSuite, len(suites))
	for i, s := range suites {
		out[i] = s
		out[i].Labels = append([]string(nil), s.Labels...)
		out[i].Arch = append([]string(nil), s.Arch...)
		if s.Checks != nil {
			out[i].Checks = make([]Check, len(s.Checks))
			for j, c := range s.Checks {
				out[i].Checks[j] = CloneCheck(c)
			}
		}
	}
	return out
}

// CloneCheck deep-copies one check: its os/arch lists, its distro override
// map, and the optional sudo/fix_sudo pointers, so the copy shares nothing
// mutable with the original.
func CloneCheck(c Check) Check {
	out := c
	out.OS = append([]string(nil), c.OS...)
	out.Arch = append([]string(nil), c.Arch...)
	out.FixSudo = cloneBoolPtr(c.FixSudo)
	if c.Distro != nil {
		out.Distro = make(map[string]DistroOverride, len(c.Distro))
		for target, override := range c.Distro {
			out.Distro[target] = DistroOverride{
				Command:  override.Command,
				Expected: override.Expected,
				Fix:      override.Fix,
				Sudo:     cloneBoolPtr(override.Sudo),
				FixSudo:  cloneBoolPtr(override.FixSudo),
			}
		}
	}
	return out
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}
