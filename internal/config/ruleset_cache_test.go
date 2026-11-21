package config

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// A reload swaps the admitted snapshot atomically: a failed reload keeps the
// last complete version, a successful one replaces it wholesale — a run, a
// retried failure, and a restart never see a mix of two ruleset versions.
func TestRulesetCacheReloadNeverMixesVersions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ruleset.yaml")
	v1 := "title: One\nchecksuites:\n- id: a\n  command: printf 1\n  expected: 1\n"
	v2 := "title: One\nchecksuites:\n- id: b\n  command: printf 2\n  expected: 2\n- id: c\n  command: printf 3\n  expected: 3\n"

	if err := os.WriteFile(path, []byte(v1), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := LoadRulesetSnapshot(path)
	if err != nil {
		t.Fatal(err)
	}

	cache := NewRulesetCache()
	if _, ok := cache.Current(); ok {
		t.Fatal("cache admitted a snapshot before any load")
	}
	cache.Admit(first)

	// A failed reload keeps the admitted snapshot.
	if err := os.WriteFile(path, []byte("title: Broken\nchecksuites:\n- id: [unterminated\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	kept, err := cache.Reload(func() (RulesetSnapshot, error) { return LoadRulesetSnapshot(path) })
	if err == nil {
		t.Fatal("broken ruleset reloaded successfully")
	}
	if kept.Version != first.Version {
		t.Fatal("failed reload dropped the admitted snapshot")
	}
	current, ok := cache.Current()
	if !ok || current.Version != first.Version || current.ChecksTotal() != 1 {
		t.Fatalf("failed reload mixed the check set: %+v", current)
	}

	// A successful reload swaps the whole snapshot — never a merge.
	if err := os.WriteFile(path, []byte(v2), 0o644); err != nil {
		t.Fatal(err)
	}
	admitted, err := cache.Reload(func() (RulesetSnapshot, error) { return LoadRulesetSnapshot(path) })
	if err != nil {
		t.Fatal(err)
	}
	if admitted.Version == first.Version || admitted.ChecksTotal() != 2 {
		t.Fatalf("reload did not swap wholesale: %+v", admitted)
	}
	ids := map[string]bool{}
	for _, s := range admitted.Suites {
		for _, c := range s.Checks {
			ids[c.ID] = true
		}
	}
	if ids["a"] || !ids["b"] || !ids["c"] {
		t.Fatalf("reloaded snapshot mixes rule versions: %v", ids)
	}

	// A loader error before any admission admits nothing.
	empty := NewRulesetCache()
	boom := errors.New("boom")
	if _, err := empty.Reload(func() (RulesetSnapshot, error) { return RulesetSnapshot{}, boom }); !errors.Is(err, boom) {
		t.Fatalf("reload error = %v", err)
	}
	if _, ok := empty.Current(); ok {
		t.Fatal("failed first load admitted a snapshot")
	}
}
