package config

import (
	"os"
	"path/filepath"
	"testing"
)

const guideGoodFile = `---
title: Updates
os: linux
checksuites:
- id: u1
  command: printf 1
  expected: 1
---
# Updates
`

var guideTestSys = SystemInfo{OS: "linux", Arch: "amd64"}

// A guide directory gets the same frozen-version treatment as a ruleset
// file: same content, same version; any edit, a new version.
func TestLoadGuideSnapshotFreezesDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "10_updates.md"), []byte(guideGoodFile), 0o644); err != nil {
		t.Fatal(err)
	}

	snap, err := LoadGuideSnapshot(dir, guideTestSys)
	if err != nil {
		t.Fatalf("LoadGuideSnapshot: %v", err)
	}
	if snap.Source != dir || len(snap.Suites) != 1 || snap.ChecksTotal() != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	again, err := LoadGuideSnapshot(dir, guideTestSys)
	if err != nil {
		t.Fatal(err)
	}
	if again.Version != snap.Version {
		t.Fatal("unchanged guide got a new version")
	}

	if err := os.WriteFile(filepath.Join(dir, "20_more.md"), []byte(guideGoodFile), 0o644); err != nil {
		t.Fatal(err)
	}
	grown, err := LoadGuideSnapshot(dir, guideTestSys)
	if err != nil {
		t.Fatal(err)
	}
	if grown.Version == snap.Version || grown.ChecksTotal() != 2 {
		t.Fatal("guide edit did not produce a new version")
	}
}

// A guide file that fails to load used to be skipped silently, so the run
// went ahead with half the checks and the missing ones looked compliant.
// Both loading paths now fail instead of admitting a partial set.
func TestGuideLoadFailsInsteadOfReturningHalfTheChecks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
	}{
		{"unparseable frontmatter", func(t *testing.T, dir string) {
			broken := "---\ntitle: \"unterminated\n---\n# broken\n"
			if err := os.WriteFile(filepath.Join(dir, "20_broken.md"), []byte(broken), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"unreadable file", func(t *testing.T, dir string) {
			if err := os.Symlink(filepath.Join(dir, "missing-target"), filepath.Join(dir, "20_broken.md")); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "10_good.md"), []byte(guideGoodFile), 0o644); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, dir)

			if _, err := LoadChecks(dir, guideTestSys); err == nil {
				t.Fatal("LoadChecks returned half the checks instead of failing")
			}
			snap, err := LoadGuideSnapshot(dir, guideTestSys)
			if err == nil || snap.Suites != nil {
				t.Fatalf("partial guide admitted: %+v", snap)
			}
		})
	}
}
