package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeGuideFile(t *testing.T, dir, name, frontMatter string) {
	t.Helper()
	content := frontMatter + "\n---\n\n# Guide body\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write guide file: %v", err)
	}
}

const validGuide = `---
title: Guide Suite
os: linux
arch:
  - amd64
checksuites:
  - id: guide-control
    description: markdown path control
    command: echo 1
    expected: 1
    sudo: false
    security_level: baseline
`

func TestLoadChecksRejectsUnknownField(t *testing.T) {
	dir := t.TempDir()
	writeGuideFile(t, dir, "01-bad.md", strings.Replace(validGuide,
		"security_level: baseline", "securty_level: baseline", 1))

	if _, err := LoadChecks(dir, SystemInfo{OS: "linux", Arch: "amd64"}); err == nil {
		t.Fatal("LoadChecks accepted a guide with an unknown field")
	} else if !strings.Contains(err.Error(), "field") {
		t.Fatalf("error should name the unknown field, got: %v", err)
	}
}

func TestLoadChecksRejectsDuplicateIDAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	second := strings.ReplaceAll(validGuide, "guide-control", "shared-id")
	first := strings.ReplaceAll(validGuide, "guide-control", "shared-id")
	writeGuideFile(t, dir, "01-first.md", first)
	writeGuideFile(t, dir, "02-second.md", strings.Replace(second, "Guide Suite", "Second Suite", 1))

	_, err := LoadChecks(dir, SystemInfo{OS: "linux", Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "duplicate check id") {
		t.Fatalf("expected duplicate id error, got: %v", err)
	}
}

func TestLoadChecksRejectsEmptyRequiredField(t *testing.T) {
	dir := t.TempDir()
	writeGuideFile(t, dir, "01-bad.md", strings.Replace(validGuide,
		"    expected: 1\n", "    expected: ''\n", 1))

	_, err := LoadChecks(dir, SystemInfo{OS: "linux", Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "empty required field expected") {
		t.Fatalf("expected empty-field error, got: %v", err)
	}
}

func TestLoadChecksAcceptsValidGuide(t *testing.T) {
	dir := t.TempDir()
	writeGuideFile(t, dir, "01-good.md", validGuide)
	// Non-YAML / frontmatter-less markdown must be ignored, not fatal.
	if err := os.WriteFile(filepath.Join(dir, "02-plain.md"), []byte("# no frontmatter\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	suites, err := LoadChecks(dir, SystemInfo{OS: "linux", Arch: "amd64"})
	if err != nil {
		t.Fatalf("valid guide must load: %v", err)
	}
	if len(suites) != 1 || suites[0].Title != "Guide Suite" || len(suites[0].Checks) != 1 {
		t.Fatalf("unexpected suites: %+v", suites)
	}
}
