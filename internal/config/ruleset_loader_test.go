package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuleset stores a ruleset fixture in a temporary file and returns its
// path.
func writeRuleset(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ruleset.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write ruleset fixture: %v", err)
	}
	return path
}

// TestLoadRulesetGrammarBoundaries is the fixed boundary fixture: document
// boundaries follow the YAML grammar, so "---" lines inside block scalars
// (heredocs, folded scalars) stay inside their document while real column-zero
// markers still separate documents. The legacy "checks" alias keeps working.
func TestLoadRulesetGrammarBoundaries(t *testing.T) {
	fixture := `---
preconditions:
  tools:
  - sh
---
title: Heredoc Suite
checksuites:
- id: heredoc-check
  command: |
    cat > /tmp/example.yaml <<'EOF'
    ---
    key: value
    EOF
    echo done
  expected: done
- id: folded-check
  fix: >-
    cat <<'EOF' > /tmp/folded.txt
    ---
    not a document
    EOF
---
title: Legacy Alias Suite
checks:
- id: alias-check
  command: printf ok
  expected: ok
---
title: CRLF Suite
checksuites:
- id: crlf-check
  command: printf crlf
  expected: crlf
`

	suites, err := LoadRuleset(writeRuleset(t, fixture))
	if err != nil {
		t.Fatalf("LoadRuleset: %v", err)
	}
	if len(suites) != 3 {
		t.Fatalf("expected 3 suites, got %d: %+v", len(suites), suites)
	}

	first := suites[0].Checks
	if len(first) != 2 {
		t.Fatalf("expected 2 checks in heredoc suite, got %d: %+v", len(first), first)
	}
	if !strings.Contains(first[0].Command, "---\nkey: value") {
		t.Fatalf("heredoc document marker was split out of command: %q", first[0].Command)
	}
	if strings.Contains(first[1].Fix, "title:") {
		t.Fatalf("folded scalar content leaked across documents: %q", first[1].Fix)
	}
	if suites[1].Title != "Legacy Alias Suite" || len(suites[1].Checks) != 1 || suites[1].Checks[0].ID != "alias-check" {
		t.Fatalf("checks alias not honoured: %+v", suites[1])
	}
	if suites[2].Title != "CRLF Suite" {
		t.Fatalf("CRLF document marker not recognised: %+v", suites[2])
	}
}

// TestLoadRulesetRejectsHiddenSuite reproduces the attack against the old
// line-based splitter. A block scalar opened with a tag or anchor (the old
// regex only recognised plain "key: |" lines) contains a heredoc whose own
// "---" line is ordinary content. The old splitter did not track that scalar
// and split the document, so the visible check lost its command and the tail
// of the stream was silently dropped or misparsed. The grammar-driven parser
// must keep the heredoc inside the one declared document.
func TestLoadRulesetRejectsHiddenSuite(t *testing.T) {
	fixture := `title: Visible Suite
checksuites:
- id: visible-check
  command: !!str |-
    cat <<'X'
    ---
    title: Hidden Suite
    checksuites:
    - id: hidden-check
      command: echo should-not-run
      expected: "1"
    X
  expected: 1
---
title: Real Second
checksuites:
- id: second-check
  command: echo two
  expected: 1
`
	suites, err := LoadRuleset(writeRuleset(t, fixture))
	if err != nil {
		t.Fatalf("LoadRuleset: %v", err)
	}
	if len(suites) != 2 {
		t.Fatalf("expected the 2 grammar-level suites, got %d: %+v", len(suites), suites)
	}
	if suites[0].Title != "Visible Suite" {
		t.Fatalf("unexpected suite title: %q", suites[0].Title)
	}
	if len(suites[0].Checks) != 1 || suites[0].Checks[0].ID != "visible-check" {
		t.Fatalf("visible check was split or lost: %+v", suites[0].Checks)
	}
	command := suites[0].Checks[0].Command
	if !strings.Contains(command, "---\ntitle: Hidden Suite") || strings.Contains(command, "second-check") {
		t.Fatalf("heredoc content was split across documents: %q", command)
	}
	if suites[1].Title != "Real Second" || suites[1].Checks[0].ID != "second-check" {
		t.Fatalf("real second suite was dropped: %+v", suites[1])
	}
}

// TestLoadRulesetStrictTopLevelKeys ensures unknown and duplicate top-level
// keys fail instead of being ignored or silently overwritten.
func TestLoadRulesetStrictTopLevelKeys(t *testing.T) {
	base := func(body string) string {
		return "title: Strict Suite\n" + body + "checksuites:\n- id: c\n  command: printf x\n  expected: x\n"
	}
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "unknown key",
			content: base("evil: hidden payload\n"),
			want:    "unknown top-level key",
		},
		{
			name:    "duplicate key",
			content: base("title: Overwritten Suite\n"),
			want:    "duplicate top-level key",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRuleset(writeRuleset(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

// TestLoadRulesetUnclosableBlocks covers inputs the parser cannot complete:
// an indented "---" is not a document marker, an unterminated block scalar
// leaves the document open, and a bare scalar is not a suite mapping.
func TestLoadRulesetUnclosableBlocks(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "indented marker is content",
			content: "title: A\nchecksuites:\n- id: a\n  x:\n  ---\ntitle: C\n",
			want:    "ruleset document 1",
		},
		{
			name:    "unterminated block scalar",
			content: "title: A\ncommand: |\n  echo hi\n bad-indent\n",
			want:    "ruleset document 1",
		},
		{
			name:    "scalar document",
			content: "just-a-scalar\n",
			want:    "expected a top-level mapping",
		},
		{
			name:    "empty stream",
			content: "---\n---\n# only a comment\n",
			want:    "no valid suites",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRuleset(writeRuleset(t, tc.content))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}
