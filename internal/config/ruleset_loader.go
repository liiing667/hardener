package config

import (
	"fmt"
	"hardener/internal/ui"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// rulesetHeader is the optional first document in a ruleset.yaml.
// It has no title and no checksuites — only guide-level metadata.
type rulesetHeader struct {
	Preconditions preconditions `yaml:"preconditions"`
}

// rulesetDoc mirrors one suite document in a ruleset.yaml file.
// Both "checksuites" and "checks" are accepted as the list key so that
// existing ruleset files that accidentally used "checks" still work.
type rulesetDoc struct {
	Title  string   `yaml:"title"`
	OS     string   `yaml:"os"`
	Arch   []string `yaml:"arch"`
	Labels []string `yaml:"labels"`
	Suites []Check  `yaml:"checksuites"`
	Checks []Check  `yaml:"checks"` // fallback key used by some entries in the wild
}

// LoadRuleset parses a multi-document YAML file (documents separated by "---")
// and returns one TestSuite per document.  It intentionally skips OS / arch
// filtering so the caller (executeRun) can decide whether to apply it.
//
// Document boundaries are determined by the YAML grammar, not by scanning for
// "---" lines. A "---" inside a block scalar (e.g. a heredoc in a command or
// fix that writes another YAML file) is ordinary content; only a directive
// document marker at column zero starts a new document. Unknown or duplicate
// top-level keys, and documents that cannot be parsed (including block scalars
// that never close), fail the load instead of silently splitting or hiding a
// suite.
//
// The optional first document may be a header-only block (no title, no
// checksuites) that declares guide-level preconditions:
//
//	---
//	preconditions:
//	  tools: [brew, csrutil]
//	---
//	title: Secure Boot
//	checksuites: ...
func LoadRuleset(path string) ([]TestSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read ruleset file %q: %w", path, err)
	}

	docs, err := parseRulesetDocuments(data)
	if err != nil {
		return nil, fmt.Errorf("ruleset file %q: %w", path, err)
	}

	// Check whether the first non-empty document is a header (no title).
	suiteStartIdx := 0
	for i, doc := range docs {
		var probe rulesetDoc
		if err := doc.Decode(&probe); err != nil {
			return nil, fmt.Errorf("ruleset document %d: YAML parse error: %w", i+1, err)
		}

		if probe.Title == "" {
			// Title-less first document → treat as guide header.
			var hdr rulesetHeader
			if err := doc.Decode(&hdr); err != nil {
				return nil, fmt.Errorf("ruleset header: YAML parse error: %w", err)
			}
			if len(hdr.Preconditions.Tools) > 0 {
				ui.PrintInfo(fmt.Sprintf("Checking guide preconditions: %v", hdr.Preconditions.Tools))
				if !CheckPreconditions(hdr.Preconditions.Tools) {
					return nil, fmt.Errorf("ruleset %q cannot run: required tools are missing", path)
				}
			}
			suiteStartIdx = i + 1
		}
		break
	}

	var suites []TestSuite

	for i, doc := range docs[suiteStartIdx:] {
		var rd rulesetDoc
		if err := doc.Decode(&rd); err != nil {
			return nil, fmt.Errorf("ruleset document %d: YAML parse error: %w", suiteStartIdx+i+1, err)
		}

		if rd.Title == "" {
			continue
		}

		// Prefer "checksuites", fall back to "checks"
		checks := rd.Suites
		if len(checks) == 0 {
			checks = rd.Checks
		}

		if len(checks) == 0 {
			continue
		}

		suites = append(suites, TestSuite{
			Title:  rd.Title,
			Labels: rd.Labels,
			OS:     rd.OS,
			Arch:   rd.Arch,
			Checks: checks,
		})
	}

	if len(suites) == 0 {
		return nil, fmt.Errorf("no valid suites found in ruleset file %q", path)
	}

	return suites, nil
}

// allowedTopLevelKeys are the only keys accepted at the root of a ruleset
// document. Both "checksuites" and "checks" name the check list; the header
// document may additionally carry "preconditions".
var allowedTopLevelKeys = map[string]bool{
	"title":         true,
	"os":            true,
	"arch":          true,
	"labels":        true,
	"checksuites":   true,
	"checks":        true,
	"preconditions": true,
}

// parseRulesetDocuments splits a ruleset stream into its YAML documents using
// the YAML grammar itself (yaml.v3's multi-document decoder). A "---" line is
// a boundary only where the grammar treats it as a directive document marker,
// so "---" lines inside block scalars such as heredocs stay part of the
// enclosing document.
//
// Every non-empty document must be a top-level mapping with only known, unique
// keys: an unknown key (which older loaders ignored) or a duplicated key
// (which silently overwrote earlier values) fails the load, as do documents
// the parser cannot close, e.g. an unterminated block scalar.
func parseRulesetDocuments(data []byte) ([]*yaml.Node, error) {
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))

	var docs []*yaml.Node
	docNum := 0
	for {
		var node yaml.Node
		if err := decoder.Decode(&node); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("ruleset document %d: %w", docNum+1, err)
		}
		docNum++

		root := documentRoot(&node)
		if root == nil {
			// Explicit empty document ("---" followed by another marker).
			continue
		}
		if root.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("ruleset document %d: expected a top-level mapping, got %s", docNum, yamlKindName(root.Kind))
		}
		if err := validateTopLevelKeys(root, docNum); err != nil {
			return nil, err
		}
		docs = append(docs, root)
	}
	return docs, nil
}

// documentRoot unwraps the DocumentNode that the decoder emits and reports nil
// for an empty (null-only) document.
func documentRoot(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}
		node = node.Content[0]
	}
	if node.Tag == "!!null" && node.Value == "" && len(node.Content) == 0 {
		return nil
	}
	return node
}

// validateTopLevelKeys rejects unknown keys and duplicate keys at the document
// root. The check is limited to the top level so nested check mappings keep
// their own validation.
func validateTopLevelKeys(root *yaml.Node, docNum int) error {
	seen := make(map[string]bool, len(root.Content)/2)
	for i := 0; i+1 < len(root.Content); i += 2 {
		key := root.Content[i]
		name := key.Value
		if !allowedTopLevelKeys[name] {
			return fmt.Errorf("ruleset document %d: unknown top-level key %q (line %d)", docNum, name, key.Line)
		}
		if seen[name] {
			return fmt.Errorf("ruleset document %d: duplicate top-level key %q (line %d)", docNum, name, key.Line)
		}
		seen[name] = true
	}
	return nil
}

func yamlKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return "node"
	}
}
