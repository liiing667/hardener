package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hardener/internal/ui"

	"github.com/adrg/frontmatter"
	"gopkg.in/yaml.v3"
)

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// LoadChecks scans a directory for Markdown files, parses their frontmatter,
// and assembles a list of TestSuites compatible with the host system.
func LoadChecks(dir string, sys SystemInfo) ([]TestSuite, error) {
	var suites []TestSuite
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, f := range files {
		// Filter for Markdown files, ignoring directories and hidden files
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") || filepath.Ext(f.Name()) != ".md" {
			continue
		}

		ui.PrintInfo(fmt.Sprintf("Processing file: %s", f.Name()))

		fullFilePath := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(fullFilePath)
		if err != nil {
			ui.Error(fmt.Errorf("failed to read %s: %w", f.Name(), err))
			continue
		}

		// Structure for unmarshaling the Markdown YAML header
		type FileFrontMatter struct {
			Title  string   `yaml:"title"`
			OS     string   `yaml:"os"`
			Arch   []string `yaml:"arch"`
			Checks []Check  `yaml:"checksuites"`
		}

		var fm FileFrontMatter
		if _, err := frontmatter.Parse(bytes.NewReader(data), &fm); err != nil {
			return nil, fmt.Errorf("metadata parsing error in %s: %w", f.Name(), err)
		}

		// Re-decode YAML front matter with a strict decoder. The frontmatter
		// library uses yaml.v2, which silently drops unknown keys; a misspelled
		// check field would then turn the control into an invisible skip.
		if raw, ok := yamlFrontMatter(data); ok {
			dec := yaml.NewDecoder(bytes.NewReader(raw))
			dec.KnownFields(true)
			if err := dec.Decode(&fm); err != nil {
				return nil, fmt.Errorf("metadata parsing error in %s: %w", f.Name(), err)
			}
		}

		// --- Platform Validation Logic ---
		if ok, reason := IsSuiteApplicable(fm.OS, fm.Arch, sys); !ok {
			ui.PrintInfo(fmt.Sprintf("Skipping %s: %s", f.Name(), reason))
			continue
		}

		// --- Suite Assembly ---

		if len(fm.Checks) > 0 {
			ui.PrintInfo(fmt.Sprintf("Adding Suite: %s (%d checks)", fm.Title, len(fm.Checks)))

			suites = append(suites, TestSuite{
				Title:  fm.Title,
				Labels: []string{strings.ToLower(fm.Title)},
				OS:     fm.OS,
				Arch:   fm.Arch,
				Checks: fm.Checks, // Checks inherit the document-level architecture validity
			})
		}
	}

	if err := ValidateSuites(suites); err != nil {
		return nil, err
	}

	return suites, nil
}

// yamlFrontMatter extracts the raw YAML block of a Markdown file. It mirrors
// the delimiter detection of the frontmatter library ("---" or "---yaml")
// and returns ok=false for files without a YAML header, which keep going
// through the lenient parser unchanged.
func yamlFrontMatter(data []byte) (block []byte, ok bool) {
	lines := bytes.Split(data, []byte("\n"))
	if len(lines) < 2 {
		return nil, false
	}
	first := strings.TrimSpace(string(lines[0]))
	if first != "---" && first != "---yaml" {
		return nil, false
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(string(lines[i])) == "---" {
			return bytes.Join(lines[1:i], []byte("\n")), true
		}
	}
	return nil, false
}
