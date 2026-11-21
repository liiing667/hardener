package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"hardener/internal/ui"

	"github.com/adrg/frontmatter"
)

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// guideFrontMatter is the YAML header of one markdown guide file.
type guideFrontMatter struct {
	Title  string   `yaml:"title"`
	OS     string   `yaml:"os"`
	Arch   []string `yaml:"arch"`
	Checks []Check  `yaml:"checksuites"`
}

// LoadChecks scans a directory for Markdown files, parses their frontmatter,
// and assembles a list of TestSuites compatible with the host system.
//
// The load is all-or-nothing: a file that cannot be read or parsed fails the
// whole load. It used to be skipped with only a log line, so the run went
// ahead with half the checks and the missing ones looked compliant.
func LoadChecks(dir string, sys SystemInfo) ([]TestSuite, error) {
	suites, _, err := loadChecks(dir, sys)
	return suites, err
}

// loadChecks is LoadChecks plus the guide's content version: a SHA-256 over
// the name and bytes of every guide file, in directory order (os.ReadDir
// sorts by name). LoadGuideSnapshot freezes that version into its snapshot.
func loadChecks(dir string, sys SystemInfo) ([]TestSuite, string, error) {
	var suites []TestSuite
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, "", err
	}

	version := sha256.New()
	var failures []string

	for _, f := range files {
		// Filter for Markdown files, ignoring directories and hidden files
		if f.IsDir() || strings.HasPrefix(f.Name(), ".") || filepath.Ext(f.Name()) != ".md" {
			continue
		}

		ui.PrintInfo(fmt.Sprintf("Processing file: %s", f.Name()))

		fullFilePath := filepath.Join(dir, f.Name())
		data, err := os.ReadFile(fullFilePath)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", f.Name(), err))
			continue
		}

		// The version covers exactly the bytes the parser saw, so a guide
		// edited between two loads gets a new version.
		version.Write([]byte(f.Name()))
		version.Write([]byte{0})
		version.Write(data)
		version.Write([]byte{0})

		var fm guideFrontMatter
		if _, err := frontmatter.Parse(bytes.NewReader(data), &fm); err != nil {
			failures = append(failures, fmt.Sprintf("%s: metadata parsing error: %v", f.Name(), err))
			continue
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

	// A guide that only half loaded must not run: the missing checks would
	// be reported as if the host simply had nothing to fix there.
	if len(failures) > 0 {
		return nil, "", fmt.Errorf("refusing to run a partially loaded guide: %d .md file(s) in %q failed to load:\n  - %s",
			len(failures), dir, strings.Join(failures, "\n  - "))
	}

	return suites, hex.EncodeToString(version.Sum(nil)), nil
}
