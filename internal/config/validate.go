package config

import (
	"fmt"
	"strings"
)

// ValidateSuites enforces the structural rules that keep a typo or a
// copy-paste mistake from silently hiding a security control:
//
//   - every suite carries a non-empty title;
//   - every check carries the non-empty scalar fields the engine needs to
//     produce a meaningful result: id, description and expected;
//   - check ids are unique across every suite, because the scoring maps are
//     keyed by id and a duplicate would overwrite the earlier control's
//     pass/fail state and collapse its report entry.
//
// Unknown YAML fields and checks/checksuites conflicts are rejected earlier,
// at decode time, so they are not handled here.
func ValidateSuites(suites []TestSuite) error {
	var problems []string
	seenIDs := make(map[string]string)

	for suiteIdx, suite := range suites {
		suiteRef := fmt.Sprintf("suite #%d", suiteIdx+1)
		if strings.TrimSpace(suite.Title) != "" {
			suiteRef = fmt.Sprintf("suite %q", suite.Title)
		} else {
			problems = append(problems, fmt.Sprintf("%s: missing title", suiteRef))
		}

		for checkIdx, check := range suite.Checks {
			checkRef := fmt.Sprintf("%s check #%d", suiteRef, checkIdx+1)
			if id := strings.TrimSpace(check.ID); id != "" {
				checkRef = fmt.Sprintf("%s check %q", suiteRef, id)
				if first, ok := seenIDs[id]; ok {
					problems = append(problems, fmt.Sprintf(
						"duplicate check id %q: first defined in %s, redefined in %s",
						id, first, suiteRef))
				} else {
					seenIDs[id] = suiteRef
				}
			} else {
				problems = append(problems, fmt.Sprintf("%s: empty required field id", checkRef))
			}
			if strings.TrimSpace(check.Description) == "" {
				problems = append(problems, fmt.Sprintf("%s: empty required field description", checkRef))
			}
			if strings.TrimSpace(check.Expected) == "" {
				problems = append(problems, fmt.Sprintf("%s: empty required field expected", checkRef))
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("ruleset validation failed:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}
