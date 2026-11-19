package config

import (
	"os"
	"runtime"
	"strings"
)

// DetectDistro reads /etc/os-release and returns the lowercase distro ID
// (e.g. "ubuntu", "debian", "arch", "fedora"). Falls back to runtime.GOOS
// when the file is absent or unparseable (e.g. on macOS or Windows).
func DetectDistro() string {
	id, _ := readOsRelease()
	if id != "" {
		return id
	}
	return runtime.GOOS
}

// DetectDistroFamily returns the family (or families) the current distro
// belongs to. It reads /etc/os-release, first honoring ID_LIKE, then falling
// back to a hand-maintained map from ID to family. The returned slice is
// ordered from most-specific to least-specific, e.g. ["ubuntu", "debian"] on
// Ubuntu, ["rocky", "rhel", "fedora"] on Rocky Linux.
//
// Family names used by rulesets:
//
//	debian  — Debian, Ubuntu, Kali, Linux Mint, ...
//	rhel    — Rocky, AlmaLinux, RHEL, Oracle Linux, CentOS Stream, ...
//	fedora  — Fedora (also included in the rhel chain)
//	suse    — openSUSE Leap/Tumbleweed, SLES
//	arch    — Arch, Manjaro, EndeavourOS
//
// The list always starts with the concrete distro ID so `ResolveForDistro`
// can try exact matches first.
func DetectDistroFamily() []string {
	id, likes := readOsRelease()
	if id == "" {
		return []string{runtime.GOOS}
	}

	chain := []string{id}
	for _, l := range likes {
		chain = appendUnique(chain, l)
	}
	// Ensure a canonical family is present even when ID_LIKE is missing.
	for _, fam := range knownFamily(id) {
		chain = appendUnique(chain, fam)
	}
	return chain
}

// readOsRelease returns (ID, ID_LIKE tokens). Both are lowercased and stripped.
func readOsRelease() (string, []string) {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", nil
	}
	var id string
	var likes []string
	for _, line := range strings.Split(string(data), "\n") {
		switch {
		case strings.HasPrefix(line, "ID="):
			id = normalizeOSReleaseValue(strings.TrimPrefix(line, "ID="))
		case strings.HasPrefix(line, "ID_LIKE="):
			raw := normalizeOSReleaseValue(strings.TrimPrefix(line, "ID_LIKE="))
			for _, tok := range strings.Fields(raw) {
				if tok != "" {
					likes = append(likes, tok)
				}
			}
		}
	}
	return id, likes
}

func normalizeOSReleaseValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"'`)
	return strings.ToLower(v)
}

// distroFamilyMap maps a distro ID to its canonical family chain, used when
// /etc/os-release is missing ID_LIKE (some minimal Arch/openSUSE images).
var distroFamilyMap = map[string][]string{
	"ubuntu":     {"debian"},
	"kali":       {"debian"},
	"linuxmint":  {"debian"},
	"mint":       {"debian"},
	"pop":        {"debian"},
	"elementary": {"debian"},
	"zorin":      {"debian"},

	"rocky":     {"rhel", "fedora"},
	"almalinux": {"rhel", "fedora"},
	"ol":        {"rhel", "fedora"},
	"oracle":    {"rhel", "fedora"},
	"centos":    {"rhel", "fedora"},
	"rhel":      {"fedora"},
	"redhat":    {"fedora"},
	"fedora":    {"rhel"},

	"opensuse":            {"suse"},
	"opensuse-leap":       {"suse"},
	"opensuse-tumbleweed": {"suse"},
	"sles":                {"suse"},
	"sled":                {"suse"},

	"manjaro":     {"arch"},
	"endeavouros": {"arch"},
	"artix":       {"arch"},
	"garuda":      {"arch"},
}

func knownFamily(id string) []string {
	return distroFamilyMap[id]
}

// extraDistroTargets are distro-map keys that can genuinely match at runtime
// but are neither family names nor IDs with a distroFamilyMap entry: bare
// distro IDs that are their own family, common aliases, and the "linux"
// fallback DetectDistro returns when /etc/os-release is unreadable.
var extraDistroTargets = []string{
	"debian", "arch", "suse", // real IDs that double as family names
	"archlinux", // alias used for Arch (Vagrant boxes, some os-release forks)
	"linux",     // fallback when /etc/os-release is missing or unparseable
}

// knownDistroTargets returns every target a distro-map key can legitimately
// start with: all known distro IDs and family names. A key outside this set
// can never match DetectDistroFamily's chain, so it would silently
// distro-skip its check on every system.
func knownDistroTargets() map[string]bool {
	targets := make(map[string]bool, len(distroFamilyMap)+len(extraDistroTargets))
	for id, families := range distroFamilyMap {
		targets[id] = true
		for _, fam := range families {
			targets[fam] = true
		}
	}
	for _, t := range extraDistroTargets {
		targets[t] = true
	}
	return targets
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}
