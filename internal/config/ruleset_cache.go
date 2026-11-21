package config

import "sync"

// RulesetCache admits one ruleset snapshot at a time and is the only place a
// "hot" reload may happen. Reload swaps the admitted snapshot only after the
// replacement loaded completely and successfully; a failed reload keeps the
// previously admitted snapshot. A run therefore always sees one whole
// ruleset version — never a mix of the old and new check sets, and never a
// partial set left behind by a failed load.
//
// The zero value is ready to use.
type RulesetCache struct {
	mu      sync.RWMutex
	current RulesetSnapshot
	loaded  bool
}

// NewRulesetCache returns an empty cache.
func NewRulesetCache() *RulesetCache {
	return &RulesetCache{}
}

// Admit freezes snap as the ruleset for upcoming runs.
func (c *RulesetCache) Admit(snap RulesetSnapshot) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.current = snap
	c.loaded = true
}

// Current returns the admitted snapshot and whether one was ever admitted.
func (c *RulesetCache) Current() (RulesetSnapshot, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current, c.loaded
}

// Reload loads a replacement snapshot and admits it atomically. When the
// load fails, the previously admitted snapshot (if any) stays admitted and
// is returned together with the error, so a retry continues from the last
// complete ruleset version instead of a partial or mixed one.
func (c *RulesetCache) Reload(load func() (RulesetSnapshot, error)) (RulesetSnapshot, error) {
	snap, err := load()
	if err != nil {
		current, _ := c.Current()
		return current, err
	}
	c.Admit(snap)
	return snap, nil
}
