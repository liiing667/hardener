package config

type ExecContext struct {
	RunID         string
	BaseDir       string
	SecurityLevel string
	OSName        string
	ArchName      string
	DistroName    string
	// DistroFamily is the ordered chain [ID, ID_LIKE...] used to resolve
	// distro overrides in rulesets (e.g. ["ubuntu", "debian"]).
	DistroFamily []string
	Profile      string
	Labels       []string
	Timestamp    string
	// RulesetSource and RulesetVersion identify the ruleset snapshot
	// admitted for this run: where it was loaded from and its content hash.
	// Both stay empty when no ruleset was loaded (e.g. a rollback run).
	RulesetSource  string
	RulesetVersion string
	Extra          map[string]interface{}
	// DryRun lists the fix each failing check would get instead of running it.
	DryRun bool
}

// Create a new context
func NewExecContext(runID, baseDir string) *ExecContext {
	return &ExecContext{
		RunID:   runID,
		BaseDir: baseDir,
		Extra:   make(map[string]interface{}),
	}
}

// Add or update a value
func (c *ExecContext) Set(key string, value interface{}) {
	c.Extra[key] = value
}

// Get a value (type-assert when reading)
func (c *ExecContext) Get(key string) (interface{}, bool) {
	v, ok := c.Extra[key]
	return v, ok
}
