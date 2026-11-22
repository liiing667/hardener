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
	Extra        map[string]interface{}
	// DryRun lists the fix each failing check would get instead of running it.
	DryRun bool

	// Run evidence published by RunSuitesObserved. Generation changes on
	// every observed run, even when the caller reuses the same context.
	// EventCursor is the last event committed by that run.
	Generation   string
	GenerationID string
	SourceGeneration string
	GenerationSource string
	GenerationSeq uint64
	EventCursor  uint64
	Cursor       uint64
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
