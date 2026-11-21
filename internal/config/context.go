package config

import "time"

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

	// Generation is the opaque identity of the immutable host/precondition
	// generation accepted for the current run. HostGeneration is the backing
	// snapshot. RunSuitesObserved starts a new generation for every invocation;
	// a retry therefore never appends checks to an older score.
	Generation     string
	HostGeneration *HostGeneration
	// Snapshot is the same pointer as HostGeneration, kept as a descriptive
	// alias for consumers that treat the admission state as a run snapshot.
	Snapshot *HostGeneration
	// The fields below mirror Generation for consumers that only need the
	// report/evidence identity. They are optional and empty for a context that
	// has not admitted a run yet.
	GenerationID       string
	RunGeneration      string
	GenerationSource   string
	PreconditionSource string
	GenerationStarted  time.Time
	CheckSetHash       string
	HostHash           string
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

// BeginGeneration freezes the host state used to admit the supplied suites.
// Each call creates a new generation, even when the host state is unchanged,
// so a retry cannot be mistaken for the previous run.
func (c *ExecContext) BeginGeneration(suites ...TestSuite) *HostGeneration {
	generation := NewHostGeneration(c, suites)
	c.HostGeneration = generation
	c.Snapshot = generation
	c.Generation = generation.ID
	c.GenerationID = generation.ID
	c.RunGeneration = generation.ID
	c.GenerationSource = generation.Source
	c.PreconditionSource = generation.Source
	c.GenerationStarted = generation.CapturedAt
	c.CheckSetHash = generation.CheckSetHash
	c.HostHash = generation.HostHash
	return generation
}

// EnsureGeneration returns the generation already accepted by this context,
// or creates one when a caller invokes a check-specific entry point directly.
// Run-level callers must use BeginGeneration so every retry is a new
// generation.
func (c *ExecContext) EnsureGeneration(suites ...TestSuite) *HostGeneration {
	if c.HostGeneration != nil {
		c.HostGeneration.ObserveSuites(suites)
		c.CheckSetHash = c.HostGeneration.CheckSetHash
		c.HostHash = c.HostGeneration.HostHash
		return c.HostGeneration
	}
	return c.BeginGeneration(suites...)
}

// FrozenGeneration exposes the accepted generation without creating another
// one. It returns nil when admission has not happened yet.
func (c *ExecContext) FrozenGeneration() *HostGeneration {
	return c.HostGeneration
}

// GenerationSnapshot is an alias for FrozenGeneration.
func (c *ExecContext) GenerationSnapshot() *HostGeneration {
	return c.FrozenGeneration()
}
