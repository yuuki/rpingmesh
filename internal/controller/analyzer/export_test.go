package analyzer

// RetainedWindows returns the number of distinct windows currently retained in
// the ring. Test-only: production code never inspects the ring.
func (a *Analyzer) RetainedWindows() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.ring)
}

// RetainedSummaries returns the total number of PathSummary records currently
// held across all retained windows. Test-only.
func (a *Analyzer) RetainedSummaries() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, b := range a.ring {
		n += len(b.summaries)
	}
	return n
}
