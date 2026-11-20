//go:build race

package analyzer

// raceDetector reports that the tests run with the race detector, which
// makes the simulations several times slower. The simulation tests then run
// fewer scenarios, and the test at the scale of the benchmarks is skipped:
// the locking they exercise is the same at any size.
const raceDetector = true
