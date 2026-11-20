//go:build !race

package analyzer

// raceDetector reports that the tests run with the race detector; see
// race_on_test.go.
const raceDetector = false
