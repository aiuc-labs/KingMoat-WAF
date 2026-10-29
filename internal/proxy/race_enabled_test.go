//go:build race

package proxy

// raceDetectorEnabled reports whether the test binary was built with -race.
// Timing assertions are not meaningful under the detector: it serialises
// memory accesses and the CRS engine runs an order of magnitude slower, so a
// CPU-bound budget that holds in a normal build blows up purely from the
// instrumentation.
const raceDetectorEnabled = true
