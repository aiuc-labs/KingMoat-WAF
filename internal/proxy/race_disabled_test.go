//go:build !race

package proxy

// raceDetectorEnabled reports whether the test binary was built with -race.
const raceDetectorEnabled = false
