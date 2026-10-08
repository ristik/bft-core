//go:build race

package leader

// raceEnabled is true under the race detector, whose slowdown (several times) makes a wall-clock budget meaningless.
const raceEnabled = true
