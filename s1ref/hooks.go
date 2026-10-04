package s1ref

// Test instrumentation. Neither hook is set outside tests, and neither changes
// behaviour unless a test installs it.

// onWork, when set, is called with "hash", "point" or "signature" immediately
// before each such operation, so tests can prove no expensive work precedes the full
// gas reservation.
var onWork func(kind string)

func work(kind string) {
	if onWork != nil {
		onWork(kind)
	}
}

// skipFn, when set, disables the named semantic check. The self-test disables
// each check in turn and requires a vector expecting its reason to notice.
var skipFn func(name string) bool

func skipped(name string) bool { return skipFn != nil && skipFn(name) }
