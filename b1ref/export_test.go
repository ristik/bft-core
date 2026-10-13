package b1ref

// SetWorkHook installs the test instrumentation hook (nil removes it).
func SetWorkHook(f func(kind string)) { onWork = f }
