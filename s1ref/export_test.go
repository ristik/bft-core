package s1ref

// SetWorkHook installs the work instrumentation hook (nil removes it).
func SetWorkHook(f func(kind string)) { onWork = f }

// SetSkip installs the check-disabling hook (nil removes it).
func SetSkip(f func(name string) bool) { skipFn = f }
