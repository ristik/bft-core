package monitoring

import (
	"runtime/debug"
)

// RegisterBuildInfo registers unicity_build_info{component,revision,go} = 1.
func RegisterBuildInfo(r *Registry, component string) {
	rev, goVer := "unknown", "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		goVer = bi.GoVersion
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 8 {
				rev = s.Value[:8]
			}
		}
	}
	r.GaugeFunc("unicity_build_info", "Always 1; the labels identify the component and its build.", func() float64 { return 1 }, "component", component, "revision", rev, "go", goVer)
}
