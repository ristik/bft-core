//go:build !linux

package seed

// retainMove exists so tests compile everywhere; off Linux there is no descriptor-relative retention.
var retainMove = func(stagefd int, stageName string, vfd int, name string) error { return nil }

// retainOldVersion: without the descriptor-relative primitives (renameat, unlinkat, fstatat) retention is refused, never done racily; the caller keeps
// the old version at the stage path. (Off Linux there is no atomic exchange either, so a replacement is refused before this point.)
func retainOldVersion(stage, dir string) error {
	return refuse("retaining a replaced version is not supported on this system")
}

func gcOldVersions(vd, keep string) {}
