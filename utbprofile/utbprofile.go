// Package utbprofile is the start-up (and lane preflight) check of the signed trust-base entry profile: a node of the profile starts from a fresh
// deployment whose pinned genesis, configuration and databases agree, and refuses everything else with a named reason instead of running a mixed or
// half-migrated deployment.
package utbprofile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Role is the kind of node.
type Role string

const (
	Root  Role = "root"
	Shard Role = "shard"
)

// ErrRefused wraps every refusal; the message lists each finding.
var ErrRefused = errors.New("the signed trust-base entry profile cannot start")

// Inputs is what the check looks at. Paths are the resolved file locations the node would open.
type Inputs struct {
	Role Role
	// the profile flags as given
	GenesisFile, GenesisID string
	// EntriesDB is the node's store of finalized entries (where it is or would be).
	EntriesDB string
	// LegacyDBs are databases a node without the profile would have created: if any holds data while the entry store does not exist, the deployment
	// predates the profile and has no signed history to continue from.
	LegacyDBs []string
	// Profile2 says the root runs the handoff profile (the entries are produced by handoffs); roots require it.
	Profile2 bool
}

// Enabled reports whether any profile flag was given.
func (in Inputs) Enabled() bool { return in.GenesisFile != "" || in.GenesisID != "" }

// Check returns nil, or an error wrapping ErrRefused that names every finding.
func Check(in Inputs) error {
	var findings []string
	add := func(format string, a ...any) { findings = append(findings, fmt.Sprintf(format, a...)) }
	entries := fileSize(in.EntriesDB)
	if !in.Enabled() {
		if entries > 0 {
			add("%s holds signed trust-base entries but the profile is off (--utb-genesis/--utb-genesis-id not given): a node would continue a UTB chain as a plain one", in.EntriesDB)
		}
	} else {
		if in.GenesisFile == "" || in.GenesisID == "" {
			add("--utb-genesis and --utb-genesis-id go together: the genesis entry is authenticated by its pin, and a pin names nothing without the entry")
		}
		if in.Role == Root && !in.Profile2 {
			add("a root of the profile runs profile 2 (--profile-2): the entries are produced by its handoffs")
		}
		if in.GenesisFile != "" {
			if fi, err := os.Stat(in.GenesisFile); err != nil || fi.IsDir() || fi.Size() == 0 {
				add("the genesis entry file %q is missing or empty", in.GenesisFile)
			}
		}
		if in.EntriesDB != "" {
			if err := writable(filepath.Dir(in.EntriesDB)); err != nil {
				add("the entry store cannot be persisted at %q: %v", in.EntriesDB, err)
			}
		}
		if entries == 0 {
			for _, db := range in.LegacyDBs {
				if fileSize(db) > 0 {
					add("%s is a database of a deployment without the profile and %s does not exist: the profile starts from a fresh deployment, there is no approved migration", db, in.EntriesDB)
				}
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return fmt.Errorf("%w (%s): %s", ErrRefused, in.Role, strings.Join(findings, "; "))
}

func fileSize(path string) int64 {
	if path == "" {
		return 0
	}
	fi, err := os.Stat(path)
	if err != nil || fi.IsDir() {
		return 0
	}
	return fi.Size()
}

func writable(dir string) error {
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".utb-writable-*")
	if err != nil {
		return err
	}
	name := f.Name()
	_ = f.Close()
	return os.Remove(name)
}
