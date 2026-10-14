// Package b1authority holds an opaque capability bound by q3active to its own
// verified history and durable installation gate. Its constructor is internal
// and restricted to q3active by the importer test; consumers cannot supply an
// authority callback. Keeping this type below q3active avoids a storage/Engine
// dependency cycle.
package b1authority

import (
	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-core/q3format"
)

type Source struct {
	history func(uint64) (*q3format.History, error)
	run     func(origin, from uint64, limit int) (*q3format.History, []b1state.Entry, error)
}

// Bind is called only by q3active.Runtime.B1Authority.
func Bind(history func(uint64) (*q3format.History, error), run func(origin, from uint64, limit int) (*q3format.History, []b1state.Entry, error)) *Source {
	return &Source{history: history, run: run}
}

// B1Run is the per-block capability: the authenticated history together with the admitted entries of epochs from.. up to the one holding origin, at most
// limit of them (0: no cap). Only that run is gated and converted, so the cost is independent of the epochs before from, which were admitted when they were
// imported. B1History (the whole prefix) remains for bootstrap, recovery and audits.
func (s *Source) B1Run(origin, from uint64, limit int) (*q3format.History, []b1state.Entry, error) {
	if s == nil || s.run == nil {
		return nil, nil, q3format.ErrHistory
	}
	return s.run(origin, from, limit)
}

func (s *Source) B1History(origin uint64) (*q3format.History, error) {
	if s == nil || s.history == nil {
		return nil, q3format.ErrHistory
	}
	return s.history(origin)
}
