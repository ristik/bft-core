// Package b1authority holds an opaque capability bound by q3active to its own
// verified history and durable installation gate. Its constructor is internal
// and restricted to q3active by the importer test; consumers cannot supply an
// authority callback. Keeping this type below q3active avoids a storage/Engine
// dependency cycle.
package b1authority

import "github.com/unicitynetwork/bft-core/q3format"

type Source struct {
	history func(uint64) (*q3format.History, error)
}

// Bind is called only by q3active.Runtime.B1Authority.
func Bind(history func(uint64) (*q3format.History, error)) *Source {
	return &Source{history: history}
}

func (s *Source) B1History(origin uint64) (*q3format.History, error) {
	if s == nil || s.history == nil {
		return nil, q3format.ErrHistory
	}
	return s.history(origin)
}
