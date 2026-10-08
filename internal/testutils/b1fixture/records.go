package b1fixture

import (
	"context"
	"errors"

	"github.com/unicitynetwork/bft-core/rootrecords"
)

// EmptyRecords is a root-record source whose log is empty: the mandatory import of every block is the empty batch at a constant UC time.
type EmptyRecords struct{ UCTime uint64 }

func (EmptyRecords) Record(uint64) (rootrecords.Record, error) {
	return rootrecords.Record{}, errors.New("the source log is empty")
}

func (e EmptyRecords) Cursor(context.Context, uint64) (rootrecords.Cursor, error) {
	return rootrecords.Cursor{UCTime: e.UCTime}, nil
}
