package rootrecords

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
)

var (
	// ErrClockLineage reports a certificate that is not on the lineage already imported: another network, an earlier epoch or round, or a
	// repeat of a round with a different time.
	ErrClockLineage = errors.New("rootrecords: UC time import is off the imported root lineage")
	// ErrClockRegress reports a UC time that is zero or below the last imported time.
	ErrClockRegress = errors.New("rootrecords: UC time regressed")
)

// Clock imports UC time: the timestamp of the quorum-approved unicity seal of a verified root certificate, read from the same
// RootOrigin the executed block binds (no EVM timestamp, no operator-supplied time). Imports must stay on one lineage and the time may
// not decrease. The seal timestamp is quorum-approved wall-clock time, bounded by root consensus (monotonic, voter clock skew:
// ristik/bft-core#445); the import keeps it monotonic on one lineage as well, which is what custody and the registry rely on.
type Clock struct {
	started             bool
	network, epoch, rnd uint64
	time                uint64
}

// Time is the last imported UC time in seconds, zero before any import.
func (c *Clock) Time() uint64 { return c.time }

// Import advances the clock to the origin's seal. Re-importing the same (epoch, round) with the same time is a no-op.
func (c *Clock) Import(o evmroot.RootOrigin) error {
	if o.ReferenceTime == 0 {
		return fmt.Errorf("%w: zero time", ErrClockRegress)
	}
	if !c.started {
		c.started, c.network, c.epoch, c.rnd, c.time = true, o.NetworkID, o.RootEpoch, o.RootRound, o.ReferenceTime
		return nil
	}
	switch {
	case o.NetworkID != c.network:
		return fmt.Errorf("%w: network %d, lineage is %d", ErrClockLineage, o.NetworkID, c.network)
	case o.RootEpoch < c.epoch, o.RootEpoch == c.epoch && o.RootRound < c.rnd:
		return fmt.Errorf("%w: (%d,%d) is before (%d,%d)", ErrClockLineage, o.RootEpoch, o.RootRound, c.epoch, c.rnd)
	case o.RootEpoch == c.epoch && o.RootRound == c.rnd && o.ReferenceTime != c.time:
		return fmt.Errorf("%w: round (%d,%d) re-imported with another time", ErrClockLineage, o.RootEpoch, o.RootRound)
	case o.ReferenceTime < c.time:
		return fmt.Errorf("%w: %d after %d", ErrClockRegress, o.ReferenceTime, c.time)
	}
	c.epoch, c.rnd, c.time = o.RootEpoch, o.RootRound, o.ReferenceTime
	return nil
}
