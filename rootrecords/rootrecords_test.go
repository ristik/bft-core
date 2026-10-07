package rootrecords

import (
	"encoding/binary"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
)

func id32(b byte) (a [32]byte) {
	for i := range a {
		a[i] = b
	}
	return
}

func origin(epoch, round, t uint64) evmroot.RootOrigin {
	return evmroot.RootOrigin{NetworkID: 3, RootEpoch: epoch, RootRound: round, ReferenceTime: t}
}

func newProj(t *testing.T) *Projector {
	t.Helper()
	p := NewProjector(1, 1)
	require.NoError(t, p.Import(origin(1, 10, 1_000)))
	return p
}

func payloadWord(r Record, i int) uint64 { return binary.BigEndian.Uint64(r.Data[32*i+24 : 32*i+32]) }

// ---- progress ----

func TestProgressGenesisOffsetZeroAndSkippedRoundsCount(t *testing.T) {
	tr := NewGenesis(1, 5)
	require.Equal(t, uint64(0), tr.Progress())
	p, err := tr.At(1, 5)
	require.NoError(t, err)
	require.Zero(t, p)
	p, err = tr.At(1, 105) // 100 skipped rounds are 100 progress
	require.NoError(t, err)
	require.Equal(t, uint64(100), p)
	require.NoError(t, tr.Observe(1, 9))
	require.Equal(t, uint64(4), tr.Progress())
}

func TestProgressRefusesRoundsOutsideTheFunction(t *testing.T) {
	tr := NewGenesis(1, 5)
	_, err := tr.At(1, 4)
	require.ErrorIs(t, err, ErrProgress)
	_, err = tr.At(2, 9)
	require.ErrorIs(t, err, ErrProgress)
	require.NoError(t, tr.Observe(1, 8))
	require.ErrorIs(t, tr.Observe(1, 7), ErrProgress) // regress
	require.ErrorIs(t, tr.Observe(2, 9), ErrProgress) // other epoch before H
}

func TestProgressFreezesAtHAndSuffixRoundsDoNotMoveIt(t *testing.T) {
	tr := NewGenesis(1, 1)
	require.NoError(t, tr.Observe(1, 6))
	off, err := tr.OrderH(8, 2, 20) // p(1,8) = 7, successor offset 8
	require.NoError(t, err)
	require.Equal(t, uint64(8), off)
	require.Equal(t, uint64(7), tr.Progress())
	require.True(t, tr.Frozen())
	// an arbitrarily high old-epoch suffix round is refused and changes nothing
	require.ErrorIs(t, tr.Observe(1, 1_000_000), ErrProgress)
	require.Equal(t, uint64(7), tr.Progress())
	// a successor round before its first round is refused
	require.ErrorIs(t, tr.Observe(2, 19), ErrProgress)
	require.Equal(t, uint64(7), tr.Progress())
	// the first successor ordinary round ends the freeze: offset + (r - first)
	require.NoError(t, tr.Observe(2, 23))
	require.False(t, tr.Frozen())
	require.Equal(t, uint64(11), tr.Progress())
}

func TestOrderHRefusals(t *testing.T) {
	tr := NewGenesis(1, 4)
	require.NoError(t, tr.Observe(1, 9))
	_, err := tr.OrderH(8, 2, 1) // below observed
	require.ErrorIs(t, err, ErrProgress)
	_, err = tr.OrderH(9, 1, 1) // successor epoch not later
	require.ErrorIs(t, err, ErrProgress)
	_, err = tr.OrderH(9, 2, 0) // no first round
	require.ErrorIs(t, err, ErrProgress)
	_, err = tr.OrderH(3, 2, 1) // before the epoch's first round (and below observed)
	require.ErrorIs(t, err, ErrProgress)
	_, err = tr.OrderH(9, 2, 1)
	require.NoError(t, err)
	_, err = tr.OrderH(9, 3, 1) // H twice
	require.ErrorIs(t, err, ErrProgress)
}

// ---- log ----

func TestRecordIDMatchesAbiEncode(t *testing.T) {
	u64, _ := abi.NewType("uint64", "", nil)
	b32, _ := abi.NewType("bytes32", "", nil)
	u8, _ := abi.NewType("uint8", "", nil)
	byt, _ := abi.NewType("bytes", "", nil)
	args := abi.Arguments{{Type: u64}, {Type: b32}, {Type: u8}, {Type: u64}, {Type: u64}, {Type: byt}}
	data := make([]byte, 128)
	data[5] = 9
	pred := id32(0x77)
	enc, err := args.Pack(uint64(3), pred, uint8(KindAck), uint64(11), uint64(1_700_000_000), data)
	require.NoError(t, err)
	want := ethcrypto.Keccak256(enc)
	got := RecordID(3, pred, KindAck, 11, 1_700_000_000, data)
	require.Equal(t, want, got[:])
	// full-width numbers and payloads that are not a whole number of words
	for _, n := range []int{0, 31, 33} {
		d := make([]byte, n)
		enc, err := args.Pack(uint64(1<<63+5), pred, uint8(KindClosure), uint64(1<<62+1), uint64(1<<57), d)
		require.NoError(t, err)
		g := RecordID(1<<63+5, pred, KindClosure, 1<<62+1, 1<<57, d)
		require.Equal(t, ethcrypto.Keccak256(enc), g[:], "len %d", n)
	}
}

func TestLogLinksAndVerifies(t *testing.T) {
	p := newProj(t)
	_, err := p.SessionClosed(id32(1))
	require.NoError(t, err)
	_, err = p.Retire(7, 1, id32(2))
	require.NoError(t, err)
	recs := p.Log.Records()
	require.Len(t, recs, 2)
	require.Equal(t, recs[0].ID, recs[1].Predecessor)
	require.NoError(t, Verify(recs))
}

func rebuilt(r Record) Record {
	r.ID = RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
	return r
}

func TestVerifyIsolatedRefusals(t *testing.T) {
	p := newProj(t)
	for i := byte(1); i <= 3; i++ {
		_, err := p.SessionClosed(id32(i))
		require.NoError(t, err)
	}
	good := p.Log.Records()
	mut := func(f func(rs []Record)) []Record { rs := append([]Record(nil), good...); f(rs); return rs }

	cases := []struct {
		name string
		recs []Record
		want error
	}{
		{"index", mut(func(rs []Record) { rs[1].Index = 2; rs[1] = rebuilt(rs[1]) }), ErrIndex},
		{"predecessor", mut(func(rs []Record) { rs[1].Predecessor = id32(9); rs[1] = rebuilt(rs[1]) }), ErrPredecessor},
		{"first predecessor", mut(func(rs []Record) { rs[0].Predecessor = id32(9); rs[0] = rebuilt(rs[0]) }), ErrPredecessor},
		{"id", mut(func(rs []Record) { rs[2].ID = id32(5) }), ErrRecordID},
		{"progress retagged", mut(func(rs []Record) { rs[2].Progress += 1 }), ErrRecordID},
		{"data tampered", mut(func(rs []Record) { rs[2].Data = append([]byte(nil), rs[2].Data...); rs[2].Data[31] ^= 1 }), ErrRecordID},
		{"payload width", mut(func(rs []Record) { rs[2].Data = rs[2].Data[:31]; rs[2] = rebuilt(rs[2]) }), ErrPayload},
		{"kind", mut(func(rs []Record) { rs[2].Kind = Kind(9); rs[2] = rebuilt(rs[2]) }), ErrKind},
		{"time backwards", mut(func(rs []Record) { rs[2].UCTime = rs[1].UCTime - 1; rs[2] = rebuilt(rs[2]) }), ErrMonotonic},
	}
	require.NoError(t, Verify(good))
	for _, c := range cases {
		require.ErrorIs(t, Verify(c.recs), c.want, c.name)
	}
	// progress backwards, isolated from time (needs a record above progress zero)
	hi := mut(func(rs []Record) {
		rs[1].Progress = 5
		rs[1] = rebuilt(rs[1])
		rs[2].Predecessor = rs[1].ID
		rs[2].Progress = 4
		rs[2] = rebuilt(rs[2])
	})
	require.ErrorIs(t, Verify(hi), ErrMonotonic)
}

func TestAppendRefusals(t *testing.T) {
	var l Log
	_, err := l.Append(Kind(0), nil, Anchor{1, 1})
	require.ErrorIs(t, err, ErrKind)
	_, err = l.Append(KindAck, make([]byte, 96), Anchor{1, 1})
	require.ErrorIs(t, err, ErrPayload)
	_, err = l.Append(KindSessionClosed, make([]byte, 32), Anchor{5, 50})
	require.NoError(t, err)
	_, err = l.Append(KindSessionClosed, make([]byte, 32), Anchor{4, 50})
	require.ErrorIs(t, err, ErrMonotonic)
	_, err = l.Append(KindSessionClosed, make([]byte, 32), Anchor{5, 49})
	require.ErrorIs(t, err, ErrMonotonic)
	require.Equal(t, uint64(1), l.Len())
}

// ---- UC time ----

func TestClockImport(t *testing.T) {
	var c Clock
	require.NoError(t, c.Import(origin(1, 10, 1_000)))
	require.NoError(t, c.Import(origin(1, 10, 1_000))) // duplicate certificate of the same statement
	require.NoError(t, c.Import(origin(1, 11, 1_000))) // equal time is not a regress
	require.NoError(t, c.Import(origin(2, 3, 1_005)))  // a later epoch may restart its round
	require.Equal(t, uint64(1_005), c.Time())
}

func TestClockRefusals(t *testing.T) {
	base := func() *Clock { var c Clock; require.NoError(t, c.Import(origin(2, 10, 1_000))); return &c }
	require.ErrorIs(t, base().Import(origin(2, 11, 999)), ErrClockRegress)
	require.ErrorIs(t, base().Import(origin(2, 11, 0)), ErrClockRegress)
	require.ErrorIs(t, base().Import(origin(2, 9, 1_001)), ErrClockLineage)
	require.ErrorIs(t, base().Import(origin(1, 99, 1_001)), ErrClockLineage)
	require.ErrorIs(t, base().Import(origin(2, 10, 1_001)), ErrClockLineage)
	other := origin(2, 11, 1_001)
	other.NetworkID = 4
	require.ErrorIs(t, base().Import(other), ErrClockLineage)
	c := base()
	_ = c.Import(origin(2, 11, 999))
	require.Equal(t, uint64(1_000), c.Time()) // a refused import leaves the clock
}

// ---- projector ----

func TestRecordNeedsUCTime(t *testing.T) {
	p := NewProjector(1, 1)
	_, err := p.SessionClosed(id32(1))
	require.ErrorIs(t, err, ErrNoUCTime)
	require.Zero(t, p.Log.Len())
}

func TestAckDerivesTheOffset(t *testing.T) {
	p := newProj(t)
	require.NoError(t, p.Tracker.Observe(1, 6))
	r, err := p.Ack(id32(1), 8, 2, 20)
	require.NoError(t, err)
	require.Equal(t, KindAck, r.Kind)
	require.Equal(t, uint64(8), payloadWord(r, 1))  // replaced H round
	require.Equal(t, uint64(8), payloadWord(r, 2))  // offset = p(1,8)+1 = 7+1
	require.Equal(t, uint64(20), payloadWord(r, 3)) // first round
	require.Equal(t, uint64(7), r.Progress)         // the record is anchored at H's endpoint
	require.Equal(t, uint64(1_000), r.UCTime)
}

func TestAckFailureLeavesNoTrace(t *testing.T) {
	p := NewProjector(1, 1)
	_, err := p.Ack(id32(1), 8, 2, 20) // no UC time: the append refuses after OrderH
	require.ErrorIs(t, err, ErrNoUCTime)
	require.False(t, p.Tracker.Frozen())
	require.NoError(t, p.Import(origin(1, 10, 1_000)))
	_, err = p.Ack(id32(1), 8, 2, 20)
	require.NoError(t, err)
}

func TestRecoveryAckDerivesBothOffsets(t *testing.T) {
	p := newProj(t)
	require.NoError(t, p.Tracker.Observe(1, 6))
	// H of the incumbent at round 8 (p=7): J offset 8, first 20; K's H at J round 25 (p=8+5=13): K offset 14, first 40.
	r, err := p.RecoveryAck(id32(1), id32(2), 8, 2, 20, 25, 3, 40, 9)
	require.NoError(t, err)
	require.Equal(t, KindRecoveryAck, r.Kind)
	want := []uint64{0, 0, 8, 20, 25, 14, 40, 3, 9}
	for i := 2; i < 9; i++ {
		require.Equal(t, want[i], payloadWord(r, i), "word %d", i)
	}
	require.Equal(t, uint64(13), r.Progress)
	require.True(t, p.Tracker.Frozen())
	require.NoError(t, p.Tracker.Observe(3, 41))
	require.Equal(t, uint64(15), p.Tracker.Progress())
}

func TestRecoveryAckRefusalsRestoreTheTracker(t *testing.T) {
	p := newProj(t)
	_, err := p.RecoveryAck(id32(1), id32(2), 8, 2, 20, 19, 3, 40, 9) // K's H before J's first round
	require.ErrorIs(t, err, ErrProgress)
	require.False(t, p.Tracker.Frozen())
	require.Zero(t, p.Log.Len())
	_, err = p.RecoveryAck(id32(1), id32(2), 8, 2, 20, 25, 2, 40, 9) // K epoch not after J's
	require.ErrorIs(t, err, ErrProgress)
	require.False(t, p.Tracker.Frozen())
	require.Equal(t, uint64(1), p.Tracker.cur.epoch)
}

func closureProjector(t *testing.T) (*Projector, ClosureKey) {
	p := newProj(t)
	_, err := p.Ack(id32(1), 8, 2, 20)
	require.NoError(t, err)
	require.NoError(t, p.Tracker.Observe(2, 24))
	require.NoError(t, p.Import(origin(1, 11, 1_100)))
	return p, ClosureKey{Epoch: 1, HRecordID: id32(0xab), HRound: 8}
}

func TestClosureFirstFixesTheAnchorAndRepeatsAreNoOps(t *testing.T) {
	p, k := closureProjector(t)
	c := Closure{id32(1), id32(2), id32(3), id32(4)}
	_, open := p.Closed(k)
	require.False(t, open)
	at, first, err := p.Close(k, c)
	require.NoError(t, err)
	require.True(t, first)
	require.Equal(t, Anchor{Progress: 12, UCTime: 1_100}, at)
	n := p.Log.Len()
	// later progress and time, a repeat proof of the same closure
	require.NoError(t, p.Tracker.Observe(2, 90))
	require.NoError(t, p.Import(origin(1, 12, 9_999)))
	at2, first2, err := p.Close(k, c)
	require.NoError(t, err)
	require.False(t, first2)
	require.Equal(t, at, at2)
	require.Equal(t, n, p.Log.Len())
	got, ok := p.Closed(k)
	require.True(t, ok)
	require.Equal(t, at, got)
}

func TestClosureIsOncePerEpoch(t *testing.T) {
	p, k := closureProjector(t)
	c := Closure{id32(1), id32(2), id32(3), id32(4)}
	_, _, err := p.Close(k, c)
	require.NoError(t, err)
	// the same epoch with another H record or another H round is another closure of a closed epoch
	for _, other := range []ClosureKey{{k.Epoch, id32(0xcd), k.HRound}, {k.Epoch, k.HRecordID, 9}} {
		_, _, err := p.Close(other, c)
		require.ErrorIs(t, err, ErrClosureConflict)
		_, open := p.Closed(other)
		require.False(t, open, "the refused key is not closed")
	}
	// an earlier epoch is its own closure
	_, first, err := p.Close(ClosureKey{0, k.HRecordID, k.HRound}, c)
	require.NoError(t, err)
	require.True(t, first)
}

func TestCloseBeforeAnyHIsRefused(t *testing.T) {
	p := newProj(t) // genesis: no H, no successor, the log and closure map are empty
	_, _, err := p.Close(ClosureKey{1, id32(0xab), 8}, Closure{id32(1), id32(2), id32(3), id32(4)})
	require.ErrorIs(t, err, ErrClosureEarly)
	require.Zero(t, p.Log.Len())
	_, open := p.Closed(ClosureKey{1, id32(0xab), 8})
	require.False(t, open)
	// the current epoch can never be the closed one, even with ordinary progress
	require.NoError(t, p.Tracker.Observe(1, 40))
	_, _, err = p.Close(ClosureKey{1, id32(0xab), 8}, Closure{})
	require.ErrorIs(t, err, ErrClosureEarly)
}

func TestReviewLogReturnedDataIsIndependent(t *testing.T) {
	flip := func(r Record) { r.Data[0] ^= 1 }
	t.Run("Append", func(t *testing.T) {
		var l Log
		r, err := l.Append(KindSessionClosed, make([]byte, 32), Anchor{1, 1})
		require.NoError(t, err)
		flip(r)
		require.NoError(t, Verify(l.Records()))
	})
	t.Run("At", func(t *testing.T) {
		var l Log
		_, err := l.Append(KindSessionClosed, make([]byte, 32), Anchor{1, 1})
		require.NoError(t, err)
		r, _ := l.At(0)
		flip(r)
		require.NoError(t, Verify(l.Records()))
	})
	t.Run("Records", func(t *testing.T) {
		var l Log
		_, err := l.Append(KindSessionClosed, make([]byte, 32), Anchor{1, 1})
		require.NoError(t, err)
		flip(l.Records()[0])
		require.NoError(t, Verify(l.Records()))
	})
	t.Run("the appended input", func(t *testing.T) {
		var l Log
		data := make([]byte, 32)
		_, err := l.Append(KindSessionClosed, data, Anchor{1, 1})
		require.NoError(t, err)
		data[0] ^= 1
		require.NoError(t, Verify(l.Records()))
	})
}

func TestProgressOverflowIsRefusedAndLeavesState(t *testing.T) {
	const max = ^uint64(0)
	t.Run("the successor offset", func(t *testing.T) {
		tr := NewGenesis(1, 1)
		_, err := tr.OrderH(max, 2, 1) // p(1,max) = max-1, the offset is max: fine
		require.NoError(t, err)
		require.NoError(t, tr.Observe(2, 1)) // progress max
		require.Equal(t, max, tr.Progress())
		require.ErrorIs(t, tr.Observe(2, 2), ErrProgress) // would wrap to zero
		require.Equal(t, max, tr.Progress())
	})
	t.Run("p plus one", func(t *testing.T) {
		tr := NewGenesis(1, 0)
		before := *tr
		_, err := tr.OrderH(max, 2, 1) // p(1,max) = max: the offset max+1 does not exist
		require.ErrorIs(t, err, ErrProgress)
		require.Equal(t, before, *tr)
	})
	t.Run("an ordinary round", func(t *testing.T) {
		tr := NewGenesis(1, 0)
		require.NoError(t, tr.Observe(1, max))
		require.Equal(t, max, tr.Progress())
		tr = NewGenesis(1, 1)
		_, err := tr.OrderH(max, 2, 1)
		require.NoError(t, err)
		before := *tr
		require.NoError(t, tr.Observe(2, 1))
		require.NotEqual(t, before, *tr)
	})
}
func TestClosureConflict(t *testing.T) {
	p, k := closureProjector(t)
	c := Closure{id32(1), id32(2), id32(3), id32(4)}
	_, _, err := p.Close(k, c)
	require.NoError(t, err)
	for i := 0; i < 4; i++ {
		d := c
		switch i {
		case 0:
			d.AssignmentID = id32(9)
		case 1:
			d.TerminalRoot = id32(9)
		case 2:
			d.ExposureDigest = id32(9)
		case 3:
			d.KeyHistoryDigest = id32(9)
		}
		_, _, err = p.Close(k, d)
		require.ErrorIs(t, err, ErrClosureConflict, "field %d", i)
	}
}

func TestClosureBeforeSuccessorProgress(t *testing.T) {
	p := newProj(t)
	_, err := p.Ack(id32(1), 8, 2, 20)
	require.NoError(t, err)
	_, _, err = p.Close(ClosureKey{1, id32(1), 8}, Closure{})
	require.ErrorIs(t, err, ErrClosureEarly)
	require.Equal(t, uint64(1), p.Log.Len())
}

func TestObserveBoundariesAndLogAt(t *testing.T) {
	tr := NewGenesis(1, 1)
	require.NoError(t, tr.Observe(1, 5))
	require.NoError(t, tr.Observe(1, 5)) // the same round again is not a regress
	_, err := tr.OrderH(5, 2, 20)
	require.NoError(t, err)
	require.NoError(t, tr.Observe(2, 20)) // exactly the successor's first round
	require.Equal(t, uint64(5), tr.Progress())

	var l Log
	_, ok := l.At(0)
	require.False(t, ok)
	_, err = l.Append(KindSessionClosed, make([]byte, 32), Anchor{1, 1})
	require.NoError(t, err)
	_, ok = l.At(0)
	require.True(t, ok)
	_, ok = l.At(1)
	require.False(t, ok)
}
