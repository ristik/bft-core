package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// budgetServer is a public replica of the plan fixture's chain (n blocks) under budget b and a fake clock.
func budgetServer(t *testing.T, n int, b PublicBudget) (*planFixture, *Server, *fakeClock) {
	t.Helper()
	p := newPlanFixture(t, n)
	p.serve(t, 1, n)
	s, err := NewServer(p.replica, p.f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, s.SetPublicReads(Limits{Deadline: time.Second, Pending: 4, PerPeer: 2}))
	require.NoError(t, s.SetPublicBudget(b))
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s.publicBudget = newPublicBudget(b, clock.now)
	return p, s, clock
}

// chainRead serves one public chain read of count records from block top (zero stop: the anchor is never met) and returns how many
// records it answered, or the error.
func chainRead(t *testing.T, s *Server, id peer.ID, p *planFixture, top, count int) (int, error) {
	t.Helper()
	raw, err := archive.EncodeRequest(archive.Request{Context: p.f.subject, BlockHash: p.hash(top)})
	require.NoError(t, err)
	frame := binary.BigEndian.AppendUint16([]byte{opChain}, uint16(count))
	frame = append(append(frame, make([]byte, 32)...), raw...)
	var out bytes.Buffer
	if err := s.serveFrame(context.Background(), &out, frame, &readMeter{budget: s.publicBudget, id: id}); err != nil {
		return 0, err
	}
	answer, err := readFrame(&out, maxArchiveFrameBytes)
	require.NoError(t, err)
	return int(answer[0]), nil
}

func ample() PublicBudget {
	return PublicBudget{Rate: 1e6, Burst: 1 << 20, GlobalRate: 1e6, GlobalBurst: 1 << 20, ByteRate: 1e12, ByteBurst: 1 << 40,
		GlobalByteRate: 1e12, GlobalByteBurst: 1 << 40, MaxTrackedPeers: 16}
}

// astra's review of #1070 (P2): a public peer repeating maximum-count chain reads is served at its budget's rate, not at the rate it asks.
func TestPublicChainReadsAreServedAtTheBudgetRate(t *testing.T) {
	t.Parallel()
	b := ample()
	b.Rate, b.Burst = 10, 30
	p, s, clock := budgetServer(t, 40, b)
	got, err := chainRead(t, s, "f1", p, 40, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 30, got, "the burst, then a usable prefix")
	_, err = chainRead(t, s, "f1", p, 10, MaxChainRecords)
	require.ErrorIs(t, err, ErrPeerLimit, "a spent budget refuses the next read before any record is read")
	_, err = chainRead(t, s, "f1", p, 10, MaxChainRecords)
	require.ErrorIs(t, err, ErrPeerLimit, "and every repeat")
	clock.advance(time.Second)
	got, err = chainRead(t, s, "f1", p, 10, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 10, got, "one second refills Rate records")
	got, err = chainRead(t, s, "f2", p, 40, 5)
	require.NoError(t, err)
	require.Equal(t, 5, got, "another peer has its own budget")
}

// The global budget is shared by all public readers: new identities do not reset it.
func TestPublicReadsShareAGlobalBudget(t *testing.T) {
	t.Parallel()
	b := ample()
	b.GlobalRate, b.GlobalBurst = 8, 20
	p, s, clock := budgetServer(t, 40, b)
	got, err := chainRead(t, s, "f1", p, 40, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 20, got)
	for _, id := range []peer.ID{"f2", "f3", "f4"} {
		_, err = chainRead(t, s, id, p, 40, MaxChainRecords)
		require.ErrorIs(t, err, ErrPeerLimit, "a fresh identity %s gets nothing while the global budget is spent", id)
	}
	clock.advance(time.Second)
	got, err = chainRead(t, s, "f5", p, 40, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 8, got, "the global rate refills for whoever asks")
}

// A chain read is charged for every record it read, including the one dropped at the byte bound; a byte budget in debt stops the read with
// the prefix and refuses the next until it has refilled.
func TestPublicChainReadsAreChargedForWhatTheyRead(t *testing.T) {
	t.Parallel()
	p, s, clock := budgetServer(t, 12, ample())
	sizes := make([]int, 0, 3)
	for h := 12; h >= 10; h-- {
		q, rec := p.f.record(t, h-1)
		encoded, err := archive.EncodeResponse(archive.Response{Request: q, Outcome: archive.OK, Record: rec})
		require.NoError(t, err)
		sizes = append(sizes, len(encoded))
	}
	// room for two records: the third is read, encoded and dropped
	s.chainBytes = 1 + 4 + sizes[0] + 4 + sizes[1]
	got, err := chainRead(t, s, "f1", p, 12, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 2, got)
	e := s.publicBudget.peers["f1"]
	require.InDelta(t, float64(ample().Burst-3), e.work.tokens, 0.001, "three record reads")
	require.InDelta(t, float64(ample().ByteBurst-(sizes[0]+sizes[1]+sizes[2])), e.bytes.tokens, 1, "three records' bytes, the dropped one included")

	// a byte budget of one record and a bit: the second read takes it into debt, the third is not attempted
	b := ample()
	b.ByteRate, b.ByteBurst = float64(sizes[0]), sizes[0]+10
	p, s, clock = budgetServer(t, 12, b)
	got, err = chainRead(t, s, "f1", p, 12, MaxChainRecords)
	require.NoError(t, err)
	require.Equal(t, 2, got, "the read that took the budget into debt is answered; none after it")
	_, err = chainRead(t, s, "f1", p, 10, MaxChainRecords)
	require.ErrorIs(t, err, ErrPeerLimit, "in debt")
	clock.advance(2 * time.Second)
	got, err = chainRead(t, s, "f1", p, 10, MaxChainRecords)
	require.NoError(t, err)
	require.Positive(t, got, "the debt is paid at the byte rate")
}

// Single reads are charged too, and an authorized peer is not metered.
func TestPublicSingleReadsTakeTheBudgetAndValidatorsDoNot(t *testing.T) {
	t.Parallel()
	b := ample()
	b.Rate, b.Burst = 1, 2
	p, s, _ := budgetServer(t, 4, b)
	raw, err := archive.EncodeRequest(archive.Request{Context: p.f.subject, BlockHash: p.hash(4)})
	require.NoError(t, err)
	read := func(m *readMeter) error {
		var out bytes.Buffer
		return s.serveFrame(context.Background(), &out, append([]byte{2}, raw...), m)
	}
	meter := &readMeter{budget: s.publicBudget, id: "f1"}
	require.NoError(t, read(meter))
	require.NoError(t, read(meter))
	require.ErrorIs(t, read(meter), ErrPeerLimit)
	for i := 0; i < 10; i++ {
		require.NoError(t, read(nil), "an authorized peer's reads are under the validators' limits only")
	}
}

// A depleted peer's entry is never dropped for a new identity (that would reset its budget); a new peer waits until an entry has refilled.
func TestADepletedBudgetEntryIsNeverEvicted(t *testing.T) {
	t.Parallel()
	b := ample()
	b.Rate, b.Burst, b.MaxTrackedPeers = 1, 2, 4
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	budget := newPublicBudget(b, clock.now)
	for _, id := range []peer.ID{"a", "b", "c", "d"} {
		require.True(t, budget.take(id))
		require.True(t, budget.take(id))
		require.False(t, budget.take(id))
	}
	require.False(t, budget.begin("e"), "every entry is depleted: a new peer is refused")
	require.False(t, budget.take("a"), "a is still depleted")
	clock.advance(2 * time.Second)
	require.True(t, budget.begin("e"), "an entry has refilled completely: dropping it gives nobody tokens")
	budget.end("e")
}

// astra's re-check of #1070: an exact-digest read with a wrong digest examined every stored representation of the block (two 1 MiB records
// here) and was charged only its small refusal, so a frozen small byte bucket never ran out. The store now refuses a wrong digest from the
// manifest without reading the records (archive.TestGetExactRejectsAWrongDigestWithoutReadingTheChunks proves that no chunk is read), so
// the refusal's charge is what it cost; a right digest is charged the record it read.
func TestPublicExactReadsOfAWrongDigestDoNotReadTheRecords(t *testing.T) {
	t.Parallel()
	q, rec := transportFixture()
	rec.Body = bytes.Repeat([]byte{0xc0}, 1<<20)
	variant := *rec
	variant.ResultingUC = []byte{9}
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.Put(q, rec))
	require.NoError(t, store.PutVariant(q, &variant))
	s, err := NewServer(store, q.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, s.SetPublicReads(Limits{Deadline: time.Second, Pending: 4, PerPeer: 2}))
	b := ample()
	b.ByteRate, b.ByteBurst = 1, 8<<10                  // a few refusals fit; a record does not
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)} // frozen: nothing refills
	s.publicBudget = newPublicBudget(b, clock.now)
	raw, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	exact := func(digest [32]byte) (archive.Response, error) {
		var out bytes.Buffer
		if err := s.serveFrame(context.Background(), &out, append(append([]byte{6}, digest[:]...), raw...), &readMeter{budget: s.publicBudget, id: "f1"}); err != nil {
			return archive.Response{}, err
		}
		frame, err := readFrame(&out, maxArchiveFrameBytes)
		require.NoError(t, err)
		return archive.DecodeResponse(frame)
	}
	for i := 0; i < 8; i++ {
		answer, err := exact([32]byte{byte(i + 1)})
		require.NoError(t, err)
		require.Equal(t, archive.Unavailable, answer.Outcome)
	}
	require.Positive(t, s.publicBudget.peers["f1"].bytes.tokens, "eight wrong-digest reads cost refusals only: no record was read")

	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	answer, err := exact(digest)
	require.NoError(t, err)
	require.Equal(t, archive.OK, answer.Outcome)
	require.Negative(t, s.publicBudget.peers["f1"].bytes.tokens, "the right digest is charged the 1 MiB it read")
	_, err = exact(digest)
	require.ErrorIs(t, err, ErrPeerLimit, "and the next read waits for the debt to be repaid")
}
