package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// namedAvailability records which replicas are asked and refuses the down ones.
type namedAvailability struct {
	mu    sync.Mutex
	down  map[string]bool
	calls []string
}

func (a *namedAvailability) VerifyAvailable(replica string, _ archive.Request, _ [32]byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = append(a.calls, replica)
	if a.down[replica] {
		return frontier.ErrUnavailable
	}
	return nil
}

func (a *namedAvailability) reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.calls = nil
}

func (a *namedAvailability) asked() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.calls...)
}

type rotationJournal struct {
	path   string
	c      Context
	policy frontier.Policy
	limits JournalLimits
	first  frontier.Coverage
	second frontier.Coverage // height 2, acknowledged by the {first, third} pair
}

// newRotationJournal builds a real configured journal whose frontier was advanced
// (and, when pruned, pruned) under the {first, second} replica pair, plus a
// second certified block whose coverage the {first, third} pair acknowledges.
func newRotationJournal(t *testing.T, pruned bool) rotationJournal {
	t.Helper()
	ctx := context.Background()
	path := t.TempDir() + "/journal.db"
	s, f, c, policy, first, limits := frontierTestSetupWithFixture(t, path)
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{first}))
	if pruned {
		require.NoError(t, s.PruneFrontier(ctx, c, limits))
	}
	state := common.Hash{31: 8}
	header := &gethtypes.Header{ParentHash: common.Hash(first.Anchor.Subject.BlockHash), Root: state, Number: big.NewInt(2), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
	headerRaw, err := rlp.EncodeToBytes(header)
	require.NoError(t, err)
	hash := header.Hash()
	var firstUC types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(first.Material.ResultingUC, &firstUC))
	var firstTR certification.TechnicalRecord
	require.NoError(t, types.Cbor.Unmarshal(first.Material.ResultingTR, &firstTR))
	candidate := JournalCandidate{Round: 2, Number: 2, ParentNumber: 1, Hash: hash.Bytes(), StateRoot: state.Bytes(),
		ParentHash: first.Anchor.Subject.BlockHash[:], ParentState: first.Anchor.StateRoot[:], Raw: []byte{4, 5, 6}, BlockSize: 3,
		AuthorizingUC: &firstUC, AuthorizingTR: &firstTR}
	require.NoError(t, s.PutJournalCandidate(ctx, c, limits, candidate))
	obs := f.observation(&types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: first.Anchor.StateRoot[:], Hash: state.Bytes(), BlockHash: hash.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_002}, 3, 6)
	p, _, err := s.PrepareObservation(ctx, c, obs)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	uc2, err := types.Cbor.Marshal(obs.Certificate())
	require.NoError(t, err)
	tr2, err := types.Cbor.Marshal(obs.TechnicalRecord())
	require.NoError(t, err)
	bodyRaw, err := rlp.EncodeToBytes(&gethtypes.Body{})
	require.NoError(t, err)
	rec := &archive.Record{Header: headerRaw, Body: bodyRaw, CanonicalRootInput: []byte{2}, OriginalUC: first.Material.ResultingUC,
		OriginalTR: first.Material.ResultingTR, ResultingUC: uc2, ResultingTR: tr2, Companion: []byte{1}}
	q := archive.Request{Context: policy.Context, BlockHash: [32]byte(hash)}
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, rec)
	require.NoError(t, err)
	ack := sha256.Sum256(req)
	second := frontier.Coverage{Anchor: frontier.Record{Sequence: 2, Round: 6, Height: 2, StateRoot: [32]byte(state), Subject: q,
		Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest}, {Replica: "third", RequestDigest: ack, ManifestDigest: digest}}}, Material: rec}
	require.NoError(t, s.Close())
	return rotationJournal{path: path, c: c, policy: policy, limits: limits, first: first, second: second}
}

// reopen restarts the journal under the given replica pair.
func (j rotationJournal) reopen(t *testing.T, replicas [2]string, avail *namedAvailability, log *slog.Logger) (*Store, error) {
	t.Helper()
	ctx := context.Background()
	s, err := OpenConfiguredV2(j.path, Settings{Retain: 3})
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	s.SetLogger(log)
	require.NoError(t, s.EnableJournal(ctx, j.c, j.limits))
	policy := j.policy
	policy.Replicas = replicas
	policy.Availability = avail
	return s, s.EnableFrontier(ctx, j.c, j.limits, policy)
}

func warnings(buf *bytes.Buffer) int {
	return strings.Count(buf.String(), "level=WARN")
}

func TestRotatedArchiveReplicaPairRestartsFromPersistedFrontier(t *testing.T) {
	for _, pruned := range []bool{false, true} {
		name := "advanced"
		if pruned {
			name = "pruned"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			j := newRotationJournal(t, pruned)
			avail := &namedAvailability{down: map[string]bool{"third": true}}
			var logs bytes.Buffer
			s, err := j.reopen(t, [2]string{"first", "third"}, avail, slog.New(slog.NewTextHandler(&logs, nil)))
			require.NoError(t, err, "a retired replica's acknowledgments must not block a restart")
			require.Equal(t, 1, warnings(&logs), "the policy change is logged once")
			require.Contains(t, logs.String(), "second")
			require.Contains(t, logs.String(), "third")

			snap, err := s.LoadFrontier(ctx, j.c, j.limits)
			require.NoError(t, err)
			require.EqualValues(t, 1, snap.Anchor.Height, "the durable position is kept")
			require.Equal(t, "first", snap.Anchor.Acks[0].Replica)
			require.True(t, snap.Anchor.Acks[1].Dropped(), "the retired replica's acknowledgment is dropped")
			require.Equal(t, "second", snap.Anchor.Retired[1])
			if pruned {
				require.EqualValues(t, 1, snap.Floor)
			} else {
				require.EqualValues(t, 0, snap.Floor)
			}

			avail.reset()
			require.NoError(t, s.VerifyFrontierCopies(ctx, j.c, j.limits))
			require.Equal(t, []string{"first"}, avail.asked(), "only the retained replica's copy is verified")

			// Pruning waits until the new pair acknowledges beyond the position.
			before, err := s.LoadJournal(ctx, j.c, j.limits)
			require.NoError(t, err)
			err = s.PruneFrontier(ctx, j.c, j.limits)
			if pruned {
				require.NoError(t, err, "an already pruned prefix stays valid")
			} else {
				require.ErrorIs(t, err, frontier.ErrAcknowledgment)
			}
			require.ErrorIs(t, s.AdvanceFrontier(ctx, j.c, j.limits, []frontier.Coverage{j.second}), frontier.ErrAcknowledgment, "the new replica has not acknowledged yet")
			snap, err = s.LoadFrontier(ctx, j.c, j.limits)
			require.NoError(t, err)
			require.EqualValues(t, 1, snap.Anchor.Height)
			after, err := s.LoadJournal(ctx, j.c, j.limits)
			require.NoError(t, err)
			require.Len(t, after.Candidates, len(before.Candidates))
			if !pruned {
				require.ErrorIs(t, s.PruneFrontier(ctx, j.c, j.limits), frontier.ErrAcknowledgment)
			}

			// Both configured replicas acknowledge: the existing two-ack rule resumes.
			avail.down["third"] = false
			require.NoError(t, s.AdvanceFrontier(ctx, j.c, j.limits, []frontier.Coverage{j.second}))
			require.NoError(t, s.PruneFrontier(ctx, j.c, j.limits))
			snap, err = s.LoadFrontier(ctx, j.c, j.limits)
			require.NoError(t, err)
			require.EqualValues(t, 2, snap.Anchor.Height)
			require.EqualValues(t, 2, snap.Floor)
			require.False(t, snap.Anchor.Migrated())
			page, err := s.LoadCoverage(ctx, j.c, j.limits, 0, 4)
			require.NoError(t, err, "coverage written under the old pair stays readable")
			require.Len(t, page, 2)
			require.True(t, page[0].Migrated())
			require.False(t, page[1].Migrated())
			require.NoError(t, s.Close())

			// A later restart under the same pair no longer reports a change.
			var again bytes.Buffer
			avail.reset()
			s, err = j.reopen(t, [2]string{"first", "third"}, avail, slog.New(slog.NewTextHandler(&again, nil)))
			require.NoError(t, err)
			require.Zero(t, warnings(&again))
			require.NoError(t, s.VerifyFrontierCopies(ctx, j.c, j.limits))
			require.Equal(t, []string{"first", "third"}, avail.asked())
		})
	}
}

func TestAcknowledgmentFromRetiredReplicaIsRefusedAfterTheChange(t *testing.T) {
	ctx := context.Background()
	j := newRotationJournal(t, false)
	avail := &namedAvailability{}
	s, err := j.reopen(t, [2]string{"first", "third"}, avail, nil)
	require.NoError(t, err)
	for name, acks := range map[string][2]string{
		"retired replica in the replaced slot": {"first", "second"},
		"retired replica beside the new one":   {"second", "third"},
		"both original replicas":               {"first", "second"},
	} {
		forged := j.second
		forged.Anchor.Acks[0].Replica, forged.Anchor.Acks[1].Replica = acks[0], acks[1]
		avail.reset()
		require.ErrorIs(t, s.AdvanceFrontier(ctx, j.c, j.limits, []frontier.Coverage{forged}), frontier.ErrContext, name)
		require.NotContains(t, avail.asked(), "second", name)
		snap, err := s.LoadFrontier(ctx, j.c, j.limits)
		require.NoError(t, err)
		require.EqualValues(t, 1, snap.Anchor.Height, name)
	}
	forged := j.second.Anchor
	forged.Acks[1].Replica = "second"
	_, err = frontier.Encode(forged, *s.frontier)
	require.ErrorIs(t, err, frontier.ErrContext, "the encoder never writes a retired replica's acknowledgment")
}

func TestUnchangedReplicaPairBehavesAsBefore(t *testing.T) {
	ctx := context.Background()
	j := newRotationJournal(t, false)
	avail := &namedAvailability{}
	var logs bytes.Buffer
	s, err := j.reopen(t, [2]string{"first", "second"}, avail, slog.New(slog.NewTextHandler(&logs, nil)))
	require.NoError(t, err)
	require.Zero(t, warnings(&logs), "no policy change, no warning")
	snap, err := s.LoadFrontier(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.False(t, snap.Anchor.Migrated())
	require.Equal(t, "second", snap.Anchor.Acks[1].Replica)
	avail.reset()
	require.NoError(t, s.VerifyFrontierCopies(ctx, j.c, j.limits))
	require.Equal(t, []string{"first", "second"}, avail.asked())
	require.NoError(t, s.PruneFrontier(ctx, j.c, j.limits), "an unchanged pair prunes without a new acknowledgment")
	snap, err = s.LoadFrontier(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.EqualValues(t, 1, snap.Floor)
}

func TestMalformedReplicaPairChangeIsRefusedAtStartup(t *testing.T) {
	ctx := context.Background()
	j := newRotationJournal(t, false)
	for name, tc := range map[string]struct {
		replicas [2]string
		want     error
	}{
		"a single replica":        {[2]string{"first", ""}, ErrContext},
		"a duplicated replica":    {[2]string{"first", "first"}, ErrContext},
		"both replicas replaced":  {[2]string{"third", "fourth"}, frontier.ErrContext},
		"the same pair reordered": {[2]string{"second", "first"}, frontier.ErrContext},
	} {
		s, err := j.reopen(t, tc.replicas, &namedAvailability{}, nil)
		require.ErrorIs(t, err, tc.want, name)
		require.Nil(t, s.frontier, name)
		_, err = s.LoadFrontier(ctx, j.c, j.limits)
		require.ErrorIs(t, err, ErrSettings, name)
		require.NoError(t, s.Close(), name)
	}
	// Refusal changes nothing durable: the original pair still starts.
	s, err := j.reopen(t, [2]string{"first", "second"}, &namedAvailability{}, nil)
	require.NoError(t, err)
	snap, err := s.LoadFrontier(ctx, j.c, j.limits)
	require.NoError(t, err)
	require.EqualValues(t, 1, snap.Anchor.Height)
}
