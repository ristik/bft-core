package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// bft-core#991: a block whose archive representation was selected (bft-core#876: another valid first resulting certificate of the same input record, at a later root round)
// and whose coverage was then committed must still verify when the journal is loaded before the prune. The coverage is committed against the SELECTED pair
// (checkCoveredCandidate), so the load check of a candidate against the frontier anchor has to look at the same pair.
func TestLoadAcceptsACoveredBlockWhoseArchiveRepresentationWasSelected(t *testing.T) {
	for _, next := range []bool{false, true} {
		name := "anchor"
		if next {
			name = "below the next anchor"
		}
		t.Run(name, func(t *testing.T) { loadSelected(t, next) })
	}
}

func loadSelected(t *testing.T, next bool) {
	s, f, c, _, item, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()

	var own types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &own))
	// the repeat of the same input record at a later root round, admitted like any observation
	repeat := f.observation(own.InputRecord, 2, 7)
	p, _, err := s.PrepareObservation(ctx, c, repeat)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	uc2, err := types.Cbor.Marshal(repeat.Certificate())
	require.NoError(t, err)
	tr2, err := types.Cbor.Marshal(repeat.TechnicalRecord())
	require.NoError(t, err)

	rec2 := *item.Material
	rec2.ResultingUC, rec2.ResultingTR = uc2, tr2
	q := item.Anchor.Subject
	req, err := archive.EncodeRequest(q)
	require.NoError(t, err)
	digest, err := archive.ManifestDigest(q, item.Material)
	require.NoError(t, err)
	digest2, err := archive.ManifestDigest(q, &rec2)
	require.NoError(t, err)
	require.NotEqual(t, digest, digest2, "premise: two representations of the block")
	ack := sha256.Sum256(req)
	anchor2 := item.Anchor
	anchor2.Round = repeat.Certificate().GetRootRoundNumber()
	anchor2.Acks = [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack, ManifestDigest: digest2}, {Replica: "second", RequestDigest: ack, ManifestDigest: digest2}}

	require.NoError(t, s.SelectArchiveRepresentation(ctx, c, limits, ArchiveSelectionRequest{BlockHash: q.BlockHash, Prior: PairID(item.Material.ResultingUC, item.Material.ResultingTR), OldDigest: digest, NewDigest: digest2, UC: uc2, TR: tr2}))
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{{Anchor: anchor2, Material: &rec2}}))

	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err, "the covered block with a selected representation loads before the prune")
	if next {
		// one more frontier advance before the prune: the next block, authorized by the repeat, covered at a later anchor. The selected block is then BELOW the anchor, and what
		// vouches for it is its coverage row, committed from the selected pair.
		state2 := common.Hash{31: 8}
		header2 := &gethtypes.Header{ParentHash: common.BytesToHash(q.BlockHash[:]), Root: state2, Number: big.NewInt(2), Difficulty: new(big.Int), BaseFee: big.NewInt(1)}
		headerRaw2, err := rlp.EncodeToBytes(header2)
		require.NoError(t, err)
		hash2 := header2.Hash()
		cand2 := JournalCandidate{Round: 2, Number: 2, ParentNumber: 1, Hash: hash2.Bytes(), StateRoot: state2.Bytes(), ParentHash: q.BlockHash[:], ParentState: item.Anchor.StateRoot[:], Raw: []byte{4, 5, 6}, BlockSize: 3,
			AuthorizingUC: repeat.Certificate(), AuthorizingTR: repeat.TechnicalRecord()}
		require.NoError(t, s.PutJournalCandidate(ctx, c, limits, cand2))
		second := f.observation(&types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: item.Anchor.StateRoot[:], Hash: state2.Bytes(), BlockHash: hash2.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_002}, 3, 9)
		p2, _, err := s.PrepareObservation(ctx, c, second)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p2)
		require.NoError(t, err)
		uc3, err := types.Cbor.Marshal(second.Certificate())
		require.NoError(t, err)
		tr3, err := types.Cbor.Marshal(second.TechnicalRecord())
		require.NoError(t, err)
		rec3 := *item.Material
		rec3.Header, rec3.OriginalUC, rec3.OriginalTR, rec3.ResultingUC, rec3.ResultingTR = headerRaw2, uc2, tr2, uc3, tr3
		q3 := q
		q3.BlockHash = [32]byte(hash2)
		req3, err := archive.EncodeRequest(q3)
		require.NoError(t, err)
		digest3, err := archive.ManifestDigest(q3, &rec3)
		require.NoError(t, err)
		ack3 := sha256.Sum256(req3)
		anchor3 := frontier.Record{Sequence: 2, Round: second.Certificate().GetRootRoundNumber(), Height: 2, StateRoot: [32]byte(state2), Subject: q3,
			Acks: [2]frontier.Acknowledgment{{Replica: "first", RequestDigest: ack3, ManifestDigest: digest3}, {Replica: "second", RequestDigest: ack3, ManifestDigest: digest3}}}
		require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{{Anchor: anchor3, Material: &rec3}}))
		image, err := s.LoadJournal(ctx, c, limits)
		require.NoError(t, err, "the selected block below the next anchor loads before the prune")
		hot := false
		for _, e := range image.Candidates {
			hot = hot || string(e.Candidate.Hash) == string(q.BlockHash[:])
		}
		t.Logf("selected block still a candidate below the anchor before the prune: %v; observations kept: %d", hot, len(image.Observations))
		// Why this state is not reached by pruning: the journal refuses a certificate of an earlier partition round at a later root round, so no uncovered observation can keep the
		// older body hot (PruneFrontier deletes a certified candidate at or below the anchor unless an uncovered observation targets it).
		late := f.observation(own.InputRecord, 2, 11)
		_, _, lerr := s.PrepareObservation(ctx, c, late)
		require.ErrorContains(t, lerr, "earlier partition round at later root round")
		// The covered-row branch of the check still has to vouch for such a body by the pair its coverage row was committed from (the selected one), so the state is built directly:
		// the observations that resolved the selected block are removed, as a prune that kept the body would have left it.
		require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
			b := tx.Bucket(bucketName)
			cur := b.Cursor()
			for k, raw := cur.Seek(journalObservationPrefix); k != nil && bytes.HasPrefix(k, journalObservationPrefix); k, raw = cur.Next() {
				w, e := decodeObservation(raw)
				if e != nil {
					return e
				}
				if bytes.Equal(w.TargetHash, q.BlockHash[:]) {
					if e := cur.Delete(); e != nil {
						return e
					}
				}
			}
			return nil
		}))
		_, err = s.LoadJournal(ctx, c, limits)
		require.NoError(t, err, "the selected block below the anchor, its observations gone, is vouched for by its coverage row")
		return
	}
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err, "and after it")
}
