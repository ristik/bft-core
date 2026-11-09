package configuredprogress

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// bft-core#991: a block whose archive representation was selected (bft-core#876: another valid first resulting certificate of the same input record, at a later root round)
// and whose coverage was then committed must still verify when the journal is loaded before the prune. The coverage is committed against the SELECTED pair
// (checkCoveredCandidate), so the load check of a candidate against the frontier anchor has to look at the same pair.
func TestLoadAcceptsACoveredBlockWhoseArchiveRepresentationWasSelected(t *testing.T) {
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
	require.NoError(t, s.PruneFrontier(ctx, c, limits))
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err, "and after it")
}
