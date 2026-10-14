package shardnode

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/utbchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

func baseResponse(t *testing.T) *certification.CertificationResponse {
	cr := &certification.CertificationResponse{Partition: 1,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}}}
	require.NoError(t, cr.SetTechnicalRecord(certification.TechnicalRecord{Round: 9, Epoch: 2, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	return cr
}

type ingestRig struct {
	c       *BFTClient
	chain   *utbchain.Chain
	entries []uint64
	gaps    [][2]uint64
}

func newIngestRig(t *testing.T, upTo uint64) *ingestRig {
	r := &ingestRig{chain: utbchain.New(t, 6)}
	r.c = &BFTClient{opts: BFTClientOptions{
		UTBStore:       r.chain.Store(t, upTo),
		OnTrustBaseGap: func(have, got uint64) { r.gaps = append(r.gaps, [2]uint64{have, got}) },
		OnTrustBaseEntry: func(e *types.RootTrustBaseV2) {
			r.entries = append(r.entries, e.Epoch)
		},
	}}
	return r
}

func (r *ingestRig) v2(t *testing.T, base *certification.CertificationResponse, epochs ...uint64) *certification.CertificationResponseV2 {
	var raw [][]byte
	for _, e := range epochs {
		raw = append(raw, r.chain.Entries[e-2])
	}
	return certification.NewCertificationResponseV2(base, raw)
}

func TestVersion2ResponseAppendsTheEntriesAndYieldsTheLegacyResponse(t *testing.T) {
	r := newIngestRig(t, 1)
	base := baseResponse(t)
	out := r.c.ingestTrustBaseUpdates(context.Background(), r.v2(t, base, 2, 3))
	legacy, ok := out.(*certification.CertificationResponse)
	require.True(t, ok, "%T", out)
	require.NoError(t, legacy.IsValid())
	require.EqualValues(t, 3, r.c.opts.UTBStore.Tip().Epoch)
	require.Equal(t, []uint64{2, 3}, r.entries, "in epoch order")
	require.Empty(t, r.gaps)

	// the same update again changes nothing and calls nothing
	r.entries = nil
	r.c.ingestTrustBaseUpdates(context.Background(), r.v2(t, base, 2, 3))
	require.Empty(t, r.entries)
	require.EqualValues(t, 3, r.c.opts.UTBStore.Tip().Epoch)
}

func TestOtherMessagesPassUnchangedAndAClientWithoutAStoreIgnoresTheEntries(t *testing.T) {
	r := newIngestRig(t, 1)
	legacy := baseResponse(t)
	require.Same(t, legacy, r.c.ingestTrustBaseUpdates(context.Background(), legacy))
	require.Equal(t, "x", r.c.ingestTrustBaseUpdates(context.Background(), "x"))

	r.c.opts.UTBStore = nil
	out := r.c.ingestTrustBaseUpdates(context.Background(), r.v2(t, baseResponse(t), 2))
	require.IsType(t, &certification.CertificationResponse{}, out, "the certificate is handled as before")
	require.Empty(t, r.entries)
}

func TestAGapIsReportedAndNothingAfterItIsApplied(t *testing.T) {
	r := newIngestRig(t, 1)
	r.c.ingestTrustBaseUpdates(context.Background(), r.v2(t, baseResponse(t), 4, 5))
	require.EqualValues(t, 1, r.c.opts.UTBStore.Tip().Epoch)
	require.Equal(t, [][2]uint64{{1, 4}}, r.gaps, "the store holds epoch 1, the offer starts at 4: fetch the range")
	require.Empty(t, r.entries)
}

func TestAnInvalidEntryIsNeverInstalledAndStopsTheUpdate(t *testing.T) {
	r := newIngestRig(t, 1)
	base := baseResponse(t)
	bad := bytes.Clone(r.chain.Entries[0])
	bad[len(bad)-7] ^= 1 // a signature byte
	v2 := certification.NewCertificationResponseV2(base, [][]byte{bad, r.chain.Entries[1]})
	out := r.c.ingestTrustBaseUpdates(context.Background(), v2)
	require.IsType(t, &certification.CertificationResponse{}, out, "the response itself is still delivered to the certificate checks")
	require.EqualValues(t, 1, r.c.opts.UTBStore.Tip().Epoch)
	require.Empty(t, r.entries)
	require.Empty(t, r.gaps)

	t.Run("an entry that does not extend the chain", func(t *testing.T) {
		other := utbchain.New(t, 3)
		r.c.opts.UTBStore = other.Store(t, 3)
		v2 := certification.NewCertificationResponseV2(base, [][]byte{r.chain.Entries[1]}) // epoch 3 of the first chain, offered to a store at epoch 3
		r.c.ingestTrustBaseUpdates(context.Background(), v2)
		require.EqualValues(t, 3, r.c.opts.UTBStore.Tip().Epoch)
	})
}

// A rejection's status and message are the legacy response's, and valid entries are kept regardless of them.
func TestValidEntriesAreKeptWhateverTheResponsesStatus(t *testing.T) {
	r := newIngestRig(t, 1)
	base := baseResponse(t)
	base.Status, base.Message = certification.CertStatusRequestInvalid, "stale round"
	out := r.c.ingestTrustBaseUpdates(context.Background(), r.v2(t, base, 2))
	legacy := out.(*certification.CertificationResponse)
	require.EqualValues(t, certification.CertStatusRequestInvalid, legacy.Status)
	require.Equal(t, "stale round", legacy.Message)
	require.False(t, legacy.IsAccepted())
	require.EqualValues(t, 2, r.c.opts.UTBStore.Tip().Epoch)
}

func TestAMalformedVersion2ResponseAppliesNothing(t *testing.T) {
	r := newIngestRig(t, 1)
	v2 := r.v2(t, baseResponse(t), 2)
	v2.Version = 7
	r.c.ingestTrustBaseUpdates(context.Background(), v2)
	require.EqualValues(t, 1, r.c.opts.UTBStore.Tip().Epoch)
	v2 = r.v2(t, baseResponse(t), 2, 3)
	v2.TrustBaseUpdates = append(v2.TrustBaseUpdates, r.chain.Entries[2])
	r.c.ingestTrustBaseUpdates(context.Background(), v2)
	require.EqualValues(t, 1, r.c.opts.UTBStore.Tip().Epoch, "three entries exceed the bound: none is applied")
}

// Through the real queue: the entries of every version 2 response are applied before any response is dropped as stale, and what the driver gets is the
// legacy response.
func TestCoalescingIngestsVersion2UpdatesBeforeItDropsAStaleResponse(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	chain := utbchain.New(t, 4)
	client, _ := f.client(f.confMine)
	client.opts.UTBStore = chain.Store(t, 1)

	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	zero := make([]byte, 32)
	trHash, err := f.technical.Hash()
	require.NoError(t, err)
	response := func(rootRound uint64, entries ...[]byte) *certification.CertificationResponseV2 {
		uc := testcertificates.CreateUnicityCertificate(t, f.signer, f.ucMine.InputRecord, pdr, rootRound, zero, trHash)
		return certification.NewCertificationResponseV2(&certification.CertificationResponse{Partition: authPartitionID, Shard: types.ShardID{}, Technical: *f.technical, UC: *uc}, entries)
	}
	older, newest := response(51, chain.Entries[0]), response(52, chain.Entries[1], chain.Entries[2])
	queued := make(chan any, 1)
	queued <- newest
	batch, closed := client.coalesceBufferedCertificationResponses(ctx, older, queued)
	require.False(t, closed)
	require.Len(t, batch, 1, "the stale response was dropped")
	got, ok := batch[0].(*certification.CertificationResponse)
	require.True(t, ok, "%T", batch[0])
	require.EqualValues(t, 52, got.UC.GetRootRoundNumber())
	require.EqualValues(t, 4, client.opts.UTBStore.Tip().Epoch, "the entries of both responses, including the dropped one's, were applied in order")
}
