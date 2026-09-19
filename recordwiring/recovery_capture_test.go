package recordwiring_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

/*
W3b-2: the capturer publishes a record for a block that anchor recovery applied, and the existing
store refusals answer the case where both a recovery commit and an ordinary commit report the same
block. The capturer cannot tell a recovery commit from an ordinary one, which is the contract: the
round hands it the certificate that certified the block, which across a quiet tail is the source,
never the quiet certificate in hand.
*/

// recoveryCommit is what Round.applyVerifiedAnchor reports for a recovered block: the SOURCE
// certificate that certified the block and its bound technical record, with the certified block hash.
func recoveryCommit(h *captureHarness, i int) shardnode.CertifiedCommit {
	uc, tr := h.c.Certificate(i)
	return shardnode.CertifiedCommit{Certificate: uc, Technical: tr, BlockHash: h.c.Blocks[i].Hash.Bytes()}
}

// childAfter builds a quiet certificate the source's technical record assigns: the child the
// readiness gate of §9 must find readiness for. The bound technical record is returned with it, so
// the test observes the exact pair the chain signed.
func childAfter(t *testing.T, c *certifiedchain.Chain, source *types.UnicityCertificate, sourceTR *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	state := bytes.Clone(source.InputRecord.Hash)
	childTR := &certification.TechnicalRecord{Round: sourceTR.Round + 1, Epoch: sourceTR.Epoch, Leader: "leader",
		StatHash: bytes.Repeat([]byte{0xa1}, 32), FeeHash: bytes.Repeat([]byte{0xa2}, 32)}
	childIR := &types.InputRecord{Version: 1, RoundNumber: sourceTR.Round, Epoch: source.InputRecord.Epoch,
		PreviousHash: state, Hash: state, SummaryValue: []byte{}, Timestamp: source.InputRecord.Timestamp + 1}
	return c.Certify(c.Signer, childIR, childTR, source.GetRootRoundNumber()+1), childTR
}

// TestRecoveryCapturePublishesARecord: the capturer publishes a record for a recovery-applied block,
// and the gate of §9 then finds readiness for its child. The commit is the one the round reports for
// a recovered block: the source certificate that names the block, so the durable record is bound to
// the certificate that actually certified it rather than to the quiet certificate in hand.
func TestRecoveryCapturePublishesARecord(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0)
	b := h.c.Blocks[1]
	h.exec.set(b)

	h.cap.ObserveCommit(recoveryCommit(h, 1))
	res := h.next()
	require.Equal(t, recordwiring.CapturePublished, res.Outcome, "%v", res.Err)
	require.Equal(t, b.Hash, h.head())

	source, sourceTR := storedHeadPair(t, h)
	require.Equal(t, b.Hash.Bytes(), []byte(source.InputRecord.BlockHash),
		"the durable record names the block the source certificate certified")

	child, childTR := childAfter(t, h.c, source, sourceTR)
	obs, err := recordwiring.NewObservations(recordwiring.DefaultObservationLimits)
	require.NoError(t, err)
	require.NoError(t, obs.Observe(source, sourceTR))
	require.NoError(t, obs.Observe(child, childTR))
	r, err := recordwiring.NewReadiness(h.d, h.store, h.exec, obs)
	require.NoError(t, err)
	p, err := r.Prepare(context.Background(), child)
	require.NoError(t, err, "the record from a recovery-applied block is the source's own certificate")
	require.True(t, p.Valid())
	require.NoError(t, r.Revalidate(context.Background(), p, child))
}

// TestRecoveryAndOrdinaryCommitForTheSameBlock: both a recovery commit and an ordinary commit for
// the same block are reported. The block is already durable after the first, so the existing
// duplicate refusal answers the second: no publication starts and no record is damaged. The store's
// own stale refusal is the other half of the same answer and is covered by
// TestCaptureFailuresKeepThePriorRecord's "a later record is already durable".
func TestRecoveryAndOrdinaryCommitForTheSameBlock(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0)
	b := h.c.Blocks[1]
	h.exec.set(b)

	h.cap.ObserveCommit(recoveryCommit(h, 1))
	require.Equal(t, recordwiring.CapturePublished, h.next().Outcome)
	prior, keys := h.head(), h.keys()

	// The ordinary commit reports the same block, re-certified at a later root round: the same input
	// record, so the same partition round and block, but a different signed certificate.
	source, sourceTR := storedHeadPair(t, h)
	repeatIR := *source.InputRecord
	repeat := h.c.Certify(h.c.Signer, &repeatIR, sourceTR, source.GetRootRoundNumber()+1)
	h.cap.ObserveCommit(shardnode.CertifiedCommit{Certificate: repeat, Technical: sourceTR, BlockHash: b.Hash.Bytes()})

	dup := h.next()
	require.Equal(t, recordwiring.CaptureDuplicate, dup.Outcome)
	require.ErrorIs(t, dup.Err, recordwiring.ErrDuplicateCapture)
	require.Equal(t, prior, h.head(), "the durable record is not damaged")
	require.Equal(t, keys, h.keys(), "nothing is written or deleted")
}
