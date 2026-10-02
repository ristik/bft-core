package signingauthority

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ackWindowRequest is a request over a certificate under conf (technical-record epoch conf.Epoch) whose INPUT RECORD is at irEpoch: while
// a successor assignment's acknowledgement is pending irEpoch is an earlier epoch. The proposal is the first at conf's epoch.
func ackWindowRequest(t *testing.T, f *fixture, conf *types.PartitionDescriptionRecord, rootEpoch, round, irEpoch uint64) Request {
	t.Helper()
	return ackWindowRequestTR(t, f, conf, rootEpoch, round, irEpoch, conf.Epoch)
}

// ackWindowRequestTR is ackWindowRequest with the technical record at trEpoch (the certificate still carries conf's hash).
func ackWindowRequestTR(t *testing.T, f *fixture, conf *types.PartitionDescriptionRecord, rootEpoch, round, irEpoch, trEpoch uint64) Request {
	t.Helper()
	zero := make([]byte, 32)
	tr := &certification.TechnicalRecord{Round: round, Epoch: trEpoch, Leader: testNodeID, StatHash: zero, FeeHash: zero}
	trHash, err := tr.Hash()
	require.NoError(t, err)
	uc := testcertificates.CreateUnicityCertificate(t, f.signers[0], &types.InputRecord{
		Version: 1, RoundNumber: round - 1, Epoch: irEpoch, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 1,
	}, conf, 50+round, zero, trHash)
	uc.UnicitySeal.Epoch = rootEpoch
	uc.UnicitySeal.Signatures = nil
	require.NoError(t, uc.UnicitySeal.Sign(nodeIDOf(t, f.signers[0]), f.signers[0]))
	proposal := f.proposal()
	proposal.InputRecord.RoundNumber = round
	proposal.InputRecord.Epoch = conf.Epoch
	proposal.InputRecord.PreviousHash = bytes.Clone(uc.InputRecord.Hash)
	proposal.InputRecord.Timestamp = uc.UnicitySeal.Timestamp
	return Request{UC: uc, Technical: tr, Proposed: proposal}
}

func confAt(conf *types.PartitionDescriptionRecord, epoch uint64) *types.PartitionDescriptionRecord {
	next := *conf
	next.Epoch = epoch
	next.EpochStart = epoch * 10
	return &next
}

// An authority-backed validator must be able to sign the request that certifies a successor assignment's acknowledgement: the
// certificate it extends carries the new configuration and technical-record epoch, but its input record is still at the epoch before.
func TestTheAcknowledgementWindowRequestIsSigned(t *testing.T) {
	f := newFixture(t, 1)
	a := f.pending(t)
	conf := ownConf(t, a)
	require.NoError(t, a.CompleteEnrollment(conf))
	session, err := a.ReplaceSession()
	require.NoError(t, err)

	// It operates at the enrolled epoch first (the acknowledged one), which is what makes its predecessor scope known.
	_, err = a.Reserve(t.Context(), session, f.requestUnder(t, conf))
	require.NoError(t, err)
	require.NoError(t, a.Sign(session))
	require.NoError(t, a.RetainResponse(session))

	next := confAt(conf, shardEpoch+1)
	require.NoError(t, a.AdvanceEpoch(t.Context(), next, successorTrust(f, 2)))
	session, err = a.ReplaceSession()
	require.NoError(t, err)

	t.Run("the acknowledgement request: technical record at the new epoch, input record at the epoch advanced from", func(t *testing.T) {
		_, err := a.Authenticate(t.Context(), ackWindowRequest(t, f, next, 2, 8, shardEpoch))
		require.NoError(t, err)
	})
	t.Run("an input-record epoch before the predecessor is refused", func(t *testing.T) {
		_, err := a.Authenticate(t.Context(), ackWindowRequest(t, f, next, 2, 8, shardEpoch-1))
		require.ErrorIs(t, err, ErrContextMismatch)
	})
	t.Run("an input-record epoch ahead of the enrolled one is refused", func(t *testing.T) {
		_, err := a.Authenticate(t.Context(), ackWindowRequest(t, f, next, 2, 8, shardEpoch+2))
		require.ErrorIs(t, err, ErrContextMismatch)
	})
	t.Run("a technical-record epoch other than the enrolled one is still refused", func(t *testing.T) {
		for _, trEpoch := range []uint64{shardEpoch, shardEpoch + 2} {
			_, err := a.Authenticate(t.Context(), ackWindowRequestTR(t, f, next, 2, 8, shardEpoch, trEpoch))
			require.ErrorIs(t, err, ErrContextMismatch, "technical-record epoch %d, enrolled %d", trEpoch, next.Epoch)
		}
	})

	t.Run("acknowledgement is one-way: once a request at the enrolled input-record epoch is reserved, an older one is refused", func(t *testing.T) {
		_, err := a.Reserve(t.Context(), session, ackWindowRequest(t, f, next, 2, 8, shardEpoch))
		require.NoError(t, err, "the acknowledgement request is reserved")
		_, err = a.Authenticate(t.Context(), ackWindowRequest(t, f, next, 2, 9, shardEpoch))
		require.NoError(t, err, "no acknowledged request has been reserved yet: the window is still open")
		_, err = a.Reserve(t.Context(), session, ackWindowRequest(t, f, next, 2, 10, next.Epoch)) // the acknowledged epoch
		require.NoError(t, err)
		_, err = a.Authenticate(t.Context(), ackWindowRequest(t, f, next, 2, 11, shardEpoch))
		require.ErrorIs(t, err, ErrContextMismatch, "an older input-record epoch after the acknowledgement")
	})

	t.Run("a further advance leaves the epoch it acknowledged as the new predecessor, and skipped epochs are admitted", func(t *testing.T) {
		skip := confAt(conf, shardEpoch+3) // epochs between were acknowledged without this authority
		require.NoError(t, a.AdvanceEpoch(t.Context(), skip, successorTrust(f, 3)))
		_, err := a.Authenticate(t.Context(), ackWindowRequest(t, f, skip, 3, 12, next.Epoch))
		require.NoError(t, err, "the epoch it last operated at")
		_, err = a.Authenticate(t.Context(), ackWindowRequest(t, f, skip, 3, 12, next.Epoch+1))
		require.NoError(t, err, "an epoch acknowledged in between, by validators this authority was not part of")
		_, err = a.Authenticate(t.Context(), ackWindowRequest(t, f, skip, 3, 12, shardEpoch))
		require.ErrorIs(t, err, ErrContextMismatch, "before the epoch it last operated at")
	})
}

// A joiner's authority has not operated yet, so its predecessor scope is unknown: the window is bounded by the supersession span.
func TestAJoinersAcknowledgementWindowIsBoundedBySupersessionSpan(t *testing.T) {
	f := newFixture(t, 1)
	enrolledAt := uint64(200)
	enroll := f.enroll
	enroll.ShardConfHash = nil
	enroll.ShardEpoch = enrolledAt
	joiner, err := New(enroll, trustStub{tb: f.tb})
	require.NoError(t, err)
	t.Cleanup(joiner.Close)
	pub, err := joiner.SigningPublicKey()
	require.NoError(t, err)
	conf := confAt(confNaming(testNodeID, pub), enrolledAt)
	require.NoError(t, joiner.CompleteEnrollment(conf))

	_, err = joiner.Authenticate(t.Context(), ackWindowRequest(t, f, conf, rootEpoch, 8, enrolledAt-1))
	require.NoError(t, err, "one epoch back")
	_, err = joiner.Authenticate(t.Context(), ackWindowRequest(t, f, conf, rootEpoch, 8, enrolledAt-handoff.MaxSupersessionSpan))
	require.NoError(t, err, "exactly the span back")
	_, err = joiner.Authenticate(t.Context(), ackWindowRequest(t, f, conf, rootEpoch, 8, enrolledAt-handoff.MaxSupersessionSpan-1))
	require.ErrorIs(t, err, ErrContextMismatch, "beyond the span")
}

func TestIREpochRule(t *testing.T) {
	const span = handoff.MaxSupersessionSpan
	for name, tc := range map[string]struct {
		ir, enrolled, base uint64
		known, acked       bool
		want               bool
	}{
		"the enrolled epoch":                      {5, 5, 0, false, false, true},
		"the enrolled epoch after the ack":        {5, 5, 4, true, true, true},
		"ahead":                                   {6, 5, 4, true, false, false},
		"the base while pending":                  {4, 5, 4, true, false, true},
		"between base and enrolled while pending": {4, 6, 3, true, false, true},
		"before the base":                         {2, 5, 4, true, false, false},
		"the base after the ack":                  {4, 5, 4, true, true, false},
		"unknown base: within the span":           {100 - span, 100, 0, false, false, true},
		"unknown base: beyond the span":           {100 - span - 1, 100, 0, false, false, false},
		"unknown base after the ack":              {99, 100, 0, false, true, false},
	} {
		t.Run(name, func(t *testing.T) {
			require.Equal(t, tc.want, irEpochAdmitted(tc.ir, tc.enrolled, tc.base, tc.known, tc.acked))
		})
	}
}
