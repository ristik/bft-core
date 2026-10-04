package consensus

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func domainBoundConfig() votesig.Config {
	return votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: sha256.Sum256([]byte("consensus-test-root-genesis"))}
}

// The paths that carry a certificate of an epoch are tested explicitly, each in an epoch that signs with the domain-bound
// scheme: a legacy-form certificate of that epoch is refused with the typed scheme error and never verified by a fallback.

func TestStateMsgOfADomainBoundEpochIsRefusedWithTheTypedError(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	root := restartedRoot(t, firstReplica(c.replicas))
	require.NoError(t, root.trustBaseStore.ActivateSigning(2, domainBoundConfig()))
	err := recoverTo(t, root, state)
	require.ErrorIs(t, err, votesig.ErrScheme)
	require.True(t, root.recovery.InRecovery(), "the refused state leaves the root in recovery")

	// control: the same state recovers when the epoch signs with scheme 1
	plain := restartedRoot(t, firstReplica(c.replicas))
	require.NoError(t, recoverTo(t, plain, state))
	require.False(t, plain.recovery.InRecovery())
}

func TestOldEpochCommitProofOfADomainBoundEpochIsRefusedAtInstall(t *testing.T) {
	c := newAnchorCluster(t)
	signers := map[string]abcrypto.Signer{}
	var source *anchorReplica
	for id, r := range c.replicas {
		signers[id.String()] = r.manager.safety.signer
		if r.oldSigners[id.String()] != nil {
			source = r
		}
	}
	require.NotNil(t, source)

	// the epoch-2 commit proof of a superseding handoff is verified by epoch 2's own rule
	h := newSecondHandoff(t, source, signers)
	require.NoError(t, h.root.trustBaseStore.ActivateSigning(2, domainBoundConfig()))
	_, err := h.root.InstallEpochGenesis(h.proof, h.head, h.body)
	require.ErrorIs(t, err, votesig.ErrScheme)
	require.EqualValues(t, 2, h.root.trustBase.Load().Epoch, "nothing was installed")

	// control: the same proof installs while epoch 2 signs with scheme 1
	ok := newSecondHandoff(t, source, signers)
	_, err = ok.root.InstallEpochGenesis(ok.proof, ok.head, ok.body)
	require.NoError(t, err)
	require.EqualValues(t, 3, ok.root.trustBase.Load().Epoch)
}

func TestLiveHandlersRefuseTheLegacyFormOfADomainBoundEpoch(t *testing.T) {
	c := newAnchorCluster(t)
	source := firstReplica(c.replicas)
	ctx := context.Background()
	root := restartedRoot(t, source)
	require.NoError(t, root.trustBaseStore.ActivateSigning(2, domainBoundConfig()))
	author := root.id.String()
	round := uint64(20)

	// an authentic, correctly signed message of the current epoch, in the legacy form
	signers := map[string]abcrypto.Signer{author: root.safety.signer}
	high := epochQC(t, source.proof.CommitQC, source.oldSigners, round-1)
	vote, timeout := epochMessages(t, root.trustBase.Load().Epoch, high, signers, author, round)
	vote.Scheme, vote.SealSignature = 0, nil
	timeout.Scheme = 0
	require.ErrorIs(t, root.onVoteMsg(ctx, vote), votesig.ErrScheme)
	require.ErrorIs(t, root.onTimeoutMsg(ctx, timeout), votesig.ErrScheme)
	require.NotContains(t, root.voteBuffer, author)
}

func secondHandoffFixture(t *testing.T) (*anchorReplica, map[string]abcrypto.Signer) {
	t.Helper()
	c := newAnchorCluster(t)
	signers := map[string]abcrypto.Signer{}
	var source *anchorReplica
	for id, r := range c.replicas {
		signers[id.String()] = r.manager.safety.signer
		if r.oldSigners[id.String()] != nil {
			source = r
		}
	}
	require.NotNil(t, source)
	return source, signers
}

// The old epoch's commit proof is verified in the wire form its own epoch signs with: the paired-signature certificate of a
// domain-bound epoch installs, and either form in the other kind of epoch is refused with the typed scheme error.
func TestOldEpochCommitProofIsVerifiedInTheFormOfItsEpoch(t *testing.T) {
	source, signers := secondHandoffFixture(t)

	t.Run("a scheme 2 proof of a domain-bound epoch installs", func(t *testing.T) {
		h := newSecondHandoff(t, source, signers, true)
		require.NoError(t, h.root.trustBaseStore.ActivateSigning(2, domainBoundConfig()))
		_, err := h.root.InstallEpochGenesis(h.proof, h.head, h.body)
		require.NoError(t, err)
		require.EqualValues(t, 3, h.root.trustBase.Load().Epoch)
	})
	t.Run("a scheme 2 proof of a legacy epoch is refused", func(t *testing.T) {
		h := newSecondHandoff(t, source, signers, true)
		_, err := h.root.InstallEpochGenesis(h.proof, h.head, h.body)
		require.ErrorIs(t, err, votesig.ErrScheme)
		require.EqualValues(t, 2, h.root.trustBase.Load().Epoch, "nothing was installed")
	})
	t.Run("a proof that is not what its epoch signs is refused even when its signatures are authentic", func(t *testing.T) {
		h := newSecondHandoff(t, source, signers, true)
		require.NoError(t, h.root.trustBaseStore.ActivateSigning(2, domainBoundConfig()))
		bad := h.proof
		qc := *h.proof.CommitQC
		qc.SealSignatures = nil
		bad.CommitQC = &qc
		_, err := h.root.InstallEpochGenesis(bad, h.head, h.body)
		require.ErrorIs(t, err, votesig.ErrSignerSets)
	})
}

// The frontier sampler and collector verify the covering QC in the form of the sampled epoch.
func TestFrontierQCIsVerifiedInTheFormOfTheSampledEpoch(t *testing.T) {
	c := newPairedCommittee(t)
	tb, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	_, root := committedBlock(t)
	quorum, err := c.store.GetByEpoch(2)
	require.NoError(t, err)
	r := NewVoteRegister()
	var qc *drctypes.QuorumCert
	for _, id := range []string{"1", "2", "3"} {
		qc, err = r.InsertVote(c.vote(t, id, root), quorum)
		require.NoError(t, err)
	}
	require.NotNil(t, qc)
	qc.LedgerCommitInfo.Epoch, qc.LedgerCommitInfo.NetworkID = 2, tb.NetworkID
	// the covering QC must be non-genesis and commit-capable: its vote round is the commit round plus one
	require.NoError(t, verifyFrontierQC(qc, tb, c.cfg, 0, 0))
	require.ErrorIs(t, verifyFrontierQC(qc, tb, votesig.Config{}, 0, 0), votesig.ErrScheme, "the legacy configuration refuses a scheme 2 certificate")
}
