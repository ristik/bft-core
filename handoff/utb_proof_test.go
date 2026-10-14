package handoff_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// The historical proof of a handoff out of a UTB epoch carries the old committee's endorsement of the successor entry, and every verifier of the proof
// (the installers, the shard follower, the closure and the Q3 history all call VerifyOldCommitProofSigning) refuses one that does not.
func TestOldCommitProofOfAUTBEpochMustBeEndorsed(t *testing.T) {
	f := handoffbundle.New(t)
	cfg := votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(f.Old.NetworkID), UTB: true}
	handoffbundle.WithUTB(t, f)
	f.Proof.CommitQC.Scheme = 0

	_, err := handoff.VerifyOldCommitProofSigning(f.Proof, f.Old, cfg)
	require.NoError(t, err, "the endorsed proof verifies")

	with := func(mut func(qc *rctypes.QuorumCert)) error {
		p := f.Proof
		qc := *p.CommitQC
		if qc.UTB != nil {
			cert := *qc.UTB
			cert.Signatures = map[string]hex.Bytes{}
			for k, v := range p.CommitQC.UTB.Signatures {
				cert.Signatures[k] = v
			}
			qc.UTB = &cert
		}
		mut(&qc)
		p.CommitQC = &qc
		_, err := handoff.VerifyOldCommitProofSigning(p, f.Old, cfg)
		return err
	}
	for name, mut := range map[string]func(qc *rctypes.QuorumCert){
		"the committing certificate without the endorsement": func(qc *rctypes.QuorumCert) { qc.UTB = nil },
		"a version 1/2 certificate":                          func(qc *rctypes.QuorumCert) { qc.Envelope, qc.UTB = 0, nil },
		"an endorser that did not sign the certificate": func(qc *rctypes.QuorumCert) {
			qc.UTB.Signatures[f.Nodes[0].PeerConf.ID.String()] = qc.UTB.Signatures[f.OldNodes[0].PeerConf.ID.String()]
		},
		"one invalid endorsement among a quorum": func(qc *rctypes.QuorumCert) {
			for id, sig := range qc.UTB.Signatures {
				bad := append([]byte(nil), sig...)
				bad[3] ^= 1
				qc.UTB.Signatures[id] = bad
				break
			}
		},
		"another entry": func(qc *rctypes.QuorumCert) {
			qc.UTB.Unsigned = append([]byte(nil), qc.UTB.Unsigned...)
			qc.UTB.Unsigned[len(qc.UTB.Unsigned)-2] ^= 1
		},
	} {
		t.Run(name, func(t *testing.T) { require.ErrorIs(t, with(mut), handoff.ErrProof) })
	}

	t.Run("an epoch that is not a UTB epoch refuses the endorsed envelope", func(t *testing.T) {
		_, err := handoff.VerifyOldCommitProofSigning(f.Proof, f.Old, votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(f.Old.NetworkID)})
		require.ErrorIs(t, err, handoff.ErrProof)
		require.ErrorIs(t, err, votesig.ErrEnvelope)
	})
}
