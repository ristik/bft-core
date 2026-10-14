package consensus

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// One committee of four, one UTB epoch, scheme 2: each member's safety module makes the committing vote of the handoff round, the register aggregates
// the votes into a certificate, the certificate verifies by the epoch's rule and satisfies the executed-state binding; each tampering is refused at the
// check that owns it.
func TestHandoffCommittingRoundEndToEnd(t *testing.T) {
	cfg := votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, UTB: true}
	cfg.Genesis[0] = 9
	ids := []string{"1", "2", "3", "4"}
	signers := map[string]abcrypto.Signer{}
	var nodes []*types.NodeInfo
	for i, id := range ids {
		s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(bytes.Repeat([]byte{byte(i + 1)}, 32))
		require.NoError(t, err)
		v, _ := s.Verifier()
		k, _ := v.MarshalPublicKey()
		signers[id] = s
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: k, Stake: 1})
	}
	store, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	tb, err := types.NewTrustBase(5, nodes, types.WithEpoch(1), types.WithEpochStart(1))
	require.NoError(t, err)
	for _, id := range ids {
		require.NoError(t, tb.Sign(id, signers[id]))
	}
	require.NoError(t, store.Store(tb))
	require.NoError(t, store.ActivateSigning(1, cfg))

	entry := unsignedEntry(t, 0x22) // the entry the members' executed state implies (epoch 2, network 5)
	executed := CommittedBlockInfo{Epoch: 1, RootHash: bytes.Repeat([]byte{7}, 32), Timestamp: 4242}
	var votes []*abdrc.VoteMsg
	for _, id := range ids {
		db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), id+".db"), storage.WithNoSync())
		require.NoError(t, err)
		t.Cleanup(func() { _ = db.Close() })
		m, err := NewSafetyModule(5, id, signers[id], db, WithDomainBoundSigning(store, func(uint64) (CommittedBlockInfo, error) { return executed, nil }),
			WithUTB(func(*drctypes.RoundInfo, uint64) ([]byte, error) { return entry, nil }))
		require.NoError(t, err)
		info := &drctypes.RoundInfo{Version: 1, RoundNumber: 4, Epoch: 1, ParentRoundNumber: 3, Timestamp: 99, CurrentRootHash: executed.RootHash}
		qc, err := newQuorumCertificate(t, info, nil)
		require.NoError(t, err)
		block := &drctypes.BlockData{Round: 5, Epoch: 1, Timestamp: 5000, Qc: qc}
		v, err := m.MakeVote(block, bytes.Repeat([]byte{1}, 32), nil, nil)
		require.NoError(t, err)
		votes = append(votes, v)
		// the members' votes also round-trip the wire
		raw, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		var back abdrc.VoteMsg
		require.NoError(t, types.Cbor.Unmarshal(raw, &back))
		require.Equal(t, v.UTB, back.UTB)
	}

	q, err := store.GetByEpoch(1)
	require.NoError(t, err)
	reg := NewVoteRegister()
	var qc *drctypes.QuorumCert
	for _, v := range votes[:3] {
		qc, err = reg.InsertVote(v, q)
		require.NoError(t, err)
	}
	require.NotNil(t, qc)
	require.NotNil(t, qc.UTB)
	require.Len(t, qc.UTB.Signatures, 3)
	require.NoError(t, qc.VerifyWith(store), "the certificate verifies by the epoch's rule, endorsement included")

	binding := storage.NewUTBBinding(store.SigningConfig, func(*drctypes.RoundInfo, uint64) ([]byte, error) { return entry, nil })
	require.NoError(t, binding(qc))

	t.Run("another entry than the executed state implies", func(t *testing.T) {
		other := storage.NewUTBBinding(store.SigningConfig, func(*drctypes.RoundInfo, uint64) ([]byte, error) { return unsignedEntry(t, 0x44), nil })
		require.ErrorIs(t, other(qc), storage.ErrUTBBinding)
		require.NoError(t, qc.VerifyWith(store), "the certificate itself is cryptographically fine: only the execution context refuses it")
	})
	t.Run("the endorsement stripped", func(t *testing.T) {
		stripped := *qc
		stripped.UTB = nil
		require.NoError(t, stripped.VerifyWith(store), "alone it is a valid version 3 certificate")
		require.ErrorIs(t, binding(&stripped), storage.ErrUTBBinding, "but the committed state implies an endorsement")
	})
	t.Run("an endorsement bound to other voters", func(t *testing.T) {
		forged := *qc
		forged.UTB = &drctypes.UTBCertificate{Unsigned: qc.UTB.Unsigned, Signatures: map[string]hex.Bytes{}}
		for id, sig := range qc.UTB.Signatures {
			forged.UTB.Signatures[id] = sig
		}
		forged.UTB.Signatures["4"] = votes[3].UTB.Signature
		delete(forged.UTB.Signatures, "1")
		require.Error(t, forged.VerifyWith(store))
	})
}
