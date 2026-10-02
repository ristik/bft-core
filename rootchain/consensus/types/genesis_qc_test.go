package types

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

// genesisQC is the QC of the genesis round as the software builds it (storage.NewGenesisBlock): the vote info of round 1, a commit info that
// names the same round, epoch, time and root, and no signatures.
func genesisQC(t *testing.T, rootHash []byte) *QuorumCert {
	t.Helper()
	info := &RoundInfo{Version: 1, RoundNumber: GenesisRootRound, Epoch: GenesisRootEpoch, Timestamp: types.GenesisTime, CurrentRootHash: rootHash}
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	return &QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: GenesisRootRound,
		Epoch: GenesisRootEpoch, Timestamp: types.GenesisTime, Hash: rootHash, PreviousHash: h}}
}

// The only round-1 QC that verifies without signatures is the local genesis QC. Any other, however consistent its hashes, is refused with the
// typed error (a peer chooses every field of a QC it sends).
func TestQuorumCert_VerifyRoundOne(t *testing.T) {
	sb := newStructBuilder(t, 3)
	rootTrust, err := sb.trustBaseStore.LoadFirst()
	require.NoError(t, err)
	local := genesisQC(t, []byte{1, 2, 3})
	pin, err := GenesisPinOf(local)
	require.NoError(t, err)

	require.NoError(t, genesisQC(t, []byte{1, 2, 3}).Verify(rootTrust, pin), "the local genesis QC, as a peer would send it")
	require.NoError(t, local.Verify(rootTrust, pin))

	for name, tc := range map[string]struct {
		qc   func() *QuorumCert
		pins []*trustbase.GenesisPin
	}{
		"the genesis QC without a pin (nothing says it is the local one)": {qc: func() *QuorumCert { return genesisQC(t, []byte{1, 2, 3}) }},
		"a nil pin":                            {qc: func() *QuorumCert { return genesisQC(t, []byte{1, 2, 3}) }, pins: []*trustbase.GenesisPin{nil}},
		"another root hash, hashes consistent": {qc: func() *QuorumCert { return genesisQC(t, []byte{9, 9, 9}) }, pins: []*trustbase.GenesisPin{pin}},
		"another vote info time": {qc: func() *QuorumCert {
			q := genesisQC(t, []byte{1, 2, 3})
			q.VoteInfo.Timestamp++
			h, err := q.VoteInfo.Hash(crypto.SHA256)
			require.NoError(t, err)
			q.LedgerCommitInfo.PreviousHash = h
			return q
		}, pins: []*trustbase.GenesisPin{pin}},
		"the right vote info but another commit info": {qc: func() *QuorumCert {
			q := genesisQC(t, []byte{1, 2, 3})
			q.LedgerCommitInfo.NetworkID++
			return q
		}, pins: []*trustbase.GenesisPin{pin}},
		"a round-1 QC signed by the whole quorum (no such QC exists)": {qc: func() *QuorumCert { return sb.QC(t, GenesisRootRound) }, pins: []*trustbase.GenesisPin{pin}},
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, tc.qc().Verify(rootTrust, tc.pins...), ErrNotGenesisQC)
		})
	}

	t.Run("signatures on the genesis QC are not part of its identity", func(t *testing.T) {
		q := genesisQC(t, []byte{1, 2, 3})
		q.Signatures = map[string]hex.Bytes{"x": {1}}
		q.LedgerCommitInfo.Signatures = map[string]hex.Bytes{"x": {1}}
		require.NoError(t, q.Verify(rootTrust, pin))
	})

	t.Run("a QC of another round is unaffected by the pin", func(t *testing.T) {
		require.NoError(t, sb.QC(t, 2).Verify(rootTrust, pin))
		require.NoError(t, sb.QC(t, 2).Verify(rootTrust))
	})
}

// A pin is made of a genesis QC only: the commit QC a block carries once committed (a later round) is refused by its round.
func TestGenesisPinOfRefusesANonGenesisRound(t *testing.T) {
	genuine := genesisQC(t, []byte{1})
	_, err := GenesisPinOf(genuine)
	require.NoError(t, err)

	later := *genuine
	info := *genuine.VoteInfo
	info.RoundNumber = GenesisRootRound + 1
	later.VoteInfo = &info
	_, err = GenesisPinOf(&later)
	require.ErrorIs(t, err, ErrPinNotGenesisRound)
}
