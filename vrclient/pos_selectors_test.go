package vrclient

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/ethereum/go-ethereum/accounts/abi"
)

// The selectors of the PoS prototype's contracts as the compiled artifacts report them (forge inspect methodIdentifiers on unicity-pos-contracts
// 3c95339 and later: ElectionPolicy, StakeCustody and the PoS-capable ValidatorRegistryPos). The CLI's ABIs must produce exactly these; a lane run
// must never be spent on an ABI error.
func TestThePoSABIsMatchTheCompiledSelectors(t *testing.T) {
	cases := []struct {
		a      abi.ABI
		method string
		want   string
	}{
		{PosElectionABI, "admitDelegation", "d99a0d2f"},
		{PosElectionABI, "delegation", "28fef7fd"},
		{PosElectionABI, "delegationDigest", "2640c08f"},
		{PosPublishABI, "finalizeCandidate", "ce48313e"},
		{PosPublishABI, "frozenMembers", "046b9998"},
		{PosPublishABI, "openResult", "5552dcb8"},
		{PosPublishABI, "popDigest", "d9d6b15a"},
		{PosPublishABI, "submitAssignmentPoPs", "ac7931b4"},
		{PosPublishABI, "publish", "8b2e6dcf"},
		{PosPublishABI, "publication", "f1d81f14"},
		{CustodyABI, "bond", "6b0432ef"},
		{CustodyABI, "bondUnit", "39f320cc"},
		{CustodyABI, "claim", "ddd5e1b2"},
		{CustodyABI, "credit", "d5d44d80"},
		{CustodyABI, "election", "4b1d3ede"},
		{CustodyABI, "generationLots", "57ac7373"},
		{CustodyABI, "mature", "6041bcfb"},
		{CustodyABI, "network", "6739afca"},
		{CustodyABI, "positions", "60f3ce04"},
		{CustodyABI, "register", "703a60cd"},
		{CustodyABI, "registerNonce", "c8e07834"},
		{CustodyABI, "requestRetirement", "b9fbfe66"},
	}
	for _, c := range cases {
		m, ok := c.a.Methods[c.method]
		require.True(t, ok, c.method)
		require.Equal(t, c.want, hex.EncodeToString(m.ID), c.method)
	}
}

// The election's publication view decodes into PublicationRecord field by field.
func TestPublicationViewDecodes(t *testing.T) {
	out := PosPublishABI.Methods["publication"].Outputs
	type tup struct {
		PrimaryHash, KCommit, Incumbent, IncumbentExposureDigest, IncumbentKeyDigest, PolicyDigest, ContractsDigest, SnapshotDigest, AssignmentID, PopSetDigest [32]byte
		Published                                                                                                                                               bool
		PopCount                                                                                                                                                uint32
		Attempt                                                                                                                                                 uint64
		Lost                                                                                                                                                    bool
	}
	raw, err := out.Pack(tup{PrimaryHash: [32]byte{1}, Published: true, PopCount: 4, Attempt: 2})
	require.NoError(t, err)
	vals, err := out.Unpack(raw)
	require.NoError(t, err)
	p := *abi.ConvertType(vals[0], new(PublicationRecord)).(*PublicationRecord)
	require.True(t, p.Published)
	require.Equal(t, uint32(4), p.PopCount)
	require.Equal(t, [32]byte{1}, p.PrimaryHash)
}
