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
