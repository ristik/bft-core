package rootevidence

import (
	"encoding/hex"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
)

// The selectors below were produced by `forge inspect <contract> methodIdentifiers|errors` at unicity-pos-contracts 07891a6 (src/p85/Evidence.sol,
// src/p85/StakeCustody.sol, src/SealRegistry.sol). A name, tuple shape or argument type of this package's ABI that differs from the deployed
// contracts' changes the selector, so it fails here, not on a live chain.
func TestABIMatchesTheContracts(t *testing.T) {
	for _, c := range []struct {
		abi  abi.ABI
		name string
		want string
	}{
		{evidenceAbi, "submitEvidence", "528bccf8"},
		{evidenceAbi, "settleEvidence", "df4764c3"},
		{evidenceAbi, "offenceIDOf", "31b8e682"},
		{evidenceAbi, "offenceSeen", "e6740265"},
		{evidenceAbi, "network", "6739afca"},
		{evidenceAbi, "rootNetwork", "c6050105"},
		{evidenceAbi, "rootGenesis", "fdfe061b"},
		{evidenceAbi, "maxBatch", "67765b87"},
		{evidenceAbi, "custody", "dda79b75"},
		{evidenceAbi, "roots", "393fe1cd"},
		{evidenceAbi, "caseInfo", "92cc5551"},
		{custodyAbi, "assignmentExposures", "b40fe7d4"},
		{custodyAbi, "exposures", "ef1c0688"},
		{custodyAbi, "exposureLots", "c03e0a67"},
		{custodyAbi, "assignments", "82c2901c"},
		{custodyAbi, "policyTerms", "b1393267"},
		{rootsAbi, "progress", "577bd336"},
	} {
		m, ok := c.abi.Methods[c.name]
		require.True(t, ok, c.name)
		require.Equal(t, c.want, hex.EncodeToString(m.ID), c.name)
	}
	for name, want := range map[string]string{
		"EvidenceLate": "420290a2", "DuplicateOffence": "087c0edd", "AssignmentNotActivated": "0755cea5", "RoundBeforeEpoch": "9dd7b036",
		"ExposureUnknown": "8111ea64", "NotAttributable": "66c75491", "KeyMismatch": "839e2ccd", "EpochMismatch": "af2cbcf0",
		"BadSignature": "5cd5d233", "IdenticalStatements": "f6b0086a", "BadStatement": "a1f115fd", "CommitMismatch": "c6841179",
		"SealSignatureMissing": "4350445a", "SealSignatureForbidden": "4e30418b", "WrongNetwork": "9160e9ce", "BadDomain": "9d135ed2",
		"CaseSettled": "a266b211", "NotNextLot": "5f19d9af", "UnknownCase": "0d34f119",
	} {
		e, ok := evidenceAbi.Errors[name]
		require.True(t, ok, name)
		require.Equal(t, want, hex.EncodeToString(e.ID[:4]), name)
	}
}
