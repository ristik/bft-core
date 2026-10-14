package certification_test

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/utbchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

var updateVectors = flag.Bool("update-ucresp-vectors", false, "rewrite testdata/ucresp_v2_vectors.json")

const vectorsFile = "testdata/ucresp_v2_vectors.json"

// vectors is the reference fixture for another implementation of the shard side (aggregator-go): a deterministic chain of signed trust-base entries
// (fixed keys, RFC 6979 signatures) and the version 2 certification responses that carry it. docs/pos/utb-ucresp.md says how to use it.
type vectors struct {
	Protocol         string   `json:"protocol"`
	GenesisEntry     string   `json:"genesisEntry"`
	GenesisEntryID   string   `json:"genesisEntryId"`
	Entries          []string `json:"entries"`          // epochs 2, 3, 4
	EntryIDs         []string `json:"entryIds"`         // their EntryIDs (SHA-256 of the unsigned bytes)
	AcceptedTwo      string   `json:"acceptedTwo"`      // status OK, entries of epochs 2 and 3
	RejectedOne      string   `json:"rejectedOne"`      // status RequestInvalid with the entry of epoch 4
	AcceptedNone     string   `json:"acceptedNone"`     // status OK, no entries
	LegacyEquivalent string   `json:"legacyEquivalent"` // the legacy (/ab/certificates/0.0.1) encoding of the accepted response
}

func buildVectors(t *testing.T) vectors {
	chain := utbchain.New(t, 4)
	base := &certification.CertificationResponse{Partition: 1,
		UC: types.UnicityCertificate{Version: 1, UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1}}}
	require.NoError(t, base.SetTechnicalRecord(certification.TechnicalRecord{Round: 99, Epoch: 2, Leader: "1", StatHash: []byte{1}, FeeHash: []byte{2}}))
	enc := func(v any) string {
		raw, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		return hex.EncodeToString(raw)
	}
	gRaw, err := chain.Genesis.MarshalCBOR()
	require.NoError(t, err)
	gid, err := chain.Genesis.EntryID()
	require.NoError(t, err)
	v := vectors{Protocol: "/ab/certificates/0.0.2", GenesisEntry: hex.EncodeToString(gRaw), GenesisEntryID: hex.EncodeToString(gid[:])}
	for _, raw := range chain.Entries {
		v.Entries = append(v.Entries, hex.EncodeToString(raw))
		e, err := types.DecodeRootTrustBaseV2(raw)
		require.NoError(t, err)
		id, err := e.EntryID()
		require.NoError(t, err)
		v.EntryIDs = append(v.EntryIDs, hex.EncodeToString(id[:]))
	}
	v.AcceptedTwo = enc(certification.NewCertificationResponseV2(base, chain.Entries[:2]))
	v.AcceptedNone = enc(certification.NewCertificationResponseV2(base, nil))
	rejected := *base
	rejected.Status, rejected.Message = certification.CertStatusRequestInvalid, "stale round"
	v.RejectedOne = enc(certification.NewCertificationResponseV2(&rejected, chain.Entries[2:3]))
	v.LegacyEquivalent = enc(base)
	return v
}

func TestUCRespV2ReferenceVectorsAreFrozen(t *testing.T) {
	got := buildVectors(t)
	if *updateVectors {
		raw, err := json.MarshalIndent(got, "", "  ")
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(vectorsFile, append(raw, '\n'), 0o644))
	}
	raw, err := os.ReadFile(vectorsFile)
	require.NoError(t, err, "run with -update-ucresp-vectors to create it")
	var want vectors
	require.NoError(t, json.Unmarshal(raw, &want))
	require.Equal(t, want, got)
}

// What a shard implementation does with the fixture, step by step: decode strictly, authenticate the entries from the pinned genesis, check the legacy view.
func TestUCRespV2ReferenceVectorsBehaveAsDocumented(t *testing.T) {
	raw, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	var v vectors
	require.NoError(t, json.Unmarshal(raw, &v))
	dec := func(s string) []byte {
		b, err := hex.DecodeString(s)
		require.NoError(t, err)
		return b
	}
	genesis, err := types.DecodeRootTrustBaseV2(dec(v.GenesisEntry))
	require.NoError(t, err)
	require.NoError(t, genesis.VerifyGenesis())

	var two certification.CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(dec(v.AcceptedTwo), &two))
	prev := genesis
	for i, u := range two.TrustBaseUpdates {
		e, err := types.DecodeRootTrustBaseV2(u)
		require.NoError(t, err)
		require.NoError(t, e.VerifySuccessor(prev), "entry %d authenticates from its predecessor", i)
		id, _ := e.EntryID()
		require.Equal(t, v.EntryIDs[i], hex.EncodeToString(id[:]))
		prev = e
	}
	require.NoError(t, two.Response().IsValid())

	var rejected certification.CertificationResponseV2
	require.NoError(t, types.Cbor.Unmarshal(dec(v.RejectedOne), &rejected))
	require.False(t, rejected.Response().IsAccepted())
	e4, err := types.DecodeRootTrustBaseV2(rejected.TrustBaseUpdates[0])
	require.NoError(t, err)
	require.Error(t, e4.VerifySuccessor(genesis), "epoch 4 does not follow the genesis: the receiver is missing epochs 2 and 3 and fetches them")

	var legacy certification.CertificationResponse
	require.NoError(t, types.Cbor.Unmarshal(dec(v.LegacyEquivalent), &legacy))
	require.Equal(t, two.Response().Technical.Round, legacy.Technical.Round)
}
