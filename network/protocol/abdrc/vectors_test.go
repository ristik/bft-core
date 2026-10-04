package abdrc

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// vectorsFile is the golden fixture the cross-language verifier (S1) consumes: fixed keys, the semantic inputs, the exact
// signed bytes, their digest, the signatures and the wire bytes, for each preimage version. It is generated here from the
// semantic inputs, deterministically (fixed keys, RFC 6979 signatures) and committed; the test fails when the committed bytes
// and the regenerated ones differ, and VECTORS_UPDATE=1 rewrites it after an intentional change.
const vectorsFile = "testdata/domain_bound_vectors.json"

type vector struct {
	Name      string            `json:"name"`
	Scheme    uint64            `json:"scheme"`
	Kind      string            `json:"kind"`
	Inputs    map[string]any    `json:"inputs"`
	Signed    string            `json:"signedBytesHex"`
	Digest    string            `json:"digestHex"`
	PublicKey string            `json:"publicKeyHex"`
	Signature map[string]string `json:"signaturesHex"`
	Wire      string            `json:"wireHex"`
	Extra     map[string]string `json:"derivedHex,omitempty"`
}

type vectorSet struct {
	Note    string   `json:"note"`
	Network uint64   `json:"network"`
	Genesis string   `json:"rootGenesisHex"`
	Vectors []vector `json:"vectors"`
}

func h(b []byte) string { return hex.EncodeToString(b) }

func dg(b []byte) string { d := votesig.Digest(b); return h(d[:]) }

func buildVectors(t *testing.T) vectorSet {
	t.Helper()
	f := newDBFixture(t)
	f.activate(t, 2)
	pub := func(id string) string {
		v, err := f.signers[id].Verifier()
		require.NoError(t, err)
		k, err := v.MarshalPublicKey()
		require.NoError(t, err)
		return h(k)
	}
	signTwice := func(id string, data []byte) []byte {
		a, err := f.signers[id].SignBytes(data)
		require.NoError(t, err)
		b, err := f.signers[id].SignBytes(data)
		require.NoError(t, err)
		require.Equal(t, a, b, "signatures must be deterministic for the vectors to be reproducible")
		return a
	}
	set := vectorSet{Note: "scheme 1 vectors freeze the legacy bytes; scheme 2 vectors are the domain-bound preimages (votesig). Signatures: secp256k1 over SHA-256(signedBytes), 65 bytes R||S||V.", Network: f.cfg.Network, Genesis: h(f.cfg.Genesis[:])}
	marshal := func(v any) string {
		b, err := types.Cbor.Marshal(v)
		require.NoError(t, err)
		return h(b)
	}
	high := f.legacyQC(t, 1, 11)

	// ---- scheme 1 (legacy), frozen
	lv := &VoteMsg{VoteInfo: high.VoteInfo, LedgerCommitInfo: high.LedgerCommitInfo, HighQc: nil, Author: "1"}
	seal, err := lv.LedgerCommitInfo.SigBytes()
	require.NoError(t, err)
	lv.Signature = signTwice("1", seal)
	lv.HighQc = high
	set.Vectors = append(set.Vectors, vector{Name: "legacy vote", Scheme: 1, Kind: "vote", Inputs: map[string]any{"author": "1", "epoch": 1, "round": 11}, Signed: h(seal), Digest: dg(seal),
		PublicKey: pub("1"), Signature: map[string]string{"vote": h(lv.Signature)}, Wire: marshal(lv)})
	lt := NewTimeoutMsg(drctypes.NewTimeout(12, 1, high), "2", nil)
	require.NoError(t, lt.Sign(f.signers["2"]))
	set.Vectors = append(set.Vectors, vector{Name: "legacy timeout", Scheme: 1, Kind: "timeout", Inputs: map[string]any{"author": "2", "epoch": 1, "round": 12, "highQcRound": 11}, Signed: h(lt.Bytes()), Digest: dg(lt.Bytes()),
		PublicKey: pub("2"), Signature: map[string]string{"timeout": h(lt.Signature)}, Wire: marshal(lt)})

	// ---- scheme 2
	for _, committing := range []bool{true, false} {
		v := f.voteV2(t, "1", 2, 12, committing, high)
		pv, sealBytes, _, err := v.domainBoundStatement(f.cfg)
		require.NoError(t, err)
		sigs := map[string]string{"vote": h(v.Signature)}
		derived := map[string]string{"voteInfoHash": h(v.LedgerCommitInfo.PreviousHash)}
		vi := votesig.VoteInfo{Epoch: 2, Round: 12, Parent: 11}
		copy(vi.Exec[:], v.VoteInfo.CurrentRootHash)
		viBytes, err := f.cfg.VoteInfoBytes(vi)
		require.NoError(t, err)
		derived["voteInfo"] = h(viBytes)
		name := "domain-bound non-committing vote"
		in := map[string]any{"author": "1", "epoch": 2, "round": 12, "parentRound": 11, "execStateHash": h(v.VoteInfo.CurrentRootHash), "commitStateHash": nil, "commitRound": 0}
		if committing {
			sigs["seal"] = h(v.SealSignature)
			derived["nativeSealSigBytes"] = h(sealBytes)
			name = "domain-bound committing vote"
			in["commitStateHash"], in["commitRound"] = h(v.LedgerCommitInfo.Hash), v.LedgerCommitInfo.RootChainRoundNumber
		}
		require.Equal(t, []byte(v.Signature), signTwice("1", pv))
		set.Vectors = append(set.Vectors, vector{Name: name, Scheme: 2, Kind: "vote", Inputs: in, Signed: h(pv), Digest: dg(pv), PublicKey: pub("1"), Signature: sigs, Wire: marshal(v), Extra: derived})
	}
	tm := f.timeoutV2(t, "2", 2, 12, high)
	pt, err := tm.Preimage(f.cfg)
	require.NoError(t, err)
	set.Vectors = append(set.Vectors, vector{Name: "domain-bound timeout", Scheme: 2, Kind: "timeout", Inputs: map[string]any{"author": "2", "epoch": 2, "round": 12, "highQcRound": 11, "anchor": nil},
		Signed: h(pt), Digest: dg(pt), PublicKey: pub("2"), Signature: map[string]string{"timeout": h(signTwice("2", pt))}, Wire: marshal(tm)})
	anchor := &drctypes.EpochAnchor{GenesisID: bytes.Repeat([]byte{7}, 32), Epoch: 2, Slot: 9, StateRoot: bytes.Repeat([]byte{8}, 32)}
	am := NewTimeoutMsg(drctypes.NewAnchorTimeout(10, anchor), "2", nil)
	require.NoError(t, am.SignDomainBound(f.signers["2"], f.cfg))
	apt, err := am.Preimage(f.cfg)
	require.NoError(t, err)
	set.Vectors = append(set.Vectors, vector{Name: "domain-bound anchor timeout", Scheme: 2, Kind: "timeout", Inputs: map[string]any{"author": "2", "epoch": 2, "round": 10, "highQcRound": 9, "anchor": map[string]any{"genesisId": h(anchor.GenesisID), "epoch": 2, "slot": 9}},
		Signed: h(apt), Digest: dg(apt), PublicKey: pub("2"), Signature: map[string]string{"timeout": h(am.Signature)}, Wire: marshal(am)})

	tc := &drctypes.TimeoutCert{Timeout: drctypes.NewTimeout(13, 2, f.legacyQC(t, 1, 11)), Signatures: map[string]*drctypes.TimeoutVote{}, Scheme: votesig.SchemeDomainBound}
	rounds := map[string]uint64{"1": 11, "2": 10, "3": 11, "4": 9}
	sigs := map[string]string{}
	for _, id := range f.ids {
		pt, err := tc.TimeoutPreimage(f.cfg, id, &drctypes.TimeoutVote{HqcRound: rounds[id]})
		require.NoError(t, err)
		sig := signTwice(id, pt)
		tc.Signatures[id] = &drctypes.TimeoutVote{HqcRound: rounds[id], Signature: sig}
		sigs[id] = h(sig)
	}
	require.NoError(t, tc.Verify(f.store))
	set.Vectors = append(set.Vectors, vector{Name: "domain-bound timeout certificate with different signer high QC rounds", Scheme: 2, Kind: "timeoutCertificate",
		Inputs: map[string]any{"epoch": 2, "round": 13, "highQcRoundsByAuthor": map[string]any{"1": 11, "2": 10, "3": 11, "4": 9}}, Signature: sigs, Wire: marshal(tc)})
	return set
}

func TestVectorsAreCommittedAndReproducible(t *testing.T) {
	want, err := json.MarshalIndent(buildVectors(t), "", "  ")
	require.NoError(t, err)
	want = append(want, '\n')
	again, err := json.MarshalIndent(buildVectors(t), "", "  ")
	require.NoError(t, err)
	require.Equal(t, want, append(again, '\n'), "generation is deterministic")
	if os.Getenv("VECTORS_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(vectorsFile, want, 0o644))
	}
	have, err := os.ReadFile(vectorsFile)
	require.NoError(t, err, "the vectors must be committed (VECTORS_UPDATE=1 go test -run TestVectors)")
	require.Equal(t, string(want), string(have), "committed vectors differ from the regenerated ones")
}

// Every committed vector is verified by the production verifiers, from the bytes alone.
func TestCommittedVectorsVerify(t *testing.T) {
	raw, err := os.ReadFile(vectorsFile)
	require.NoError(t, err)
	var set vectorSet
	require.NoError(t, json.Unmarshal(raw, &set))
	f := newDBFixture(t)
	f.activate(t, 2)
	require.Equal(t, h(f.cfg.Genesis[:]), set.Genesis)
	n := 0
	for _, v := range set.Vectors {
		wire, err := hex.DecodeString(v.Wire)
		require.NoError(t, err)
		switch v.Kind {
		case "vote":
			var m VoteMsg
			require.NoError(t, types.Cbor.Unmarshal(wire, &m), v.Name)
			require.EqualValues(t, v.Scheme, m.signingScheme(), v.Name)
			if v.Scheme == 2 {
				require.NoError(t, m.Verify(f.store), v.Name)
			} else {
				g := newDBFixture(t)
				require.NoError(t, m.Verify(g.store), v.Name)
			}
		case "timeout":
			var m TimeoutMsg
			require.NoError(t, types.Cbor.Unmarshal(wire, &m), v.Name)
			if v.Scheme == 2 {
				require.NoError(t, m.Verify(f.store), v.Name)
			} else {
				g := newDBFixture(t)
				require.NoError(t, m.Verify(g.store), v.Name)
			}
		case "timeoutCertificate":
			var tc drctypes.TimeoutCert
			require.NoError(t, types.Cbor.Unmarshal(wire, &tc), v.Name)
			require.NoError(t, tc.Verify(f.store), v.Name)
		default:
			t.Fatalf("unknown vector kind %q", v.Kind)
		}
		n++
	}
	require.Equal(t, 7, n)
}
