package posrelayer

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-go-base/types"
)

const fixturePath = "../rootchain/evmstate/testdata/publication.json"

// recorded serves the builder from what the real modules answered (unicity-pos-contracts PublicationFixture.t.sol, "relayerReads"): the
// exact calldata and return data of the getters the builder reads, at the published state. A call outside the record fails the test.
type recorded struct {
	t      *testing.T
	reads  map[string][]byte
	asked  map[string]bool
	tamper func(to [20]byte, data, ret []byte) []byte
}

func newRecorded(t *testing.T) (*recorded, Modules) {
	raw, err := os.ReadFile(fixturePath)
	require.NoError(t, err)
	var fx struct {
		Deployment struct {
			Election, Custody string
		}
		RelayerReads []struct{ To, Data, Ret string }
	}
	require.NoError(t, json.Unmarshal(raw, &fx))
	// the fixture's deployment names the election and custody; the recorded reads carry their addresses too
	r := &recorded{t: t, reads: map[string][]byte{}, asked: map[string]bool{}}
	for _, c := range fx.RelayerReads {
		ret, err := hex.DecodeString(strings.TrimPrefix(c.Ret, "0x"))
		require.NoError(t, err)
		r.reads[strings.ToLower(c.To)+strings.ToLower(c.Data)] = ret
	}
	var m Modules
	e, err := hex.DecodeString(strings.TrimPrefix(fx.Deployment.Election, "0x"))
	require.NoError(t, err)
	c, err := hex.DecodeString(strings.TrimPrefix(fx.Deployment.Custody, "0x"))
	require.NoError(t, err)
	copy(m.Election[:], e)
	copy(m.Custody[:], c)
	return r, m
}

func (r *recorded) Call(_ context.Context, to [20]byte, data []byte) ([]byte, error) {
	key := "0x" + hex.EncodeToString(to[:]) + "0x" + hex.EncodeToString(data)
	ret, ok := r.reads[strings.ToLower(key)]
	if !ok {
		r.t.Fatalf("the builder read something the contracts fixture did not record: %s", key)
	}
	r.asked[key] = true
	if r.tamper != nil {
		return r.tamper(to, data, bytes.Clone(ret)), nil
	}
	return ret, nil
}

// namesOf names the node-id words the recorded delegations hold ("root-a", "evm-a", ...), the way the fixture's identity records name them.
func namesOf(t *testing.T, r *recorded) Names {
	n := Names{}
	i := 0
	for key, ret := range r.reads {
		data := key[len("0x")+40:] // after the address
		if !strings.HasPrefix(data, "0x"+hex.EncodeToString(election.Methods["delegation"].ID)) {
			continue
		}
		out, err := election.Unpack("delegation", ret)
		require.NoError(t, err)
		d, err := decode[delegationView](out[0])
		require.NoError(t, err)
		if _, ok := n[d.RootNodeID]; !ok {
			n[d.RootNodeID] = "root-" + string(rune('a'+i))
			n[d.EvmNodeID] = "evm-" + string(rune('a'+i))
			i++
		}
	}
	return n
}

func rootContext(t *testing.T, k []evmassign.Identity) RootContext {
	var infos []*types.NodeInfo
	for _, x := range k {
		infos = append(infos, &types.NodeInfo{NodeID: x.EVMNodeID, SigKey: x.EVMKey, Stake: x.Weight})
	}
	conf := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Validators: infos, EpochStart: 1}
	return RootContext{Network: 5, Chain: 31337, Predecessor: bytes.Repeat([]byte{7}, 32), Acknowledged: conf}
}

// buildFixture builds the proposal inputs of the fixture's published result, reading the incumbent's identities first only to name the root
// context (the test's stand-in for what `root handoff evm-context` reports).
func buildFixture(t *testing.T, r *recorded, m Modules, names Names) (*Output, RootContext) {
	p := evmstatetest.Load(t, fixturePath)
	root := rootContext(t, p.Candidate.Authorization.K)
	out, err := Build(context.Background(), r, m, p.ResultID, root, names)
	require.NoError(t, err)
	return out, root
}

func sameRecord(t *testing.T, want, got evmassign.Identity, what string) {
	// the builder resolves node ids from the operator's names, so compare everything else
	want.RootNodeID, want.EVMNodeID, got.RootNodeID, got.EVMNodeID = "", "", "", ""
	require.Equal(t, want, got, what)
}

// The builder's output is accepted by the real verification route: the identity records, the recovery authorization and the possession
// proofs it assembles satisfy evmassign.VerifyPrimary against the facts proven from the certified state, with no hand-built candidate.
func TestBuiltInputsAreAcceptedByTheRealVerifyPrimary(t *testing.T) {
	r, m := newRecorded(t)
	names := namesOf(t, r)
	require.NotEmpty(t, names)
	p := evmstatetest.Load(t, fixturePath)
	out, _ := buildFixture(t, r, m, names)

	require.Equal(t, p.ResultID, out.ResultID)
	require.Len(t, out.Identities, len(p.Candidate.Identities))
	for i := range out.Identities {
		sameRecord(t, p.Candidate.Identities[i], out.Identities[i], "the primary's identity record")
	}
	require.Len(t, out.Authorization.K, len(p.Candidate.Authorization.K))
	for i := range out.Authorization.K {
		sameRecord(t, p.Candidate.Authorization.K[i], out.Authorization.K[i], "K")
	}
	require.Len(t, out.Validators, len(out.Identities))
	require.Len(t, out.Bindings, len(out.Identities))
	for _, v := range out.Validators {
		require.NotZero(t, v.Stake)
	}

	cand := evmassign.Candidate{Kind: evmassign.KindPrimary, Identities: out.Identities, Authorization: out.Authorization}
	require.NoError(t, evmassign.VerifyPrimary(cand, p.Deployment, p.Facts, p.PoPs), "the builder's records are the ones the election committed")
	// the digests the pipeline hashes are well-formed
	_, err := out.Authorization.Digest()
	require.NoError(t, err)
	_, err = evmassign.IdentitiesDigest(out.Identities)
	require.NoError(t, err)
	// the stored possession-proof hashes are the hashes of the signatures the fixture submitted
	for _, pop := range p.PoPs {
		h := out.PopHashes[pop.ID]
		require.Equal(t, h[:], keccak(pop.Signature), "pop hash of member %d", pop.ID)
	}
	// the election's open result is read by the CLI before Build: part of the same surface
	open, err := OpenResult(context.Background(), r, m)
	require.NoError(t, err)
	require.Equal(t, p.ResultID, open)
	var unused []string
	for k := range r.reads {
		if !r.asked[k] {
			unused = append(unused, k[:12+40]+"…"+k[len(k)-8:])
		}
	}
	require.Empty(t, unused, "the fixture records exactly the builder's read surface")
}

// A tool that lies is refused by the root, not trusted: each tampering of the builder's output is rejected by the real VerifyPrimary with
// a distinct cause.
func TestATamperedBuilderOutputIsRefusedByTheRealVerifyPrimary(t *testing.T) {
	r, m := newRecorded(t)
	p := evmstatetest.Load(t, fixturePath)
	out, _ := buildFixture(t, r, m, namesOf(t, r))
	verify := func(ids []evmassign.Identity, a *evmassign.Authorization) error {
		return evmassign.VerifyPrimary(evmassign.Candidate{Kind: evmassign.KindPrimary, Identities: ids, Authorization: a}, p.Deployment, p.Facts, p.PoPs)
	}
	require.NoError(t, verify(out.Identities, out.Authorization))

	clone := func() ([]evmassign.Identity, *evmassign.Authorization) {
		ids := append([]evmassign.Identity(nil), out.Identities...)
		a := *out.Authorization
		a.K = append([]evmassign.Identity(nil), out.Authorization.K...)
		return ids, &a
	}
	ids, a := clone()
	ids[0].OperatorPayee = bytes.Repeat([]byte{9}, 20)
	require.ErrorIs(t, verify(ids, a), evmassign.ErrPrimaryIdentities, "another payee")
	ids, a = clone()
	ids[1].ExposureDigest = bytes.Repeat([]byte{9}, 32)
	require.ErrorIs(t, verify(ids, a), evmassign.ErrPrimaryIdentities, "another lot set")
	ids, a = clone()
	a.K[0].OperatorPayee = bytes.Repeat([]byte{9}, 20)
	require.ErrorIs(t, verify(ids, a), evmassign.ErrPrimaryRecovery, "a K that is not the incumbent committee")
	ids, a = clone()
	a.Policies = bytes.Repeat([]byte{9}, 32)
	require.ErrorIs(t, verify(ids, a), evmassign.ErrPrimaryBinding, "other captured policies")
}

// firstExposure adds delta to word w of the first exposure the builder reads (the primary's first member), leaving every other answer intact.
func firstExposure(w int, delta byte) func(to [20]byte, data, ret []byte) []byte {
	done := false
	return func(_ [20]byte, data, ret []byte) []byte {
		if !done && bytes.HasPrefix(data, custody.Methods["exposures"].ID) {
			done = true
			ret[32*w+31] += delta
		}
		return ret
	}
}

// The records carry what the chain says: with a raw weight above the committed one (a quantized committee) the builder reports both, and the
// root's check then judges them, not the builder.
func TestTheBuilderReportsTheRawWeightTheChainCommitted(t *testing.T) {
	r, m := newRecorded(t)
	p := evmstatetest.Load(t, fixturePath)
	done, frozenDone := false, false
	r.tamper = func(_ [20]byte, data, ret []byte) []byte {
		switch {
		case !done && bytes.HasPrefix(data, custody.Methods["exposures"].ID):
			done = true
			ret[32*4+31] += 5 // rawWeight of the first exposure
		case !frozenDone && bytes.HasPrefix(data, election.Methods["frozenMembers"].ID):
			frozenDone = true
			ret[32*5+31] += 5 // raw of the first frozen member
		}
		return ret
	}
	root := rootContext(t, p.Candidate.Authorization.K)
	out, err := Build(context.Background(), r, m, p.ResultID, root, namesOf(t, r))
	require.NoError(t, err)
	require.Equal(t, out.Identities[0].Weight+5, out.Identities[0].RawWeight, "x is reported beside q")
	cand := evmassign.Candidate{Kind: evmassign.KindPrimary, Identities: out.Identities, Authorization: out.Authorization}
	require.ErrorIs(t, evmassign.VerifyPrimary(cand, p.Deployment, p.Facts, p.PoPs), evmassign.ErrPrimaryIdentities,
		"the root refuses records that are not the proven ones, whatever the builder read")
}

func TestTheBuilderRefusesWhatItCannotBuild(t *testing.T) {
	p := evmstatetest.Load(t, fixturePath)
	for name, tc := range map[string]struct {
		tamper func(to [20]byte, data, ret []byte) []byte
		names  func(Names) Names
		want   error
	}{
		"a delegation key that custody did not commit": {tamper: func(_ [20]byte, data, ret []byte) []byte {
			if bytes.HasPrefix(data, election.Methods["delegation"].ID) {
				ret[len(ret)-150] ^= 1 // inside the dynamic key bytes
			}
			return ret
		}, want: ErrBuild},
		"a node id the operator did not name": {names: func(n Names) Names {
			for w := range n {
				delete(n, w)
				break
			}
			return n
		}, want: ErrUnknownNode},
		"an unpublished result": {tamper: func(_ [20]byte, data, ret []byte) []byte {
			if bytes.HasPrefix(data, election.Methods["publication"].ID) {
				ret[32*10+31] = 0 // published = false
			}
			return ret
		}, want: ErrBuild},
		"a result that lost a member's coverage": {tamper: func(_ [20]byte, data, ret []byte) []byte {
			if bytes.HasPrefix(data, election.Methods["publication"].ID) {
				ret[32*13+31] = 1
			}
			return ret
		}, want: ErrBuild},
		"an exposure whose weight is not the election's frozen one":     {tamper: firstExposure(3, 1), want: ErrBuild},
		"an exposure whose raw weight is not the election's frozen one": {tamper: firstExposure(4, 1), want: ErrBuild},
	} {
		t.Run(name, func(t *testing.T) {
			r, m := newRecorded(t)
			r.tamper = tc.tamper
			names := namesOf(t, r)
			if tc.names != nil {
				names = tc.names(names)
			}
			root := rootContext(t, p.Candidate.Authorization.K)
			_, err := Build(context.Background(), r, m, p.ResultID, root, names)
			require.Error(t, err)
			require.ErrorIs(t, err, tc.want)
		})
	}
	// an incomplete root context
	r, m := newRecorded(t)
	_, err := Build(context.Background(), r, m, p.ResultID, RootContext{}, namesOf(t, r))
	require.True(t, errors.Is(err, ErrBuild))
}

func keccak(b []byte) []byte { return evmassignKeccak(b) }

func TestCheckPoPsOrdersAndChecksAgainstTheStoredHashes(t *testing.T) {
	r, m := newRecorded(t)
	p := evmstatetest.Load(t, fixturePath)
	out, _ := buildFixture(t, r, m, namesOf(t, r))
	shuffled := append([]evmassign.EVMPoP{}, p.PoPs...)
	shuffled[0], shuffled[len(shuffled)-1] = shuffled[len(shuffled)-1], shuffled[0]
	got, err := CheckPoPs(out, shuffled)
	require.NoError(t, err)
	require.Equal(t, p.PoPs, got, "ordered by member, ready for the plan")

	wrong := append([]evmassign.EVMPoP{}, p.PoPs...)
	wrong[1].Signature = append(bytes.Clone(p.PoPs[1].Signature[:64]), p.PoPs[1].Signature[64]^1)
	_, err = CheckPoPs(out, wrong)
	require.ErrorIs(t, err, ErrBuild, "a signature the election did not store")
	_, err = CheckPoPs(out, p.PoPs[1:])
	require.ErrorIs(t, err, ErrBuild, "a member missing")
	_, err = CheckPoPs(out, append(append([]evmassign.EVMPoP{}, p.PoPs...), p.PoPs[0]))
	require.ErrorIs(t, err, ErrBuild, "a duplicate")
	stranger := append([]evmassign.EVMPoP{}, p.PoPs...)
	stranger[0].EVMKey = bytes.Repeat([]byte{2}, 33)
	_, err = CheckPoPs(out, stranger)
	require.ErrorIs(t, err, ErrBuild, "another key")
}
