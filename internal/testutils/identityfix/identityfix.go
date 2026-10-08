// Package identityfix builds deterministic #85 identity records and recovery authorizations for tests that need an assignment
// candidate: one record per coupled root/EVM pair, with a payee and exposure digest derived from the root node id.
package identityfix

import (
	"bytes"
	"crypto/sha256"
	"sort"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-go-base/types"
)

func sum(tag, id string) [32]byte { return sha256.Sum256([]byte(tag + "/" + id)) }

// Identities returns the identity records of the coupled set, sorted by staking id. Records are found by node id, not by position.
func Identities(root []evmassign.RootMember, succ *types.PartitionDescriptionRecord, bindings []evmassign.Binding) []evmassign.Identity {
	return IdentitiesWithPayee(root, succ, bindings, "")
}

// IdentitiesWithPayee is Identities with the payee derived from payeeTag+root node id, so a test can change payees alone.
func IdentitiesWithPayee(root []evmassign.RootMember, succ *types.PartitionDescriptionRecord, bindings []evmassign.Binding, payeeTag string) []evmassign.Identity {
	byRoot := map[string]evmassign.RootMember{}
	for _, m := range root {
		byRoot[m.NodeID] = m
	}
	byEVM := map[string]*types.NodeInfo{}
	for _, v := range succ.Validators {
		byEVM[v.NodeID] = v
	}
	out := make([]evmassign.Identity, 0, len(bindings))
	for _, b := range bindings {
		m, v := byRoot[b.RootNodeID], byEVM[b.EVMNodeID]
		sid, payee, exp := sum("staking", b.RootNodeID), sum("payee"+payeeTag, b.RootNodeID), sum("exposure", b.RootNodeID)
		out = append(out, evmassign.Identity{StakingID: sid[:], Generation: 1, RootNodeID: m.NodeID, RootKey: bytes.Clone(m.Key),
			EVMNodeID: v.NodeID, EVMKey: bytes.Clone(v.SigKey), Weight: m.Weight, RawWeight: m.Weight, OperatorPayee: payee[:20], ExposureDigest: exp[:]})
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].StakingID, out[j].StakingID) < 0 })
	return out
}

// Authorization is the recovery authorization whose K is k, based on the given acknowledged root body and assignment hash.
func Authorization(network uint64, baseBody []byte, baseAssignment [32]byte, k []evmassign.Identity) *evmassign.Authorization {
	exposure, err := evmassign.ExposureCommit(k)
	if err != nil {
		panic(err)
	}
	contracts, result, snapshot, policies := sum("contracts", ""), sum("result", ""), sum("snapshot", ""), sum("policies", "")
	return &evmassign.Authorization{Network: network, Chain: 1, Contracts: contracts[:], ResultID: result[:], SnapshotDigest: snapshot[:],
		BaseRootBodyID: bytes.Clone(baseBody), BaseAssignmentHash: baseAssignment[:], K: k, ExposureDigest: exposure[:], Policies: policies[:]}
}

// Primary is the primary lifecycle of ids carrying authorization a.
func Primary(ids []evmassign.Identity, a *evmassign.Authorization) evmassign.Lifecycle {
	return evmassign.Lifecycle{Kind: evmassign.KindPrimary, Identities: ids, Authorization: a}
}

// Shaped gives a hand-built candidate the minimum shape Encode requires (primary kind, an authorization, one proof) for tests that
// only exercise decoding or transport of the assignment bytes; its contents are not verified.
func Shaped(c evmassign.Candidate) evmassign.Candidate {
	c.Kind = evmassign.KindPrimary
	if len(c.PoPs) == 0 {
		c.PoPs = []evmassign.PoP{{NodeID: "x", Key: []byte{1}, Signature: []byte{1}}}
	}
	if c.Authorization == nil {
		c.Authorization = &evmassign.Authorization{}
	}
	return c
}

// Provenance is a provenance entry over a shaped candidate preimage of the given kind (its contents are not verified), for tests of
// the orchestration index. salt distinguishes entries; the record id is 32 bytes of recordByte.
func Provenance(recordByte byte, rootEpoch uint64, kind uint64, salt byte) (evmassign.Provenance, error) {
	c := Shaped(evmassign.Candidate{Version: evmassign.CandidateVersion, Attempt: uint64(salt), Predecessor: bytes.Repeat([]byte{salt}, 32)})
	if kind == evmassign.KindRecovery {
		c.Kind, c.PoPs, c.ReplacedAssignment = evmassign.KindRecovery, nil, bytes.Repeat([]byte{salt}, 32)
	}
	raw, err := c.Encode()
	if err != nil {
		return evmassign.Provenance{}, err
	}
	digest := sha256.Sum256(raw)
	return evmassign.Provenance{RecordID: bytes.Repeat([]byte{recordByte}, 32), CandidateDigest: digest[:], RootEpoch: rootEpoch, Kind: kind, Preimage: raw}, nil
}

// ProvenanceFor is the provenance entry of a committed candidate (shaped or real), of the kind it carries.
func ProvenanceFor(c evmassign.Candidate, recordByte byte, rootEpoch uint64) (evmassign.Provenance, error) {
	raw, err := c.Encode()
	if err != nil {
		return evmassign.Provenance{}, err
	}
	digest := sha256.Sum256(raw)
	return evmassign.Provenance{RecordID: bytes.Repeat([]byte{recordByte}, 32), CandidateDigest: digest[:], RootEpoch: rootEpoch, Kind: c.Kind, Preimage: raw}, nil
}
