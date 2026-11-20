package cmd

// The PoS-prototype generation's share of `vr-genesis verify` (VT-04, design 3.8): the module is the PosElectionAdapter at 0xff..07 (no
// storage, no composer), custody is liability holder 0 of the generation, and the P85 stack the contracts genesis allocates is bound to
// the plan: its accounts, code hashes, balances, and the custody slots that tie it to VR and to the roots' genesis identities.

import (
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The PosElectionAdapter's cached metadata (src/vr/pos/PosElectionAdapter.sol): the tag, LIABILITY_HOLDER, and the gas bounds it
// declares: the PoS-capable VR build's caps (5.0 / 1.5 / 2.5 M; VT-04b, astra's caps ruling), which VR takes as min(its ceiling, these).
var (
	vrPosTag       = vrschema.Keccak([]byte("unicity.vr.pos-p85.v1"))
	vrPosGasBounds = [8]uint64{5_000_000, 1_500_000, 2_500_000, 10_000, 10_000, 10_000, 10_000, 10_000}
)

// The prototype's measured deployment limit (contracts script/VRPosGenesis.s.sol, test/vr/pos/PosLimit.t.sol): a committee of at most 6 from an
// index of at most 8 identities of one lot each.
const (
	vrPosMaxCommittee = 5
	vrPosMaxPool      = 8
)

// custody storage appended by VT-04 (docs/p85/custody-storage-layout.txt): deploymentDomain and exposureMemberDigest.
const (
	vrCustodyDomainSlot       = 39
	vrCustodyMemberDigestSlot = 40
)

func vrModuleTag(in vrGenesisInput) vrschema.Word {
	if in.Pos != nil {
		return vrPosTag
	}
	return vrPoaTag
}

// vrPosAccounts are the accounts of the P85 stack the PoS deployment report names.
func vrPosAccounts(in vrGenesisInput, d vrDeploymentFile) (map[common.Address]string, error) {
	out := map[common.Address]string{}
	if in.Pos == nil {
		if d.Pos {
			return nil, fmt.Errorf("%w: the deployment report is a PoS deployment but the input has no pos object", ErrVRGenesis)
		}
		return out, nil
	}
	if !d.Pos || d.PosAssignmentID == "" {
		return nil, fmt.Errorf("%w: the input is a PoS plan but the deployment report is not a PoS deployment", ErrVRGenesis)
	}
	for role, s := range map[string]string{"factory": d.Factory, "custody": d.Custody, "genesisImpl": d.GenesisImpl, "election": d.Election,
		"evidence": d.Evidence, "selection": d.Selection, "reader": d.Reader, "policy": d.Policy, "rewardPool": d.RewardPool} {
		a, err := vrAddress("PoS "+role, s)
		if err != nil {
			return nil, err
		}
		if a == (common.Address{}) {
			return nil, fmt.Errorf("%w: the PoS %s is the zero address", ErrVRGenesis, role)
		}
		if prior, dup := out[a]; dup {
			return nil, fmt.Errorf("%w: the PoS %s and %s are one account", ErrVRGenesis, role, prior)
		}
		if vrGenesisRole(a) != "" {
			return nil, fmt.Errorf("%w: the PoS %s collides with a VR genesis account", ErrVRGenesis, role)
		}
		out[a] = role
	}
	return out, nil
}

// vrPosExpectedState rewrites VR's expected genesis storage for the PoS module: its cached metadata (V+16..V+21), holder 0
// (V+36, V+49, the holder count in V+6). The module account itself holds no storage.
func vrPosExpectedState(in vrGenesisInput, d vrDeploymentFile, identities []evmassign.Identity, vr vrStorage, moduleCode [32]byte) error {
	V := vrschema.VRSlot
	custody, err := vrAddress("PoS custody", d.Custody)
	if err != nil {
		return err
	}
	custodyHash, err := vrHex("PoS custody code hash", d.CustodyCodeHash, 32)
	if err != nil {
		return err
	}
	set := func(slot, w vrschema.Word) {
		if w == (vrschema.Word{}) {
			delete(vr, slot)
			return
		}
		vr[slot] = w
	}
	set(V(16), vrPosTag)
	set(V(17), packed([3]uint64{0, 4, 1}, [3]uint64{4, 8, in.Pos.CadenceRounds}))
	for half := 0; half < 2; half++ {
		set(V(18+uint64(half)), packed([3]uint64{0, 8, vrPosGasBounds[4*half]}, [3]uint64{8, 8, vrPosGasBounds[4*half+1]},
			[3]uint64{16, 8, vrPosGasBounds[4*half+2]}, [3]uint64{24, 8, vrPosGasBounds[4*half+3]}))
	}
	cw := vrschema.AddrWord(custody)
	set(V(20), cw)
	set(V(21), vrschema.Word(custodyHash))
	set(V(vrschema.SlotStatus), packed([3]uint64{1, 8, in.KnownRootEpoch}, [3]uint64{21, 1, 1}))
	// holders[0] = {custody, registeredEpoch, custody code hash, module}: V+36 (a uint8 key), V+49 holderIndexPlusOne[custody] = 1
	h := vrschema.MapSlot(vrschema.U64(0), V(36))
	w := packed([3]uint64{20, 8, in.KnownRootEpoch})
	addrAt(&w, 0, custody)
	set(h, w)
	set(vrschema.SlotAdd(h, 1), vrschema.Word(custodyHash))
	mw := vrschema.AddrWord(vrGenesisAddress(7))
	set(vrschema.SlotAdd(h, 2), mw)
	set(vrschema.MapSlot(cw, V(49)), vrschema.U64(1))
	_ = moduleCode
	_ = identities
	return nil
}

// vrCheckPosStack binds the P85 stack to the plan: every account allocated with the code hash the report names, custody holding exactly the
// bonds and the reward pool exactly its funding, custody's deployment domain VR, and each genesis identity's member digest in custody the
// one the roots' genesis identity carries (so a closure of the genesis assignment derives the digest custody stored).
func vrCheckPosStack(in vrGenesisInput, d vrDeploymentFile, identities []evmassign.Identity, alloc map[common.Address]vrAllocAccount, posAccts map[common.Address]string) error {
	fail := func(f string, a ...any) error { return fmt.Errorf("%w: "+f, append([]any{ErrVRGenesis}, a...)...) }
	hashes := map[string]string{"custody": d.CustodyCodeHash, "election": d.ElectionCodeHash, "policy": d.PolicyCodeHash, "rewardPool": d.RewardPoolCodeHash}
	var custody common.Address
	for a, role := range posAccts {
		acct, ok := alloc[a]
		if !ok {
			return fail("the PoS %s %s is not allocated", role, a)
		}
		code := strings.TrimPrefix(acct.Code, "0x")
		if code == "" {
			return fail("the PoS %s has no code", role)
		}
		raw, err := vrHex("code", "0x"+code, len(code)/2)
		if err != nil {
			return err
		}
		if want, named := hashes[role]; named {
			if got := ethcrypto.Keccak256Hash(raw); !strings.EqualFold(lowerHex(got[:]), want) {
				return fail("the PoS %s code hashes to %x, the report names %s", role, got, want)
			}
		}
		if role == "custody" {
			custody = a
		}
	}
	bondUnit, _ := new(big.Int).SetString(in.Pos.BondUnit, 10)
	total := new(big.Int)
	for _, p := range in.Identities {
		total.Add(total, new(big.Int).Mul(new(big.Int).SetUint64(p.RawWeight), bondUnit))
	}
	balance := func(a common.Address) *big.Int {
		w, _ := bigWord(cmpOr(alloc[a].Balance, "0x0"))
		return new(big.Int).SetBytes(w[:])
	}
	if got := balance(custody); got.Cmp(total) != 0 {
		return fail("custody holds %s, the genesis bonds are %s", got, total)
	}
	pool, _ := vrAddress("PoS reward pool", d.RewardPool)
	funding, _ := new(big.Int).SetString(in.Pos.RewardFunding, 10)
	if got := balance(pool); got.Cmp(funding) != 0 {
		return fail("the reward pool holds %s, the plan funds %s", got, funding)
	}
	slots, err := storageOf(alloc[custody])
	if err != nil {
		return err
	}
	if got := slots[vrschema.U64(vrCustodyDomainSlot)]; got != vrschema.AddrWord(common.Address(vrschema.ValidatorRegistry)) {
		return fail("custody's exposure-digest domain is %x, not VR", got)
	}
	network, err := vrHex("network", in.Network, 32)
	if err != nil {
		return err
	}
	assignment, err := vrHex("assignment", in.Pos.AssignmentID, 32)
	if err != nil {
		return err
	}
	if err := vrCheckPosElection(in, d, network, alloc); err != nil {
		return err
	}
	chainWord := vrschema.U64(in.ChainID)
	for i, id := range identities {
		sid := uint64(i + 1)
		eid := vrschema.PoaExposureDigest(vrschema.Word(network), chainWord, vrschema.ValidatorRegistry, vrschema.Word(assignment), sid)
		if got := slots[vrschema.MapSlot(eid, vrschema.U64(vrCustodyMemberDigestSlot))]; !strings.EqualFold(lowerHex(got[:]), lowerHex(id.ExposureDigest)) {
			return fail("custody's member digest of genesis identity %d is %x, the roots' genesis identity carries %x", sid, got, id.ExposureDigest)
		}
	}
	return nil
}

// ElectionPolicy storage (the compiled layout the genesis script initializes through the factory; unicity-pos-contracts src/p85/ElectionPolicy.sol).
const (
	vrElectionInitializedSlot = 0
	vrElectionNetworkSlot     = 2
	vrElectionCustodySlot     = 3
	vrElectionRootsSlot       = 4
	vrElectionEvidenceSlot    = 5
	vrElectionSelectionSlot   = 6
	vrElectionParamsSlot      = 8  // nMin, nTarget, nMax as three 4-byte fields
	vrElectionCadenceSlot     = 9  // cadenceRounds, then cadenceSeconds, above the low 8 bytes
	vrElectionStagedSlot      = 18 // mapping(id => mapping(generation => Staged))
	vrElectionIndexLenSlot    = 19 // the live index: the length here, the entries (uint64, four to a word) from keccak(19)
	vrElectionPositionSlot    = 20 // mapping(id => 1-based position in the index)
	vrElectionMaxBatchSlot    = 15
	vrElectionReaderSlot      = 21
	vrElectionHookCallerSlot  = 23
	vrElectionRegistrySlot    = 24
)

// vrPosElectionExpected is the election's ENTIRE planned genesis storage, derived from the plan alone: every slot ElectionPolicy.initialize
// writes (links, limits, parameters and cadence, the live index with its reverse positions, and each genesis identity's staged binding at
// generation 1 with its key bytes and hashes). Nothing else is written at genesis, so the allocated storage must equal it slot for slot: an extra slot,
// a missing one or an altered one is refused. The manifest hash is the factory's hash of the whole manifest and is not derivable from the plan; it
// must be present and is the one word taken from the alloc.
func vrPosElectionExpected(in vrGenesisInput, d vrDeploymentFile, network []byte, manifestHash vrschema.Word) (vrStorage, error) {
	e := vrStorage{}
	addr := func(name, s string) (common.Address, error) { return vrAddress("PoS "+name, s) }
	custody, err1 := addr("custody", d.Custody)
	evidence, err2 := addr("evidence", d.Evidence)
	selection, err3 := addr("selection", d.Selection)
	reader, err4 := addr("reader", d.Reader)
	policy, err5 := addr("policy", d.Policy)
	if err := errors.Join(err1, err2, err3, err4, err5); err != nil {
		return nil, err
	}
	e.set(vrschema.U64(vrElectionInitializedSlot), vrschema.U64(1))
	e.set(vrschema.U64(1), manifestHash)
	e.set(vrschema.U64(vrElectionNetworkSlot), vrschema.Word(network))
	e.set(vrschema.U64(vrElectionCustodySlot), vrschema.AddrWord(custody))
	e.set(vrschema.U64(vrElectionRootsSlot), vrschema.AddrWord(common.Address(vrschema.SealRegistry)))
	e.set(vrschema.U64(vrElectionEvidenceSlot), vrschema.AddrWord(evidence))
	e.set(vrschema.U64(vrElectionSelectionSlot), vrschema.AddrWord(selection))
	// policySource (20 bytes) and vMax (uint32) share a word
	w := packed([3]uint64{20, 4, uint64(in.Limits.VMax)})
	addrAt(&w, 0, policy)
	e.set(vrschema.U64(7), w)
	// ElectionParams: nMin, nTarget, nMax (uint32), maxM, distNum (uint64) in the first word; distDen, cadenceRounds, cadenceSeconds in the next
	e.set(vrschema.U64(vrElectionParamsSlot), packed([3]uint64{0, 4, uint64(in.Limits.NMin)}, [3]uint64{4, 4, uint64(in.Limits.NTarget)}, [3]uint64{8, 4, uint64(in.Limits.NMax)},
		[3]uint64{12, 8, in.Continuity.MaxM}, [3]uint64{20, 8, in.Continuity.DistNum}))
	e.set(vrschema.U64(vrElectionCadenceSlot), packed([3]uint64{0, 8, in.Continuity.DistDen}, [3]uint64{8, 8, in.Pos.CadenceRounds}, [3]uint64{16, 8, in.Pos.CadenceSeconds}))
	e.set(vrschema.U64(vrElectionMaxBatchSlot), vrschema.U64(uint64(in.Limits.MaxBatch)))
	e.set(vrschema.U64(vrElectionReaderSlot), vrschema.AddrWord(reader))
	e.set(vrschema.U64(vrElectionHookCallerSlot), vrschema.AddrWord(vrGenesisAddress(7)))
	e.set(vrschema.U64(vrElectionRegistrySlot), vrschema.AddrWord(common.Address(vrschema.ValidatorRegistry)))
	e.set(vrschema.U64(vrElectionIndexLenSlot), vrschema.U64(uint64(len(in.Identities))))
	for i, id := range in.Identities {
		sid := uint64(i + 1)
		rootKey, err1 := vrHex("rootKey", id.RootKey, 33)
		evmKey, err2 := vrHex("evmKey", id.EVMKey, 33)
		payee, err3 := vrAddress("payee", id.Payee)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, err
		}
		base := vrschema.MapSlot(vrschema.U64(1), vrschema.MapSlot(vrschema.U64(sid), vrschema.U64(vrElectionStagedSlot)))
		rootNode, evmNode := vrschema.Keccak([]byte(id.RootNodeID)), vrschema.Keccak([]byte(id.EVMNodeID))
		e.set(base, rootNode)
		e.bytesAt(vrschema.SlotAdd(base, 1), rootKey)
		e.set(vrschema.SlotAdd(base, 2), evmNode)
		e.bytesAt(vrschema.SlotAdd(base, 3), evmKey)
		e.set(vrschema.SlotAdd(base, 4), vrschema.AddrWord(payee))
		e.set(vrschema.SlotAdd(base, 5), vrschema.Keccak(wb(vrElectionBindingDomain), wb(vrschema.U64(sid)), wb(vrschema.U64(1)), wb(rootNode),
			wb(vrschema.Keccak(rootKey)), wb(evmNode), wb(vrschema.Keccak(evmKey)), wb(vrschema.AddrWord(payee))))
		e.set(vrschema.SlotAdd(base, 7), vrschema.Keccak(rootKey))
		e.set(vrschema.SlotAdd(base, 8), vrschema.Keccak(evmKey))
		// the live index: entry i is identity i+1 (four uint64 to a word), and the reverse position is 1-based
		entry := vrschema.SlotAdd(vrschema.Keccak(wb(vrschema.U64(vrElectionIndexLenSlot))), uint64(i)/4)
		cur := e[entry]
		cur = orWord(cur, packed([3]uint64{(uint64(i) % 4) * 8, 8, sid}))
		e.set(entry, cur)
		e.set(vrschema.MapSlot(vrschema.U64(sid), vrschema.U64(vrElectionPositionSlot)), vrschema.U64(sid))
	}
	return e, nil
}

func orWord(a, b vrschema.Word) vrschema.Word {
	for i := range a {
		a[i] |= b[i]
	}
	return a
}

// vrCheckPosElection compares the election's whole allocated storage with the one the plan derives (vrPosElectionExpected): a missing link (the
// eligibility reader included), index entry or key byte, and any extra slot, is refused.
func vrCheckPosElection(in vrGenesisInput, d vrDeploymentFile, network []byte, alloc map[common.Address]vrAllocAccount) error {
	election, err := vrAddress("PoS election", d.Election)
	if err != nil {
		return err
	}
	got, err := storageOf(alloc[election])
	if err != nil {
		return err
	}
	want, err := vrPosElectionExpected(in, d, network, got[vrschema.U64(1)])
	if err != nil {
		return err
	}
	if got[vrschema.U64(1)] == (vrschema.Word{}) {
		return fmt.Errorf("%w: the election has no manifest hash: it is not initialized", ErrVRGenesis)
	}
	if diffs := diffStorage("the PoS election", want, got); len(diffs) > 0 {
		return fmt.Errorf("%w: the election's storage is not the plan's: %s", ErrVRGenesis, strings.Join(diffs, "; "))
	}
	return nil
}

// vrElectionBindingDomain is ElectionPolicy.BINDING_DOMAIN.
var vrElectionBindingDomain = vrschema.Keccak([]byte("unicity.p85.delegation-binding"))

// wb is a word as a byte slice.
func wb(w vrschema.Word) []byte { return w[:] }
