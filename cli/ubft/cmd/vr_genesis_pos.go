package cmd

// The PoS-prototype generation's share of `vr-genesis verify` (VT-04, design 3.8): the module is the PosElectionAdapter at 0xff..07 (no
// storage, no composer), custody is liability holder 0 of the generation, and the P85 stack the contracts genesis allocates is bound to
// the plan: its accounts, code hashes, balances, and the custody slots that tie it to VR and to the roots' genesis identities.

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The PosElectionAdapter's cached metadata (src/vr/pos/PosElectionAdapter.sol): the tag, LIABILITY_HOLDER, and the gas bounds it
// declares (the caps themselves: the measured worst case is above them, owner-questions "VT-04").
var (
	vrPosTag       = vrschema.Keccak([]byte("unicity.vr.pos-p85.v1"))
	vrPosGasBounds = [8]uint64{4_000_000, 1_000_000, 1_500_000, 10_000, 10_000, 10_000, 10_000, 10_000}
)

// The prototype's measured deployment limit (contracts script/VRPosGenesis.s.sol, test/vr/pos/PosLimit.t.sol): a committee of at most 6 from an
// index of at most 8 identities of one lot each.
const (
	vrPosMaxCommittee = 6
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
