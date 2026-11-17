package cmd

// The expected genesis storage of a VR generation's contract accounts, reconstructed from the plan alone (VT-14 review, astra and sol
// P1): `vr-genesis verify` compares the finalized genesis allocation with it slot for slot, so no deployment report stands in for the
// allocated state. The layouts are the reviewed contracts' (unicity-pos-contracts src/vr/VRLayout.sol, the ERC-7201 struct at V; forge
// `storageLayout` of PoaElection and FoundationMultisig); a contract whose constructor writes anything else is a different deployment.

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The reviewed runtimes VR's code hash does not cover: the composer engine (PoaElection commits to its address only) and the
// FoundationMultisig (VR's governor, held in storage). The VR core and the module are bound by the measurement and the EVM PDR; the facets
// by the hashes the pinned core carries as immutables.
//
// Provenance (astra, VT-14 r1 and r2, review-code-hashes.json): unicity-pos-contracts f922d04ccc421e88598c1ed76aa9fa5f3c044e32
// (ristik/unicity-pos-contracts#91), forge 1.8.1, solc 0.8.37, via-IR, cancun, bytecode_hash none, no CBOR metadata:
//   - out/PoaComposer.sol/PoaComposerEngine.json, deployed runtime 8,603 bytes (optimizer runs 200);
//   - out/FoundationMultisig.sol/FoundationMultisig.p85.json, deployed runtime 3,643 bytes: the optimizer-runs-1 "p85" compiler profile
//     variant that script/VRGenesis.s.sol deploys (the runs-200 variant hashes differently).
const (
	vrReviewedComposerCodeHash = "0x519fea7b1685ee52bfb93083b0436980ec0ebba6a2469d3e00dd30a3d2a83e40"
	vrReviewedGovernorCodeHash = "0x189b2d0eb755de9007a6e944c4f753fd4b6a283075d08315ac50d872cf67ad07"
)

// The PoA v1 module metadata VR caches at genesis (V+16 .. V+21): PoaElection's TAG, capabilities, maxElectionInterval and gasBounds
// (src/vr/poa/PoaElection.sol). They are constants of the code the measurement pins.
var (
	vrPoaTag                = vrschema.Keccak([]byte("unicity.vr.poa.v1"))
	vrPoaElectInterval      = uint64(10 * 100) // 10 x MIN_EPOCH_GAP
	vrPoaGasBounds          = [8]uint64{3_600_000, 100_000, 900_000, 10_000, 1_500_000, 10_000, 100_000, 10_000}
	vrPoaActive        byte = 4
)

type vrStorage map[vrschema.Word]vrschema.Word

// packed is a Solidity-packed word: each field (offset, size in bytes, value) occupies the low-order bytes from its offset upward.
func packed(fields ...[3]uint64) vrschema.Word {
	var w vrschema.Word
	for _, f := range fields {
		off, size, v := f[0], f[1], f[2]
		for i := uint64(0); i < size; i++ {
			w[31-off-i] = byte(v >> (8 * i))
		}
	}
	return w
}

func addrAt(w *vrschema.Word, off int, a common.Address) { copy(w[32-off-20:32-off], a[:]) }

func (s vrStorage) set(slot, value vrschema.Word) {
	if value != (vrschema.Word{}) {
		s[slot] = value
	}
}

// bytesAt writes a Solidity bytes/string value at slot: short (< 32) inline with 2*len in the low byte, long as 2*len+1 and the data
// from keccak256(slot).
func (s vrStorage) bytesAt(slot vrschema.Word, b []byte) {
	if len(b) < 32 {
		var w vrschema.Word
		copy(w[:], b)
		w[31] = byte(2 * len(b))
		s.set(slot, w)
		return
	}
	s.set(slot, vrschema.U64(uint64(2*len(b)+1)))
	base := vrschema.BytesDataSlot(slot)
	for i := 0; i*32 < len(b); i++ {
		var w vrschema.Word
		copy(w[:], b[i*32:])
		s.set(vrschema.SlotAdd(base, uint64(i)), w)
	}
}

func idKey(id uint64) vrschema.Word { return vrschema.U64(id) }

// vrExpectedState is the planned genesis storage of VR, the PoA module and the multisig. identities are the roots' genesis records, already
// checked to be the input's identities in id order.
func vrExpectedState(in vrGenesisInput, identities []evmassign.Identity, moduleCode [32]byte) (vr, poa, multisig vrStorage, committee vrschema.Word, err error) {
	vr, poa, multisig = vrStorage{}, vrStorage{}, vrStorage{}
	V := vrschema.VRSlot
	network, err := vrHex("network", in.Network, 32)
	if err != nil {
		return nil, nil, nil, committee, err
	}
	collector, err := vrAddress("fee collector", in.Fees.FeeCollector)
	if err != nil {
		return nil, nil, nil, committee, err
	}
	chainWord := vrschema.U64(in.ChainID)
	vr.set(V(vrschema.SlotNetwork), vrschema.Word(network))
	vr.set(V(vrschema.SlotLastAcked), vrschema.GenesisResult)
	l := in.Limits
	vr.set(V(vrschema.SlotCommitteeLimits), packed([3]uint64{0, 4, uint64(l.NMin)}, [3]uint64{4, 4, uint64(l.NTarget)}, [3]uint64{8, 4, uint64(l.NMax)}))
	vr.set(V(vrschema.SlotHookLimits), packed([3]uint64{0, 4, uint64(l.VMax)}, [3]uint64{4, 4, uint64(l.LMax)}, [3]uint64{8, 4, uint64(l.RMax)},
		[3]uint64{12, 4, uint64(l.MaxBatch)}))
	vr.set(V(vrschema.SlotStatus), packed([3]uint64{1, 8, in.KnownRootEpoch}))
	var w vrschema.Word
	addrAt(&w, 0, vrGenesisAddress(7))
	vr.set(V(vrschema.SlotActiveModule), w)
	vr.set(V(vrschema.SlotActiveModuleHash), moduleCode)
	w = vrschema.Word{}
	addrAt(&w, 0, vrGenesisAddress(9))
	vr.set(V(vrschema.SlotGovernor), w)
	vr.set(V(vrschema.SlotCounters), packed([3]uint64{0, 8, 1}, [3]uint64{8, 8, uint64(len(in.Identities))}))
	fees := packed([3]uint64{0, 8, in.Fees.BaseFeeFloor}, [3]uint64{8, 8, in.Fees.ChangeDenominator})
	w = vrschema.Word{}
	addrAt(&w, 0, collector)
	for _, k := range []uint64{vrschema.SlotFeesPrevious, vrschema.SlotFeesCurrent} {
		vr.set(V(k), fees)
		vr.set(V(k+1), w)
	}
	// V+16 .. V+21: the active module's cached metadata
	vr.set(V(16), vrPoaTag)
	vr.set(V(17), packed([3]uint64{0, 4, 0}, [3]uint64{4, 8, vrPoaElectInterval}))
	for half := 0; half < 2; half++ {
		vr.set(V(18+uint64(half)), packed([3]uint64{0, 8, vrPoaGasBounds[4*half]}, [3]uint64{8, 8, vrPoaGasBounds[4*half+1]},
			[3]uint64{16, 8, vrPoaGasBounds[4*half+2]}, [3]uint64{24, 8, vrPoaGasBounds[4*half+3]}))
	}
	// V+22 the watch (epochStartProgress), V+24 and V+25 the generation parameters
	vr.set(V(22), packed([3]uint64{10, 8, in.EpochStartProgress}))
	vr.set(V(24), packed([3]uint64{0, 8, in.Continuity.MaxM}, [3]uint64{8, 8, in.Continuity.DistNum}, [3]uint64{16, 8, in.Continuity.DistDen},
		[3]uint64{24, 8, in.MaxGas}))
	vr.set(V(25), packed([3]uint64{0, 8, in.SystemGas}))

	// identities (V+38), key history (V+39), the binding store (V+41) and the committee (V+42)
	var members []uint64
	seats := vrschema.BytesDataSlot(V(42))
	for i, p := range in.Identities {
		id := uint64(i + 1)
		rootKey, err1 := vrHex("root key", strings.ToLower(p.RootKey), 33)
		evmKey, err2 := vrHex("evm key", strings.ToLower(p.EVMKey), 33)
		owner, err3 := vrAddress("owner", p.Owner)
		payee, err4 := vrAddress("payee", p.Payee)
		if e := errors.Join(err1, err2, err3, err4); e != nil {
			return nil, nil, nil, committee, e
		}
		rn, rk := ethcrypto.Keccak256Hash([]byte(p.RootNodeID)), ethcrypto.Keccak256Hash(rootKey)
		en, ek := ethcrypto.Keccak256Hash([]byte(p.EVMNodeID)), ethcrypto.Keccak256Hash(evmKey)
		pw := vrschema.AddrWord(payee)
		ref := vrschema.Keccak(rn[:], rk[:], en[:], ek[:], pw[:])
		ident := vrschema.MapSlot(idKey(id), V(38))
		w = packed([3]uint64{20, 8, 1})
		addrAt(&w, 0, owner)
		vr.set(ident, w)
		vr.set(vrschema.SlotAdd(ident, 1), ref)
		vr.set(vrschema.MapSlot(vrschema.Word(rk), V(39)), vrschema.U64(id<<8|1))
		vr.set(vrschema.MapSlot(vrschema.Word(ek), V(39)), vrschema.U64(id<<8|2))
		b := vrschema.MapSlot(ref, V(41))
		for j, word := range []vrschema.Word{vrschema.Word(rn), vrschema.Word(rk), vrschema.Word(en), vrschema.Word(ek), pw} {
			vr.set(vrschema.SlotAdd(b, uint64(j)), word)
		}
		vr.bytesAt(vrschema.SlotAdd(b, 5), []byte(p.RootNodeID))
		vr.bytesAt(vrschema.SlotAdd(b, 6), rootKey)
		vr.bytesAt(vrschema.SlotAdd(b, 7), []byte(p.EVMNodeID))
		vr.bytesAt(vrschema.SlotAdd(b, 8), evmKey)
		if p.RawWeight == 0 {
			continue
		}
		k := uint64(len(members))
		members = append(members, id)
		rec := identities[k]
		exposure := vrschema.PoaExposureDigest(vrschema.Word(network), chainWord, vrschema.ValidatorRegistry, vrschema.GenesisResult, id)
		if !bytes.Equal(rec.ExposureDigest, exposure[:]) {
			return nil, nil, nil, committee, fmt.Errorf("%w: genesis identity %d's exposure digest is not VR's genesis exposure", ErrVRGenesis, id)
		}
		seat := vrschema.SlotAdd(seats, 3*k)
		vr.set(seat, packed([3]uint64{0, 8, id}, [3]uint64{8, 8, 1}, [3]uint64{16, 8, rec.Weight}, [3]uint64{24, 8, p.RawWeight}))
		vr.set(vrschema.SlotAdd(seat, 1), ref)
		vr.set(vrschema.SlotAdd(seat, 2), exposure)
	}
	vr.set(V(42), vrschema.U64(uint64(len(members))))
	if committee, err = vradmit.MembersDigestOf(identities); err != nil {
		return nil, nil, nil, committee, errors.Join(ErrVRGenesis, err)
	}
	vr.set(V(26), committee)

	// PoaElection: _entries[id] = Entry(ACTIVE, 0) at slot 0, _members at slot 1 (uint64, four per slot)
	for i, id := range members {
		poa.set(vrschema.MapSlot(idKey(id), vrschema.Word{}), packed([3]uint64{0, 1, uint64(vrPoaActive)}))
		slot := vrschema.SlotAdd(vrschema.BytesDataSlot(vrschema.U64(1)), uint64(i/4))
		cur := poa[slot]
		off := uint64(i%4) * 8
		for b := uint64(0); b < 8; b++ {
			cur[31-off-b] = byte(id >> (8 * b))
		}
		poa.set(slot, cur)
	}
	poa.set(vrschema.U64(1), vrschema.U64(uint64(len(members))))

	// FoundationMultisig: _signers[0..4] at slots 0..4, ascending
	signers := append([]string(nil), in.GovernorSigners...)
	if !sort.StringsAreSorted(signers) || len(signers) != 5 {
		return nil, nil, nil, committee, fmt.Errorf("%w: the plan's governor signers are not five ascending addresses", ErrVRGenesis)
	}
	for i, s := range signers {
		a, err := vrAddress("governor signer", s)
		if err != nil {
			return nil, nil, nil, committee, err
		}
		multisig.set(vrschema.U64(uint64(i)), vrschema.AddrWord(a))
	}
	return vr, poa, multisig, committee, nil
}

// diffStorage lists the slots where the allocated storage differs from the expected one (a zero slot is absent).
func diffStorage(role string, want, got vrStorage) []string {
	var out []string
	for k, v := range want {
		if got[k] != v {
			out = append(out, fmt.Sprintf("%s slot %x: allocated %x, planned %x", role, k, got[k], v))
		}
	}
	for k, v := range got {
		if _, ok := want[k]; !ok && v != (vrschema.Word{}) {
			out = append(out, fmt.Sprintf("%s slot %x: allocated %x, planned nothing", role, k, v))
		}
	}
	sort.Strings(out)
	return out
}

func storageOf(a vrAllocAccount) (vrStorage, error) {
	s, err := vrSlots(a)
	if err != nil {
		return nil, err
	}
	out := vrStorage{}
	for k, v := range s {
		out.set(k, v)
	}
	return out, nil
}

// embeds reports whether code carries word as a 32-byte immutable (a PUSH32 of it).
func embeds(code []byte, word [32]byte) bool {
	return bytes.Contains(code, append([]byte{0x7f}, word[:]...))
}

func bigWord(s string) (vrschema.Word, bool) {
	var w vrschema.Word
	b, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
	if !ok || b.Sign() < 0 || b.BitLen() > 256 {
		return w, false
	}
	b.FillBytes(w[:])
	return w, true
}
