package bridgeprofile

import (
	"errors"
	"math/big"
)

// BRIDGE_COMPOSE_V2 (protocol 6): BRIDGE_COMPOSE_V1's composition with the lineage relation and a result that separates the root lock
// from the redeemed part. Same input ABI, same gas schedule plus the split terms of lineage.go, same B1 calls; a fresh deployment
// replaces V1 (nothing is upgraded in place). docs/design/bridge-split-lineage-spec.md is normative.

// ComposeMarkerV2 is bytes32("UNICITY_BRIDGE_COMPOSE_V2"), left aligned.
var ComposeMarkerV2 = func() (m [32]byte) { copy(m[:], "UNICITY_BRIDGE_COMPOSE_V2"); return }()

// ComposeOutputBytesV2 is the fixed output, fifteen words: marker, status, cfg, nonce, amount, tokenId, salt, firstPredicateHash,
// lockDigest, releaseTo, nullifier, leafCount (words 0 to 11 as in V1, but the root's), partTokenId, partAmount, splitDepth.
const ComposeOutputBytesV2 = 15 * 32

// ComposeStatusV2 is the V1 status table with the split reasons appended, then the two certificate-codec reasons an embedded ancestor
// proof can raise (V1 projections carry no certificates): code i is ComposeStatusV2[i].
var ComposeStatusV2 = append(append([]error{}, ComposeStatus...),
	ErrSplitJustif, ErrSplitProofCount, ErrSplitProofShape, ErrSplitManifest, ErrSplitBurn, ErrSplitProof, ErrSplitSum,
	ErrCertScan, ErrCertSigLength)

// ComposeStatusNameV2 is the reason name of a V2 status code ("" for success or an unknown code).
func ComposeStatusNameV2(code uint64) string {
	if code == 0 || code >= uint64(len(ComposeStatusV2)) {
		return ""
	}
	name, _ := Reason(ComposeStatusV2[code])
	return name
}

// StatusOfV2 is StatusOf over the V2 table.
func StatusOfV2(err error) (uint64, error) { return statusIn(ComposeStatusV2, err) }

// ComposeOutputV2 is the decoded V2 output of a successful call.
type ComposeOutputV2 struct {
	Result *Result
	Leaves uint64
}

// NativeComposeV2 is BRIDGE_COMPOSE_V2 over input with gasLimit forwarded, metered as NativeCompose: steps 1 to 3 are identical; in
// step 4 a return additionally charges, before the work each pays for, SplitPerByte for the outer mint and for every justification
// descended into, 20 per CBOR item and 16000 per leaf of every ancestor, and SplitEdgeBase + SplitPerStep per proof step for every
// allocation edge; steps 5 to 7 are NativeCompose's over all leaves of the lineage in root-to-child order. A mint (operation 1) is
// the V1 mint: a split reason is refused as a mint justification.
func NativeComposeV2(input []byte, gasLimit uint64, b1 B1) (out [ComposeOutputBytesV2]byte, status, gas uint64, halt error) {
	m := &meter{limit: gasLimit}
	res, err := nativeComposeV2(input, m, b1)
	if errors.Is(err, ErrComposeABI) || errors.Is(err, ErrComposeOutOfGas) {
		return out, 0, gasLimit, err
	}
	copy(out[:32], ComposeMarkerV2[:])
	status, mapErr := StatusOfV2(err)
	if mapErr != nil {
		panic(mapErr.Error() + ": " + err.Error())
	}
	big.NewInt(int64(status)).FillBytes(out[32:64])
	if status == 0 {
		copy(out[64:96], res.Cfg[:])
		new(big.Int).SetUint64(res.Nonce).FillBytes(out[96:128])
		res.Amount.FillBytes(out[128:160])
		copy(out[160:192], res.TokenID[:])
		copy(out[192:224], res.Salt[:])
		copy(out[224:256], res.FirstPredicateHash[:])
		copy(out[256:288], res.LockDigest[:])
		copy(out[300:320], res.ReleaseTo[:])
		copy(out[320:352], res.Nullifier[:])
		new(big.Int).SetUint64(uint64(len(res.Leaves))).FillBytes(out[352:384])
		copy(out[384:416], res.PartTokenID[:])
		res.PartAmount.FillBytes(out[416:448])
		new(big.Int).SetUint64(res.Depth).FillBytes(out[448:480])
	}
	return out, status, m.used, nil
}

func nativeComposeV2(input []byte, m *meter, b1 B1) (*Result, error) {
	if err := m.charge(ComposeBase + ComposePerByte*uint64(len(input))); err != nil {
		return nil, err
	}
	if len(input) > MaxComposeInputBytes {
		return nil, ErrInputTooLarge
	}
	op, cfgBytes, envelope, err := decodeComposeInput(input)
	if err != nil {
		return nil, err
	}
	if op != OpMint && op != OpReturn {
		return nil, ErrBadOperation
	}
	cfg, err := DecodeCfg(cfgBytes)
	if err != nil {
		return nil, err
	}
	if err := m.charge(ComposePerItem * itemsOf(cfgBytes)); err != nil {
		return nil, err
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	env, err := DecodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	pol, err := CheckPolicyBody(cfg, env)
	if err != nil {
		return nil, err
	}
	if err := m.charge(ComposePerItem * itemsOf(env.PolicyBody)); err != nil {
		return nil, err
	}
	if err := m.charge(ComposePerItem*historyItems(env.History) + ComposePerLeaf*historyLeaves(env.History)); err != nil {
		return nil, err
	}
	var res *Result
	if op == OpMint {
		res, err = VerifyMintWith(cfg, env.History, ComposedHistory)
		if err == nil {
			res.PartTokenID, res.PartAmount = res.TokenID, new(big.Int).Set(res.Amount)
		}
	} else {
		var lin *Lineage
		lin, err = verifyLineageMetered(cfg, env.History, ComposedHistory, m)
		if err == nil {
			res = lin.Result
		}
	}
	if err != nil {
		return nil, err
	}
	if err := composeTail(m, b1, cfgBytes, env, pol, res); err != nil {
		return nil, err
	}
	return res, nil
}

// DecodeComposeOutputV2 strictly decodes a V2 output: the marker, a status in the table and, for success, every field.
func DecodeComposeOutputV2(b []byte) (status uint64, res *Result, err error) {
	if len(b) != ComposeOutputBytesV2 {
		return 0, nil, ErrResultFrame
	}
	var marker [32]byte
	copy(marker[:], b[:32])
	st := new(big.Int).SetBytes(b[32:64])
	if marker != ComposeMarkerV2 || !st.IsUint64() || st.Uint64() >= uint64(len(ComposeStatusV2)) {
		return 0, nil, ErrResultFrame
	}
	status = st.Uint64()
	if status != 0 {
		for _, x := range b[64:] {
			if x != 0 {
				return 0, nil, ErrResultFrame
			}
		}
		return status, nil, nil
	}
	res = &Result{}
	copy(res.Cfg[:], b[64:96])
	nonce := new(big.Int).SetBytes(b[96:128])
	depth := new(big.Int).SetBytes(b[448:480])
	if !nonce.IsUint64() || !depth.IsUint64() || !isZero(b[288:300]) {
		return 0, nil, ErrResultFrame
	}
	res.Nonce, res.Depth = nonce.Uint64(), depth.Uint64()
	res.Amount = new(big.Int).SetBytes(b[128:160])
	copy(res.TokenID[:], b[160:192])
	copy(res.Salt[:], b[192:224])
	copy(res.FirstPredicateHash[:], b[224:256])
	copy(res.LockDigest[:], b[256:288])
	copy(res.ReleaseTo[:], b[300:320])
	copy(res.Nullifier[:], b[320:352])
	copy(res.PartTokenID[:], b[384:416])
	res.PartAmount = new(big.Int).SetBytes(b[416:448])
	return 0, res, nil
}

func isZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// ComposeLineage is the composing verifier as an executable oracle for protocol 6: Compose's order with the lineage relation. It
// returns the lineage (the result and its levels).
func ComposeLineage(cfg *Cfg, op uint8, envelope []byte, b1 B1) (*Lineage, error) {
	if op != OpMint && op != OpReturn {
		return nil, ErrBadOperation
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	env, err := DecodeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	pol, err := CheckPolicyBody(cfg, env)
	if err != nil {
		return nil, err
	}
	var lin *Lineage
	if op == OpMint {
		var res *Result
		if res, err = VerifyMintWith(cfg, env.History, ComposedHistory); err == nil {
			res.PartTokenID, res.PartAmount = res.TokenID, new(big.Int).Set(res.Amount)
			lin = &Lineage{Result: res, Levels: []LevelInfo{{TokenID: res.TokenID, Amount: res.Amount, Leaves: 1}}}
		}
	} else {
		lin, err = verifyLineageMetered(cfg, env.History, ComposedHistory, nil)
	}
	if err != nil {
		return nil, err
	}
	if err := composeTail(&meter{limit: ^uint64(0)}, b1, cfg.Bytes(), env, pol, lin.Result); err != nil {
		return nil, err
	}
	return lin, nil
}

// ComposeGasV2 is the gas NativeComposeV2 charges for input with B1 behaving as b1, or the failure that decides the status. It is the
// estimate a wallet sets its gas limit from; it runs the whole relation.
func ComposeGasV2(input []byte, b1 B1) (uint64, uint64, error) {
	_, status, gas, halt := NativeComposeV2(input, ^uint64(0)>>1, b1)
	return gas, status, halt
}
