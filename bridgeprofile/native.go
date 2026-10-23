package bridgeprofile

import (
	"errors"
	"math/big"
	"math/bits"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// BRIDGE_COMPOSE_V1 (0x0105), the native composition of B7 direct PR 2 (briefs/dev4-b7-native-compose-spec.md): Compose's relation
// in one native call, with a fixed-size result, a stable status code and incremental gas metering. This file is the executable
// reference the ureth precompile, the contract wrapper and the plug-ins' estimate follow.

// ComposeMarker is bytes32("UNICITY_BRIDGE_COMPOSE_V1"), left aligned.
var ComposeMarker = func() (m [32]byte) { copy(m[:], "UNICITY_BRIDGE_COMPOSE_V1"); return }()

// ComposeOutputBytes is the fixed output: marker, status, cfg, nonce, amount, tokenId, salt, firstPredicateHash, lockDigest,
// releaseTo, nullifier, leafCount (twelve words).
const ComposeOutputBytes = 12 * 32

// MaxComposeInputBytes bounds abi.encode(uint8 op, bytes cfg, bytes envelope): three head words, two length words and the padded
// Cfg and envelope at their bounds.
const MaxComposeInputBytes = 5*32 + MaxCfgBytes + MaxEnvelopeBytes

// The trial schedule (spec section 4). G = ComposeBase + ComposePerByte*B + ComposePerItem*J + ComposePerLeaf*L +
// ComposePerSignature*Q + ComposePerEpoch*E + ComposePerClaim*A + ComposePerStep*P + ComposeGroupGas(K).
const (
	ComposeBase         uint64 = 100_000
	ComposePerByte      uint64 = 2
	ComposePerItem      uint64 = 20
	ComposePerLeaf      uint64 = 16_000
	ComposePerSignature uint64 = 6_000
	ComposePerEpoch     uint64 = 29_900
	ComposePerClaim     uint64 = 2_000
	ComposePerStep      uint64 = 250
	ComposePerGroupStep uint64 = 50
)

// Halts: the only outcomes that are not a status result. A halt consumes all forwarded gas.
var (
	ErrComposeABI      = errors.New("bridgeprofile: native compose input is not the canonical abi.encode(uint8,bytes,bytes)")
	ErrComposeOutOfGas = errors.New("bridgeprofile: native compose out of gas")
	errComposeUnmapped = errors.New("bridgeprofile: error without a compose status")
)

// ComposeStatus is the append-only status table: code i is ComposeStatus[i], code 0 is success (nil). It is the corpus reason
// order (reasons) restricted to the sentinels Compose can return: the trust-base, lock-backing, MPT, RLP, certificate-scan and
// kernel-output-frame reasons live only in VerifyMintBacking, DecodeToken and DecodeResult, which Compose never calls.
var ComposeStatus = []error{
	nil,
	ErrTruncated, ErrTrailing, ErrNonCanonical, ErrForbiddenCBOR, ErrShape, ErrTag, ErrVersion, ErrLength, ErrIntRange,
	ErrABIFraming, ErrBadOperation, ErrDeadline,
	ErrInputTooLarge, ErrTooManyTx, ErrTooManyItems, ErrTooDeep, ErrTooManyPaths, ErrJustificationTooLarge, ErrLockProofTooLarge,
	ErrCfgMismatch, ErrPolicyHash, ErrPolicyTuple, ErrPolicyAnchors, ErrPolicyLeafIndex, ErrPolicyLeafCount, ErrPolicyPartition,
	ErrPredicate, ErrMintShape, ErrLockProofShape, ErrLockProofCfg, ErrMintJustif, ErrMintSalt, ErrMintType, ErrMintData,
	ErrTransferData, ErrCDMismatch, ErrUnlock, ErrUnlockLength, ErrUnlockScalars, ErrUnlockRecovery, ErrUnlockKey, ErrMinterKey,
	ErrRepeatedSID, ErrNoTransfers, ErrHasTransfers, ErrBurnNotFinal, ErrNotBurn, ErrBurnReason, ErrReturnData, ErrReturnAmount,
	ErrReturnRecip, ErrLockInput, ErrZeroDigest, ErrDeadlineMismatch, ErrDeadlineExpired,
	ErrIROpening, ErrIRShape, ErrIRState, ErrIRTime, ErrPathBitmap, ErrAnchorAuth, ErrLeafProof,
}

// ComposeStatusName is the reason name of a status code ("" for success or an unknown code).
func ComposeStatusName(code uint64) string {
	if code == 0 || code >= uint64(len(ComposeStatus)) {
		return ""
	}
	name, _ := Reason(ComposeStatus[code])
	return name
}

// StatusOf maps a Compose error to its status code: the outermost error in err's chain (depth first, in the order Unwrap and
// Unwrap() []error give) that is itself a table sentinel decides. Sentinels unwrap only to their family, so the first sentinel met
// is the most specific reason. An error with no table sentinel in its chain is errComposeUnmapped.
func StatusOf(err error) (uint64, error) { return statusIn(ComposeStatus, err) }

// statusIn is StatusOf over a status table.
func statusIn(table []error, err error) (uint64, error) {
	if err == nil {
		return 0, nil
	}
	var walk func(error) (uint64, bool)
	walk = func(e error) (uint64, bool) {
		if e == nil {
			return 0, false
		}
		for i := 1; i < len(table); i++ {
			if e == table[i] {
				return uint64(i), true
			}
		}
		switch u := e.(type) {
		case interface{ Unwrap() []error }:
			for _, c := range u.Unwrap() {
				if code, ok := walk(c); ok {
					return code, true
				}
			}
		case interface{ Unwrap() error }:
			return walk(u.Unwrap())
		}
		return 0, false
	}
	if code, ok := walk(err); ok {
		return code, nil
	}
	return 0, errComposeUnmapped
}

// ComposeDims are the counts the schedule prices: B input bytes; J CBOR item heads (BridgeItems) of the Cfg, the policy body, the
// history, every anchor UC occurrence and every anchor IR opening; L leaves (the kernel's count, 1 + transfers); Q, E, A, K the
// b1ref grouping of the anchor table's CERT_BATCH_V2 request; P its certificate path steps plus every leaf's RSMT siblings.
type ComposeDims struct{ B, J, L, Q, E, A, K, P uint64 }

// ComposeGroupGas is 50*K*ceil(log2 K): sort-based grouping of K claim occurrences (zero for K <= 1).
func ComposeGroupGas(k uint64) uint64 {
	if k <= 1 {
		return 0
	}
	return ComposePerGroupStep * k * uint64(bits.Len64(k-1))
}

// ComposeGas is the whole charge of a call that succeeds.
func ComposeGas(d ComposeDims) uint64 {
	return ComposeBase + ComposePerByte*d.B + ComposePerItem*d.J + ComposePerLeaf*d.L + ComposePerSignature*d.Q +
		ComposePerEpoch*d.E + ComposePerClaim*d.A + ComposePerStep*d.P + ComposeGroupGas(d.K)
}

// EncodeComposeInput is abi.encode(uint8 op, bytes cfg, bytes envelope): the kernel input's ABI with the envelope as payload.
func EncodeComposeInput(op uint8, cfg, envelope []byte) ([]byte, error) {
	return EncodeKernelInput(op, cfg, envelope)
}

type meter struct{ used, limit uint64 }

func (m *meter) charge(n uint64) error {
	if n > m.limit-m.used {
		m.used = m.limit
		return ErrComposeOutOfGas
	}
	m.used += n
	return nil
}

// historyScan is the history's native item scan under ComposedHistory's item bound.
func historyScan(history []byte) (*item, int, error) {
	s := scanner{b: history, native: true, maxItems: ComposedHistory.Items}
	it, err := s.item(0)
	if err != nil {
		return nil, 0, err
	}
	if s.pos != len(history) {
		return nil, 0, ErrTrailing
	}
	return &it, s.tokens, nil
}

// historyItems is the history's J: its item heads under the native scan, zero if it does not scan.
func historyItems(history []byte) uint64 {
	_, n, err := historyScan(history)
	if err != nil {
		return 0
	}
	return uint64(n)
}

// historyLeaves is the kernel's leaf count read from the history's head before any verification, as B2 counts it: the history is
// [mint, transfers] and L = 1 + len(transfers); a history whose head is not that shape has no count (zero).
func historyLeaves(history []byte) uint64 {
	root, _, err := historyScan(history)
	if err != nil || !root.isArray(2) || root.kids[1].major != majArray {
		return 0
	}
	return 1 + uint64(len(root.kids[1].kids))
}

// NativeCompose is BRIDGE_COMPOSE_V1 over input with gasLimit forwarded. It returns the 384-byte output, its status and the gas
// charged, or a halt (ErrComposeABI, ErrComposeOutOfGas) with gas = gasLimit. The metering, each charge taken before the work it
// pays for and the first failure deciding the status:
//
//  1. 100000 + 2*B; an input over MaxComposeInputBytes is ErrInputTooLarge; a non-canonical ABI halts; an op other than mint or
//     return is ErrBadOperation.
//  2. The Cfg is decoded (DecodeCfg); its J is charged once it decodes, then Validate.
//  3. The envelope is decoded (DecodeEnvelope); the policy body is checked (CheckPolicyBody) and its J charged once it passes.
//  4. The history's J (when it scans) and 16000*L (historyLeaves) are charged, then the kernel (VerifyMint or VerifyReturn) runs.
//  5. PlanAnchors; then the anchor scans in computeGate's order (ScanAnchor, the bridge item scan, the b1ref grouping): the UC and IR
//     openings' J is charged once the item scan passes, and 6000*Q + 29900*E + 2000*A + 250*P_cert + 50*K*ceil(log2 K) once the
//     grouping passes; then every leaf path's shape (LeafPathGas).
//  6. B1 authenticates the anchor table; each anchor's IR is opened and the leaf times are compared.
//  7. Per leaf: 250*p_i, then its RSMT membership.
//
// J of an object is charged only after that object scans successfully: a failing object adds nothing.
func NativeCompose(input []byte, gasLimit uint64, b1 B1) (out [ComposeOutputBytes]byte, status, gas uint64, halt error) {
	m := &meter{limit: gasLimit}
	res, err := nativeCompose(input, m, b1)
	if errors.Is(err, ErrComposeABI) || errors.Is(err, ErrComposeOutOfGas) {
		return out, 0, gasLimit, err
	}
	copy(out[:32], ComposeMarker[:])
	status, mapErr := StatusOf(err)
	if mapErr != nil {
		panic(mapErr.Error() + ": " + err.Error())
	}
	big.NewInt(int64(status)).FillBytes(out[32:64])
	if status == 0 {
		copy(out[64:96], res.Cfg[:])
		new(big.Int).SetUint64(res.Nonce).FillBytes(out[96:128])
		if res.Amount != nil {
			res.Amount.FillBytes(out[128:160])
		}
		copy(out[160:192], res.TokenID[:])
		copy(out[192:224], res.Salt[:])
		copy(out[224:256], res.FirstPredicateHash[:])
		copy(out[256:288], res.LockDigest[:])
		copy(out[300:320], res.ReleaseTo[:])
		copy(out[320:352], res.Nullifier[:])
		new(big.Int).SetUint64(uint64(len(res.Leaves))).FillBytes(out[352:384])
	}
	return out, status, m.used, nil
}

func nativeCompose(input []byte, m *meter, b1 B1) (*Result, error) {
	items := itemsOf
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
	if err := m.charge(ComposePerItem * items(cfgBytes)); err != nil {
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
	if err := m.charge(ComposePerItem * items(env.PolicyBody)); err != nil {
		return nil, err
	}
	if err := m.charge(ComposePerItem*historyItems(env.History) + ComposePerLeaf*historyLeaves(env.History)); err != nil {
		return nil, err
	}
	var res *Result
	if op == OpMint {
		res, err = VerifyMintWith(cfg, env.History, ComposedHistory)
	} else {
		res, err = VerifyReturnWith(cfg, env.History, ComposedHistory)
	}
	if err != nil {
		return nil, err
	}
	if err := composeTail(m, b1, cfgBytes, env, pol, res); err != nil {
		return nil, err
	}
	return res, nil
}

// itemsOf is J of one object: its bridge item count, zero if it does not scan.
func itemsOf(b []byte) uint64 {
	n, err := BridgeItems(b)
	if err != nil {
		return 0
	}
	return uint64(n)
}

// composeTail is steps 5 to 7 of NativeCompose, shared with the lineage composition: the anchor plan and scans, the grouping charge,
// B1 authentication, the time comparison and one membership per leaf of res, in leaf order.
func composeTail(m *meter, b1 B1, cfgBytes []byte, env *Envelope, pol Policy, res *Result) error {
	sids := make([][32]byte, len(res.Leaves))
	for i, l := range res.Leaves {
		sids[i] = l.SID
	}
	plan, err := PlanAnchors(pol, env, sids)
	if err != nil {
		return err
	}
	// The anchor scans in computeGate's order, with the same failures.
	for j := range env.Anchors {
		if err := ScanAnchor(&env.Anchors[j]); err != nil {
			return err
		}
	}
	if _, err := bridgeJ(cfgBytes, env); err != nil {
		return err
	}
	var anchorItems uint64
	for j := range env.Anchors {
		anchorItems += itemsOf(env.Anchors[j].UC) + itemsOf(env.Anchors[j].InputRecord)
	}
	if err := m.charge(ComposePerItem * anchorItems); err != nil {
		return err
	}
	grouping, err := b1ref.GroupWith(CertBatchRequest(env.Anchors), b1ref.Composed)
	if err != nil {
		return ErrAnchorAuth
	}
	if err := m.charge(ComposePerSignature*grouping.Q + ComposePerEpoch*grouping.E + ComposePerClaim*grouping.A +
		ComposePerStep*grouping.P + ComposeGroupGas(grouping.K)); err != nil {
		return err
	}
	steps := make([]uint64, len(env.LeafProofs))
	for i, p := range env.LeafProofs {
		_, s, err := LeafPathGas(p)
		if err != nil {
			return err
		}
		steps[i] = s
	}
	if err := b1.AuthenticateAnchors(env.Anchors); err != nil {
		return ErrAnchorAuth
	}
	times := make([]uint64, len(env.Anchors))
	for j := range env.Anchors {
		ir, err := OpenAnchor(&env.Anchors[j])
		if err != nil {
			return err
		}
		times[j] = ir.Timestamp
	}
	for i, l := range res.Leaves {
		if l.ReferenceTime > times[plan.LeafAnchor[i]] {
			return ErrIRTime
		}
	}
	for i, l := range res.Leaves {
		if err := m.charge(ComposePerStep * steps[i]); err != nil {
			return err
		}
		a := &env.Anchors[plan.LeafAnchor[i]]
		if err := b1.VerifyMember(a.ExpectedStateRoot, l.SID, l.Value, env.LeafProofs[i]); err != nil {
			return ErrLeafProof
		}
	}
	return nil
}

// decodeComposeInput is DecodeKernelInput without the kernel's size bound (the caller applies MaxComposeInputBytes): any framing
// that is not the canonical encoding of the three fields is ErrComposeABI.
func decodeComposeInput(b []byte) (op uint8, cfg, envelope []byte, err error) {
	if len(b)%32 != 0 || len(b) < 3*32 {
		return 0, nil, nil, ErrComposeABI
	}
	vals, uerr := kernelInArgs.Unpack(b)
	if uerr != nil || len(vals) != 3 {
		return 0, nil, nil, ErrComposeABI
	}
	op, cfg, envelope = vals[0].(uint8), vals[1].([]byte), vals[2].([]byte)
	if re, rerr := EncodeComposeInput(op, cfg, envelope); rerr != nil || string(re) != string(b) {
		return 0, nil, nil, ErrComposeABI
	}
	return op, cfg, envelope, nil
}
