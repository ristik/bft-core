package evmroot

import (
	"bytes"
	"crypto/sha256"
	"testing"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// D1 fixture-based tests: real types.UnicitySeal / UnicityCertificate /
// TechnicalRecord values, actual secp256k1 signatures, and an independent
// CBOR oracle (bft-go-base's fxamacker core-deterministic encoder) for the
// expected canonical bytes.

func newSigner(t *testing.T) (abcrypto.Signer, []byte) {
	t.Helper()
	s, err := abcrypto.NewInMemorySecp256K1Signer()
	if err != nil {
		t.Fatal(err)
	}
	v, err := s.Verifier()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := v.MarshalPublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return s, pub
}

// fixtureTrustBase builds an equal-stake 5-node root trust base. Its
// default quorum threshold is ⌊5·2/3⌋+1 = 4.
func fixtureTrustBase(t *testing.T, ids []string, pubs map[string][]byte) *types.RootTrustBaseV1 {
	t.Helper()
	nodes := make([]*types.NodeInfo, 0, len(ids))
	for _, id := range ids {
		nodes = append(nodes, &types.NodeInfo{NodeID: id, SigKey: pubs[id], Stake: 1})
	}
	tb, err := types.NewTrustBase(types.NetworkLocal, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if tb.GetQuorumThreshold() != 4 {
		t.Fatalf("unexpected quorum threshold %d", tb.GetQuorumThreshold())
	}
	return tb
}

// fixtureCertificate builds a certificate whose committed content is fixed
// and signs its UnicitySeal with the given signer subset. The shard-tree
// and unicity-tree certificates are left zero — RootOriginFromCertificate
// reads none of them, which is the point.
func fixtureCertificate(t *testing.T, signerIDs []string, signers map[string]abcrypto.Signer) (*types.UnicityCertificate, *certification.TechnicalRecord) {
	t.Helper()
	ir := &types.InputRecord{
		Version: 1, RoundNumber: 57, Epoch: 1,
		PreviousHash: rep(0x11, 32), Hash: rep(0x22, 32),
		SummaryValue: []byte{}, Timestamp: 1_726_000_000,
		BlockHash: rep(0x33, 32), SumOfEarnedFees: 0,
	}
	tr := &certification.TechnicalRecord{
		Round: 57, Epoch: 1, Leader: "evm-node-2",
		StatHash: rep(0x66, 32), FeeHash: rep(0x77, 32),
	}
	trHash, err := tr.Hash()
	if err != nil {
		t.Fatal(err)
	}
	seal := &types.UnicitySeal{
		Version:              1,
		NetworkID:            types.NetworkLocal, // 3
		RootChainRoundNumber: 104,
		Epoch:                1,
		Timestamp:            1_726_000_000,
		PreviousHash:         rep(0x90, 32),
		Hash:                 rep(0xA1, 32),
	}
	for _, id := range signerIDs {
		if err := seal.Sign(id, signers[id]); err != nil {
			t.Fatalf("sign %s: %v", id, err)
		}
	}
	uc := &types.UnicityCertificate{
		Version:       1,
		InputRecord:   ir,
		TRHash:        trHash,
		ShardConfHash: rep(0x55, 32),
		UnicitySeal:   seal,
	}
	return uc, tr
}

func TestRootOrigin_TwoValidSignatureSubsetsAgree(t *testing.T) {
	// Five equal-stake root signers; quorum threshold is 4. Two DIFFERENT
	// 4-of-5 subsets each independently clear quorum when verified against
	// the trust base, and both project to a byte-identical O_-.
	ids := []string{"r1", "r2", "r3", "r4", "r5"}
	signers := map[string]abcrypto.Signer{}
	pubs := map[string][]byte{}
	for _, id := range ids {
		s, p := newSigner(t)
		signers[id], pubs[id] = s, p
	}
	tb := fixtureTrustBase(t, ids, pubs)

	ucA, trA := fixtureCertificate(t, []string{"r1", "r2", "r3", "r4"}, signers)
	ucB, trB := fixtureCertificate(t, []string{"r2", "r3", "r4", "r5"}, signers)

	// Each subset actually reaches quorum against the trust base.
	if err := ucA.UnicitySeal.Verify(tb); err != nil {
		t.Fatalf("subset A did not verify to quorum: %v", err)
	}
	if err := ucB.UnicitySeal.Verify(tb); err != nil {
		t.Fatalf("subset B did not verify to quorum: %v", err)
	}
	// A 3-of-5 subset is below quorum — the test would be meaningless if
	// any 3 signatures "passed".
	ucLow, _ := fixtureCertificate(t, []string{"r1", "r2", "r3"}, signers)
	if err := ucLow.UnicitySeal.Verify(tb); err == nil {
		t.Fatal("a 3-of-5 subset verified to quorum — threshold not enforced")
	}

	if bytes.Equal(mustCBOR(t, ucA.UnicitySeal), mustCBOR(t, ucB.UnicitySeal)) {
		t.Fatal("test setup: the two seals encode identically despite different signature sets")
	}

	oA, err := RootOriginFromCertificate(ucA, trA)
	if err != nil {
		t.Fatal(err)
	}
	oB, err := RootOriginFromCertificate(ucB, trB)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(oA.Encode(), oB.Encode()) {
		t.Fatalf("two verified quorum subsets produced different O_-:\n A=%x\n B=%x", oA.Encode(), oB.Encode())
	}
	if oA.Identity() != oB.Identity() {
		t.Fatal("two verified quorum subsets produced different O_- identity")
	}
}

func TestRootOrigin_DifferentAuthenticatedStatementDiffers(t *testing.T) {
	ids := []string{"r1", "r2", "r3", "r4", "r5"}
	signers := map[string]abcrypto.Signer{}
	pubs := map[string][]byte{}
	for _, id := range ids {
		s, p := newSigner(t)
		signers[id], pubs[id] = s, p
	}
	tb := fixtureTrustBase(t, ids, pubs)

	uc, tr := fixtureCertificate(t, []string{"r1", "r2", "r3", "r4"}, signers)
	if err := uc.UnicitySeal.Verify(tb); err != nil {
		t.Fatalf("baseline certificate did not verify: %v", err)
	}
	o1, _ := RootOriginFromCertificate(uc, tr)

	// A genuinely different certified statement: mutate the IR and
	// RE-CERTIFY — recompute the seal's Unicity Tree root over the new IR
	// and re-sign with a fresh quorum.
	mutIR := *uc.InputRecord
	mutIR.Hash = rep(0x23, 32)
	irBytes, err := mutIR.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	seal2 := &types.UnicitySeal{
		Version: 1, NetworkID: types.NetworkLocal, RootChainRoundNumber: 105, Epoch: 1,
		Timestamp: 1_726_000_001, PreviousHash: uc.UnicitySeal.Hash,
		Hash: sha256Slice(irBytes), // a real (if simplified) recommitment over the mutated IR
	}
	for _, id := range []string{"r1", "r2", "r3", "r4"} {
		if err := seal2.Sign(id, signers[id]); err != nil {
			t.Fatal(err)
		}
	}
	if err := seal2.Verify(tb); err != nil {
		t.Fatalf("re-certified seal did not verify: %v", err)
	}
	uc2 := &types.UnicityCertificate{Version: 1, InputRecord: &mutIR, TRHash: uc.TRHash, ShardConfHash: uc.ShardConfHash, UnicitySeal: seal2}
	o2, _ := RootOriginFromCertificate(uc2, tr)
	if o1.Identity() == o2.Identity() {
		t.Fatal("a re-certified different statement produced the same O_- identity")
	}
}

// TestRootOrigin_IndependentCBOROracle checks the hand-rolled encoder in
// cbor.go against bft-go-base's fxamacker CoreDetEnc encoder for the same
// logical O_- array — an independent second implementation of the same
// RFC 8949 core-deterministic rules.
func TestRootOrigin_IndependentCBOROracle(t *testing.T) {
	o := sampleOrigin()

	// The same structure as canonicalBody(), expressed for the reference encoder.
	var irBlockHash any = o.IR.BlockHash
	if len(o.IR.BlockHash) == 0 {
		irBlockHash = nil // CBOR null
	}
	oracle := []any{
		o.NetworkID, o.RootRound, o.RootEpoch, o.ReferenceTime, o.UnicityTreeRoot,
		[]any{o.IR.Round, o.IR.Epoch, o.IR.PreviousHash, o.IR.Hash, o.IR.Timestamp, irBlockHash},
		o.TRHash, o.ShardConfHash,
	}
	want, err := types.Cbor.Marshal(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if got := o.Encode(); !bytes.Equal(got, want) {
		t.Fatalf("hand-rolled encoder disagrees with the fxamacker oracle:\n got  %x\n want %x", got, want)
	}

	// Same for a quiet origin whose block hash is null.
	q := sampleOrigin()
	q.IR.PreviousHash, q.IR.Hash, q.IR.BlockHash = rep(0x22, 32), rep(0x22, 32), nil
	qOracle := []any{
		q.NetworkID, q.RootRound, q.RootEpoch, q.ReferenceTime, q.UnicityTreeRoot,
		[]any{q.IR.Round, q.IR.Epoch, q.IR.PreviousHash, q.IR.Hash, q.IR.Timestamp, nil},
		q.TRHash, q.ShardConfHash,
	}
	qWant, err := types.Cbor.Marshal(qOracle)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(q.Encode(), qWant) {
		t.Fatalf("quiet-origin encoder disagrees with the oracle:\n got  %x\n want %x", q.Encode(), qWant)
	}
}

func TestExtraData_IndependentOracle(t *testing.T) {
	ri := sampleRootInput()
	// H(CBOR(rootInput)) via the oracle-encoded body.
	body := []any{
		ri.Version, ri.NetworkID, ri.PartitionID, ri.ShardID, ri.Round,
		ri.CertifiedEpoch, ri.AuthorizedEpoch, ri.ParentHash,
		[]any{
			ri.Origin.NetworkID, ri.Origin.RootRound, ri.Origin.RootEpoch, ri.Origin.ReferenceTime, ri.Origin.UnicityTreeRoot,
			[]any{ri.Origin.IR.Round, ri.Origin.IR.Epoch, ri.Origin.IR.PreviousHash, ri.Origin.IR.Hash, ri.Origin.IR.Timestamp, ri.Origin.IR.BlockHash},
			ri.Origin.TRHash, ri.Origin.ShardConfHash,
		},
		[]any{ri.TE.Round, ri.TE.Epoch, ri.TE.Leader, ri.TE.StatHash, ri.TE.FeeHash},
		[]any{},
	}
	enc, err := types.Cbor.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(enc)
	if ri.ExtraData() != Hash32(want) {
		t.Fatalf("extraData disagrees with the oracle:\n got  %x\n want %x", ri.ExtraData(), want)
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	b, err := types.Cbor.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --- certificate selection: asymmetric delivery + late repeat -------------

func TestSelection_AsymmetricDeliveryAgrees(t *testing.T) {
	o := sampleOrigin() // root round 104, authorizes shard round 57
	ref, err := RefFromOrigin(o)
	if err != nil {
		t.Fatal(err)
	}
	const n = 57
	// Node A verified exactly the bound certificate.
	certA := verifiedCertFromOrigin(o, n, true)
	// Node B ALSO received a later valid repeat (same IR, root round 130)
	// but validates the block's bound certificate, not whichever it saw
	// last. Both nodes hold the same seal-registry cursor (104).
	certB := verifiedCertFromOrigin(o, n, true)

	ra := ValidateBoundCertificate(ref, certA, n, 104)
	rb := ValidateBoundCertificate(ref, certB, n, 104)
	if !ra.Accept || !rb.Accept {
		t.Fatalf("asymmetric delivery: A=%+v B=%+v", ra, rb)
	}
	if ra != rb {
		t.Fatal("two honest nodes reached different selection results for the same bound certificate")
	}
}

func TestSelection_StaleBindingRejected(t *testing.T) {
	// The proposer bound a certificate at root round 90, but the follower
	// has already applied root round 104 to its seal registry.
	stale := sampleOrigin()
	stale.RootRound = 90
	ref, _ := RefFromOrigin(stale)
	cert := verifiedCertFromOrigin(stale, 57, true)
	res := ValidateBoundCertificate(ref, cert, 57, 104)
	if res.Accept {
		t.Fatal("a stale bound certificate behind the registry cursor was accepted")
	}
}

func TestSelection_LateRepeatDoesNotChangeAcceptedResult(t *testing.T) {
	// A late repeat the proposer did NOT bind must not affect validation:
	// the follower validates the bound original; the repeat is simply
	// unused for this block. The follower's cursor is still at the
	// original's root round.
	orig := sampleOrigin() // root round 104
	ref, _ := RefFromOrigin(orig)
	cert := verifiedCertFromOrigin(orig, 57, true)
	if !ValidateBoundCertificate(ref, cert, 57, 104).Accept {
		t.Fatal("bound original rejected while an unbound repeat exists")
	}
	// Once the follower APPLIES the repeat (cursor moves to 130), a block
	// still binding the original is correctly rejected and re-proposed.
	if ValidateBoundCertificate(ref, cert, 57, 130).Accept {
		t.Fatal("block binding a superseded certificate accepted after the repeat was applied")
	}
}
