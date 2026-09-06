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
	// Five root signers; two different >2/3 subsets sign the SAME seal
	// statement.
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"r1", "r2", "r3", "r4", "r5"} {
		s, _ := newSigner(t)
		signers[id] = s
	}
	ucA, trA := fixtureCertificate(t, []string{"r1", "r2", "r3"}, signers)
	ucB, trB := fixtureCertificate(t, []string{"r1", "r3", "r4", "r5"}, signers)

	// Different signature maps...
	if len(ucA.UnicitySeal.Signatures) == len(ucB.UnicitySeal.Signatures) {
		t.Fatal("test setup: subsets should differ in size")
	}
	if bytes.Equal(mustCBOR(t, ucA.UnicitySeal), mustCBOR(t, ucB.UnicitySeal)) {
		t.Fatal("test setup: the two seals encode identically despite different signatures")
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
		t.Fatalf("alternate signature subsets produced different O_-:\n A=%x\n B=%x", oA.Encode(), oB.Encode())
	}
	if oA.Identity() != oB.Identity() {
		t.Fatal("alternate signature subsets produced different O_- identity")
	}
}

func TestRootOrigin_DifferentAuthenticatedStatementDiffers(t *testing.T) {
	signers := map[string]abcrypto.Signer{}
	for _, id := range []string{"r1", "r2", "r3"} {
		s, _ := newSigner(t)
		signers[id] = s
	}
	uc, tr := fixtureCertificate(t, []string{"r1", "r2", "r3"}, signers)
	o1, _ := RootOriginFromCertificate(uc, tr)

	// A certificate for a different statement: one byte of the certified
	// state root changes.
	uc.InputRecord.Hash = rep(0x23, 32)
	o2, _ := RootOriginFromCertificate(uc, tr)
	if o1.Identity() == o2.Identity() {
		t.Fatal("a different certified statement produced the same O_- identity")
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
