package b1ref

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-go-base/types"
)

// claim is one decoded certificate claim of a UC_V1/SHARED_SEAL_V1 call.
type claim struct {
	partition  uint32
	shardBytes []byte
	shard      types.ShardID
	shardConf  [32]byte
	stateRoot  [32]byte
	irHash     [32]byte
	uc         *types.UnicityCertificate
	sealRaw    []byte
	sigs       *item // signature map of the seal
	pathSteps  uint64
}

type certCall struct {
	view   *trustView
	claims []claim
	size   uint64
	charge uint64
}

// header parses `version:u8=1 | flags:u8=0 | count:u16` and returns the count.
func header(in []byte) (uint16, error) {
	if len(in) < 4 {
		return 0, ErrTruncated
	}
	if in[0] != 1 {
		return 0, ErrVersion
	}
	if in[1] != 0 {
		return 0, ErrFlags
	}
	return binary.BigEndian.Uint16(in[2:4]), nil
}

// reader consumes the call with checked slicing.
type reader struct {
	b   []byte
	pos int
}

func (r *reader) left() uint64 { return uint64(len(r.b) - r.pos) }

func (r *reader) take(n uint64) ([]byte, error) {
	if n > r.left() {
		return nil, ErrTruncated
	}
	out := r.b[r.pos : r.pos+int(n)]
	r.pos += int(n)
	return out, nil
}

func (r *reader) u16() (uint64, error) {
	b, err := r.take(2)
	if err != nil {
		return 0, err
	}
	return uint64(binary.BigEndian.Uint16(b)), nil
}

func (r *reader) u32() (uint64, error) {
	b, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return uint64(binary.BigEndian.Uint32(b)), nil
}

// parseCertCall decodes and bound-checks a whole UC_V1 (shared=false) or
// SHARED_SEAL_V1 (shared=true) call. Every malformed input is rejected here,
// before any semantic check, so the verdict never depends on evaluation order.
func parseCertCall(in []byte, shared bool) (*certCall, error) {
	if len(in) > MaxCallBytes {
		return nil, ErrInputTooLarge
	}
	count, err := header(in)
	if err != nil {
		return nil, err
	}
	if count < 1 || count > MaxClaims || (!shared && count != 1) {
		return nil, ErrCount
	}
	r := &reader{b: in, pos: 4}
	tokens := 0

	viewLen, err := r.u32()
	if err != nil {
		return nil, err
	}
	if viewLen > MaxViewBytes {
		return nil, ErrViewTooLarge
	}
	viewRaw, err := r.take(viewLen)
	if err != nil {
		return nil, err
	}
	view, err := scanView(viewRaw, &tokens)
	if err != nil {
		return nil, fmt.Errorf("trust view: %w", err)
	}

	call := &certCall{view: view, size: uint64(len(in)), claims: make([]claim, 0, count)}
	for i := 0; i < int(count); i++ {
		c, err := parseClaim(r, &tokens)
		if err != nil {
			return nil, fmt.Errorf("claim %d: %w", i, err)
		}
		if i > 0 {
			prev := &call.claims[i-1]
			if cmp := compareClaimID(prev, &c); cmp > 0 {
				return nil, ErrClaimOrder
			}
		}
		call.claims = append(call.claims, c)
	}
	if r.left() != 0 {
		return nil, ErrTrailingBytes
	}

	var steps uint64
	for i := range call.claims {
		steps += call.claims[i].pathSteps
	}
	s := uint64(call.claims[0].sigs.arg)
	call.charge = UCGas(call.size, uint64(len(view.members)), s, uint64(len(call.claims)), steps)
	return call, nil
}

func compareClaimID(a, b *claim) int {
	if a.partition != b.partition {
		if a.partition < b.partition {
			return -1
		}
		return 1
	}
	return bytes.Compare(a.shardBytes, b.shardBytes)
}

func parseClaim(r *reader, tokens *int) (claim, error) {
	var c claim
	part, err := r.u32()
	if err != nil {
		return c, err
	}
	c.partition = uint32(part)
	shardLen, err := r.u16()
	if err != nil {
		return c, err
	}
	if shardLen > MaxShardBytes {
		return c, ErrShardTooDeep
	}
	if c.shardBytes, err = r.take(shardLen); err != nil {
		return c, err
	}
	if c.shard, err = decodeShard(c.shardBytes); err != nil {
		return c, err
	}
	for _, dst := range []*[32]byte{&c.shardConf, &c.stateRoot, &c.irHash} {
		b, err := r.take(32)
		if err != nil {
			return c, err
		}
		copy(dst[:], b)
	}
	ucLen, err := r.u32()
	if err != nil {
		return c, err
	}
	if ucLen > MaxUCBytes {
		return c, ErrUCTooLarge
	}
	ucRaw, err := r.take(ucLen)
	if err != nil {
		return c, err
	}
	if err := decodeUC(&c, ucRaw, tokens); err != nil {
		return c, fmt.Errorf("unicity certificate: %w", err)
	}
	return c, nil
}

// decodeShard decodes the native shard bit string and requires the exact
// canonical re-encoding and the depth bound.
func decodeShard(b []byte) (types.ShardID, error) {
	var id types.ShardID
	if err := id.UnmarshalCBOR(cborBytes(b)); err != nil {
		return id, ErrShardEncoding
	}
	if id.Length() > MaxShardDepth {
		return id, ErrShardTooDeep
	}
	if !bytes.Equal(id.Bytes(), b) {
		return id, ErrShardEncoding
	}
	return id, nil
}

// cborBytes is the shortest-form CBOR byte string for b (len(b) <= 65535).
func cborBytes(b []byte) []byte {
	var out []byte
	switch n := len(b); {
	case n < 24:
		out = []byte{0x40 | byte(n)}
	case n < 256:
		out = []byte{0x58, byte(n)}
	default:
		out = []byte{0x59, byte(n >> 8), byte(n)}
	}
	return append(out, b...)
}

// decodeUC runs the strict scan and shape rules over the UC bytes, then the
// native decoder, and requires byte-exact re-encoding.
func decodeUC(c *claim, raw []byte, tokens *int) error {
	root, err := scanOne(raw, tokens)
	if err != nil {
		return err
	}
	body, ok := root.tagContent(types.UnicityCertificateTag)
	if !ok || !body.isArray(7) {
		return ErrShape
	}
	k := body.kids
	if !k[0].isUint() || k[0].arg != 1 {
		return ErrVersion
	}
	if err := shapeIR(&k[1]); err != nil {
		return fmt.Errorf("input record: %w", err)
	}
	if !k[2].isHash() || !k[3].isHash() {
		return ErrShape
	}
	if err := shapeShardCert(&k[4]); err != nil {
		return fmt.Errorf("shard tree certificate: %w", err)
	}
	steps, err := shapeUnicityCert(&k[5])
	if err != nil {
		return fmt.Errorf("unicity tree certificate: %w", err)
	}
	sigs, err := shapeSeal(&k[6])
	if err != nil {
		return fmt.Errorf("unicity seal: %w", err)
	}
	c.sigs = sigs
	c.pathSteps = steps + k[4].kids[0].kids[2].arg
	c.sealRaw = raw[k[6].start:k[6].end]

	var uc types.UnicityCertificate
	if err := uc.UnmarshalCBOR(raw); err != nil {
		return fmt.Errorf("%w: %v", ErrNativeDecode, err)
	}
	if again, err := uc.MarshalCBOR(); err != nil || !bytes.Equal(again, raw) {
		return ErrReencode
	}
	c.uc = &uc
	return nil
}

func shapeIR(it *item) error {
	body, ok := it.tagContent(types.InputRecordTag)
	if !ok || !body.isArray(10) {
		return ErrShape
	}
	k := body.kids
	if !k[0].isUint() || k[0].arg != 1 {
		return ErrVersion
	}
	if !k[1].isUint() || !k[2].isUint() || !k[6].isUint() || !k[8].isUint() {
		return ErrShape
	}
	// stateHash is bstr32 (B1 is stricter than the native nullable field);
	// the other hashes are null or bstr32.
	if !k[3].isNullOrHash() || !k[4].isHash() || !k[7].isNullOrHash() || !k[9].isNullOrHash() {
		return ErrShape
	}
	if k[5].major == majBytes && len(k[5].data) > MaxSummaryBytes {
		return ErrSummaryTooLong
	}
	if !k[5].null && k[5].major != majBytes {
		return ErrShape
	}
	return nil
}

func shapeShardCert(it *item) error {
	body, ok := it.tagContent(types.ShardTreeCertificateTag)
	if !ok || !body.isArray(3) {
		return ErrShape
	}
	k := body.kids
	if !k[0].isUint() || k[0].arg != 1 {
		return ErrVersion
	}
	if k[1].major != majBytes || k[2].major != majArray {
		return ErrShape
	}
	if len(k[1].data) == 0 {
		return ErrShardEncoding
	}
	if len(k[1].data) > MaxShardBytes {
		return ErrShardTooDeep
	}
	shard, err := decodeShard(k[1].data)
	if err != nil {
		return err
	}
	if k[2].arg > MaxShardSiblings {
		return ErrTooManySiblings
	}
	if k[2].arg != uint64(shard.Length()) {
		return ErrShape // exactly one sibling per shard bit
	}
	for i := range k[2].kids {
		if !k[2].kids[i].isHash() {
			return ErrShape
		}
	}
	return nil
}

func shapeUnicityCert(it *item) (steps uint64, err error) {
	body, ok := it.tagContent(types.UnicityTreeCertificateTag)
	if !ok || !body.isArray(3) {
		return 0, ErrShape
	}
	k := body.kids
	if !k[0].isUint() || k[0].arg != 1 {
		return 0, ErrVersion
	}
	if !k[1].isUint() || k[1].arg > math.MaxUint32 || k[2].major != majArray {
		return 0, ErrShape
	}
	if k[2].arg > MaxUnicitySteps {
		return 0, ErrTooManySteps
	}
	for i := range k[2].kids {
		p := &k[2].kids[i]
		if !p.isArray(2) || !p.kids[0].isUint() || p.kids[0].arg > math.MaxUint32 || !p.kids[1].isHash() {
			return 0, ErrShape
		}
	}
	return k[2].arg, nil
}

// shapeSeal returns the signature map item.
func shapeSeal(it *item) (*item, error) {
	body, ok := it.tagContent(types.UnicitySealTag)
	if !ok || !body.isArray(8) {
		return nil, ErrShape
	}
	k := body.kids
	if !k[0].isUint() || k[0].arg != 1 {
		return nil, ErrVersion
	}
	if !k[1].isUint() || k[1].arg > math.MaxUint16 || !k[2].isUint() || !k[3].isUint() || !k[4].isUint() {
		return nil, ErrShape
	}
	if !k[5].isHash() || !k[6].isHash() || k[7].major != majMap {
		return nil, ErrShape
	}
	if k[7].arg > MaxSigsPerSeal {
		return nil, ErrTooManySigs
	}
	for i := 0; i < len(k[7].kids); i += 2 {
		key, val := &k[7].kids[i], &k[7].kids[i+1]
		if key.major != majText || val.major != majBytes {
			return nil, ErrShape
		}
		if len(key.data) > MaxNodeIDBytes {
			return nil, ErrNodeIDTooLong
		}
	}
	return &k[7], nil
}

// ucFolds runs the native UC validation and the two native tree folds and
// returns the unicity tree root they imply.
func ucFolds(c *claim) error {
	work("fold")
	uc := c.uc
	if uc.UnicityTreeCertificate.Partition != types.PartitionID(c.partition) {
		return ErrPartition
	}
	if !uc.ShardTreeCertificate.Shard.Equal(c.shard) {
		return ErrShard
	}
	if !bytes.Equal(uc.ShardConfHash, c.shardConf[:]) {
		return ErrShardConf
	}
	if err := uc.IsValid(types.PartitionID(c.partition), c.shard, c.shardConf[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrNativeInvalid, err)
	}
	shardRoot, err := uc.ShardTreeCertificate.ComputeCertificateHash(uc.InputRecord, uc.TRHash, uc.ShardConfHash, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	treeRoot, err := uc.UnicityTreeCertificate.EvalAuthPath(shardRoot, crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	if !bytes.Equal(treeRoot, uc.UnicitySeal.Hash) {
		return ErrTreeRoot
	}
	if !bytes.Equal(uc.InputRecord.Hash, c.stateRoot[:]) {
		return ErrStateRoot
	}
	irBytes, err := uc.InputRecord.Bytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	if digest := sha256.Sum256(irBytes); digest != c.irHash {
		return ErrIRHash
	}
	return nil
}
