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

// claim is one decoded claim occurrence of a CERT_BATCH_V2 call.
type claim struct {
	partition  uint32
	shardBytes []byte
	shard      types.ShardID
	shardConf  [32]byte
	stateRoot  [32]byte
	irHash     [32]byte
	uc         *types.UnicityCertificate
	ucRaw      []byte
	sealRaw    []byte
	sigs       *item // signature map of the seal
	pathSteps  uint64
}

// header parses `version:u8 | flags:u8=0 | count:u16` for the given version and returns the count.
func header(in []byte, version byte) (uint16, error) {
	if len(in) < 4 {
		return 0, ErrTruncated
	}
	if in[0] != version {
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

// parseClaims decodes every claim occurrence of a request scanBatch accepted (k occurrences after the header), including the
// native decode and byte-exact re-encoding of each certificate. It runs only after the full charge is reserved.
func parseClaims(in []byte, k uint64) ([]claim, error) {
	r := &reader{b: in, pos: 4}
	tokens := 0
	claims := make([]claim, 0, k)
	for i := uint64(0); i < k; i++ {
		c, err := parseClaim(r, &tokens)
		if err != nil {
			return nil, fmt.Errorf("claim %d: %w", i, err)
		}
		claims = append(claims, c)
	}
	if r.left() != 0 {
		return nil, ErrTrailingBytes
	}
	return claims, nil
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
	if err := decodeUC(&c, ucRaw, tokens, MaxSigsPerSeal); err != nil {
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
func decodeUC(c *claim, raw []byte, tokens *int, maxSigs uint64) error {
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
	sigs, err := shapeSeal(&k[6], maxSigs)
	if err != nil {
		return fmt.Errorf("unicity seal: %w", err)
	}
	c.sigs = sigs
	c.pathSteps = steps + k[4].kids[0].kids[2].arg
	c.ucRaw = raw
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
	if k[1].major != majBytes || (!k[2].null && k[2].major != majArray) {
		return ErrShape
	}
	if len(k[1].data) == 0 {
		return ErrShardEncoding
	}
	if len(k[1].data) > MaxShardBytes {
		return ErrShardTooDeep
	}
	_, err := decodeShard(k[1].data)
	if err != nil {
		return err
	}
	if k[2].arg > MaxShardSiblings {
		return ErrTooManySiblings
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
	if !k[1].isUint() || k[1].arg > math.MaxUint32 || (!k[2].null && k[2].major != majArray) {
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
func shapeSeal(it *item, maxSigs uint64) (*item, error) {
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
	if !k[5].isHash() || !k[6].isHash() || (!k[7].null && k[7].major != majMap) {
		return nil, ErrShape
	}
	if k[7].arg > maxSigs {
		return nil, ErrTooManySigs
	}
	for i := 0; i < len(k[7].kids); i += 2 {
		key, val := &k[7].kids[i], &k[7].kids[i+1]
		if key.major != majText || val.major != majBytes {
			return nil, ErrShape
		}
		if (len(val.data) != 64 && len(val.data) != 65) || (len(val.data) == 65 && val.data[64] > 1) {
			return nil, ErrSigFormat
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

// protocol3SigsPerSeal is the step-0 per-seal signature bound that ScanUC keeps for the protocol-3 bridge in bridgeprofile, whose
// sealed corpus pins it; CERT_BATCH_V2 enforces MaxSigsPerSeal in its own scan before any decode. It goes with protocol 3.
const protocol3SigsPerSeal = 64

// UCShape is what the strict structural scan of one standalone certificate found.
type UCShape struct {
	// PathSteps is the unicity tree path length plus the shard tree sibling count the native gas schedule charges.
	PathSteps uint64
	// SigLens are the byte lengths of the seal signatures, in canonical map order.
	SigLens []int
}

// ScanUC applies the protocol-3 native bounded certificate scan to raw (64 signatures per seal, see protocol3SigsPerSeal): the byte cap, the strict CBOR token and depth bounds, every
// field's shape and sublimit (summary, shard depth, siblings, steps, signatures, node ids), the native decoder and the byte-exact
// re-encoding. It performs no cryptography and allocates only within those bounds. Callers that accept a narrower codec (the SDK's)
// intersect it with this result.
func ScanUC(raw []byte) (UCShape, error) {
	var c claim
	if len(raw) > MaxUCBytes {
		return UCShape{}, ErrUCTooLarge
	}
	tokens := 0
	if err := decodeUC(&c, raw, &tokens, protocol3SigsPerSeal); err != nil {
		return UCShape{}, err
	}
	shape := UCShape{PathSteps: c.pathSteps}
	for i := 1; c.sigs != nil && i < len(c.sigs.kids); i += 2 {
		shape.SigLens = append(shape.SigLens, len(c.sigs.kids[i].data))
	}
	return shape, nil
}
