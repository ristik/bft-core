// Package archive provides a bounded certified-record archive.
// Its bytes are availability data; callers must authenticate them independently.
package archive

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"

	"github.com/unicitynetwork/bft-go-base/types"
)

const Version byte = 1
const requestDomain = "archive/request"
const responseDomain = "archive/response"
const roundRequestDomain = "archive/round-request"

const (
	MaxContextBytes = 4096
	MaxShardBytes   = 513 // 4096 bits plus the bitstring end marker
	MaxRequestBytes = MaxContextBytes + MaxShardBytes + 256
	MaxChunkBytes   = 8 << 20
	MaxRecordBytes  = 32 << 20
	MaxWireBytes    = MaxRecordBytes + MaxContextBytes + 4096
)

var ErrInvalid = errors.New("invalid archive message")

// Identity is the small boundary to WP1's versioned execution identity.
// The caller must supply the canonical, complete identity bytes. RawIdentity is
// an adapter for a checked execution configuration encoder.
type Identity interface{ ArchiveIdentity() ([]byte, error) }
type RawIdentity []byte

func (i RawIdentity) ArchiveIdentity() ([]byte, error) { return bytes.Clone(i), nil }

// Context includes the entire deployment subject; identity binds execution
// configuration, including the fee profile and collector once WP1 lands.
type Context struct {
	NetworkID                           types.NetworkID
	PartitionID                         types.PartitionID
	ShardID                             types.ShardID
	ShardEpoch, RootEpoch               uint64
	FullShardConfHash, RegistryCodeHash [32]byte
	RegistryAddress                     [20]byte
	GenesisCommitment, EVMGenesisHash   [32]byte
	ExecutionIdentity                   []byte
}

type Request struct {
	Context   Context
	BlockHash [32]byte
}

// RoundRequest locates the newest stored certified block at or below a shard
// round. The returned record is availability data; callers authenticate its
// certificate and state against their independently pinned tip.
type RoundRequest struct {
	Context Context
	Round   uint64
}

func EncodeRoundRequest(q RoundRequest) ([]byte, error) {
	if q.Round == 0 {
		return nil, ErrInvalid
	}
	probe := Request{Context: q.Context}
	probe.BlockHash[0] = 1
	raw, err := EncodeRequest(probe)
	if err != nil {
		return nil, err
	}
	var out []byte
	out = append(out, roundRequestDomain...)
	out = append(out, raw[len(requestDomain):len(raw)-32]...)
	var round [8]byte
	binary.BigEndian.PutUint64(round[:], q.Round)
	out = append(out, round[:]...)
	return out, nil
}

func DecodeRoundRequest(raw []byte) (RoundRequest, error) {
	if len(raw) < len(roundRequestDomain)+8 || len(raw) > MaxRequestBytes || !bytes.HasPrefix(raw, []byte(roundRequestDomain)) {
		return RoundRequest{}, ErrInvalid
	}
	round := binary.BigEndian.Uint64(raw[len(raw)-8:])
	var probe []byte
	probe = append(probe, requestDomain...)
	probe = append(probe, raw[len(roundRequestDomain):len(raw)-8]...)
	probe = append(probe, make([]byte, 32)...)
	probe[len(probe)-32] = 1
	q, err := DecodeRequest(probe)
	if err != nil || round == 0 {
		return RoundRequest{}, ErrInvalid
	}
	out := RoundRequest{Context: q.Context, Round: round}
	canonical, err := EncodeRoundRequest(out)
	if err != nil || !bytes.Equal(raw, canonical) {
		return RoundRequest{}, ErrInvalid
	}
	return out, nil
}

// WithIdentity fills the identity slot without coupling this package to WP1's
// concrete type. The returned context owns its bytes.
func WithIdentity(c Context, id Identity) (Context, error) {
	if id == nil {
		return Context{}, ErrInvalid
	}
	b, err := id.ArchiveIdentity()
	if err != nil || len(b) == 0 || len(b) > MaxContextBytes {
		return Context{}, ErrInvalid
	}
	c.ExecutionIdentity = bytes.Clone(b)
	return c, nil
}

type Outcome byte

const (
	OK          Outcome = 1
	Unavailable Outcome = 2
	Busy        Outcome = 3
	Invalid     Outcome = 4
)

// A successful response carries one complete record. No refusal carries data.
type Response struct {
	Request Request
	Outcome Outcome
	Record  *Record
}

type Record struct {
	Header, Body, CanonicalRootInput                 []byte
	OriginalUC, OriginalTR, ResultingUC, ResultingTR []byte
	Companion, ParentAccounting                      []byte // ParentAccounting is empty in version 1.
	// Reserved for future versioned proof/export material. Not interpreted here.
	Extensions map[string][]byte
}

var required = []string{"header", "body", "root-input", "original-uc", "original-tr", "resulting-uc", "resulting-tr", "companion", "parent-accounting"}

// ReceiptListKey is the immutable v2 archive field containing the ordered
// consensus receipt envelopes, encoded as an RLP list of byte strings.
const ReceiptListKey = "consensus-receipts-v2"

func HasReceiptList(r *Record) bool {
	v, ok := r.Extensions[ReceiptListKey]
	return ok && len(v) != 0
}

func validReceiptList(r *Record) bool {
	if r == nil {
		return false
	}
	v, ok := r.Extensions[ReceiptListKey]
	return ok && len(v) != 0
}

func fields(r *Record) map[string][]byte {
	return map[string][]byte{"header": r.Header, "body": r.Body, "root-input": r.CanonicalRootInput,
		"original-uc": r.OriginalUC, "original-tr": r.OriginalTR, "resulting-uc": r.ResultingUC,
		"resulting-tr": r.ResultingTR, "companion": r.Companion, "parent-accounting": r.ParentAccounting}
}

func validRequest(q Request) bool {
	if q.Context.ShardID.Length() > 4096 || len(q.Context.ExecutionIdentity) == 0 || len(q.Context.ExecutionIdentity) > MaxContextBytes || q.BlockHash == ([32]byte{}) {
		return false
	}
	return q.Context.FullShardConfHash != ([32]byte{}) && q.Context.RegistryAddress != ([20]byte{}) && q.Context.RegistryCodeHash != ([32]byte{}) && q.Context.GenesisCommitment != ([32]byte{}) && q.Context.EVMGenesisHash != ([32]byte{})
}

func putBytes(b *bytes.Buffer, v []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(v)))
	b.Write(n[:])
	b.Write(v)
}
func put32(b *bytes.Buffer, v uint32) {
	var x [4]byte
	binary.BigEndian.PutUint32(x[:], v)
	b.Write(x[:])
}
func put16(b *bytes.Buffer, v uint16) {
	var x [2]byte
	binary.BigEndian.PutUint16(x[:], v)
	b.Write(x[:])
}
func put64(b *bytes.Buffer, v uint64) {
	var x [8]byte
	binary.BigEndian.PutUint64(x[:], v)
	b.Write(x[:])
}

// EncodeRequest is a fixed-order binary format. All integers are big endian.
func EncodeRequest(q Request) ([]byte, error) {
	if !validRequest(q) {
		return nil, ErrInvalid
	}
	var b bytes.Buffer
	b.WriteString(requestDomain)
	b.WriteByte(Version)
	put16(&b, uint16(q.Context.NetworkID))
	put32(&b, uint32(q.Context.PartitionID))
	putBytes(&b, q.Context.ShardID.Bytes())
	put64(&b, q.Context.ShardEpoch)
	put64(&b, q.Context.RootEpoch)
	b.Write(q.Context.FullShardConfHash[:])
	b.Write(q.Context.RegistryAddress[:])
	b.Write(q.Context.RegistryCodeHash[:])
	b.Write(q.Context.GenesisCommitment[:])
	b.Write(q.Context.EVMGenesisHash[:])
	putBytes(&b, q.Context.ExecutionIdentity)
	b.Write(q.BlockHash[:])
	if b.Len() > MaxRequestBytes {
		return nil, ErrInvalid
	}
	return b.Bytes(), nil
}

func readBytes(r *bytes.Reader, cap int) ([]byte, error) {
	var n uint32
	if binary.Read(r, binary.BigEndian, &n) != nil || uint64(n) > uint64(cap) || uint64(n) > uint64(r.Len()) {
		return nil, ErrInvalid
	}
	v := make([]byte, n)
	_, err := io.ReadFull(r, v)
	return v, err
}

func DecodeRequest(b []byte) (Request, error) {
	var q Request
	if len(b) > MaxRequestBytes || len(b) < len(requestDomain)+1 || !bytes.Equal(b[:len(requestDomain)], []byte(requestDomain)) || b[len(requestDomain)] != Version {
		return q, ErrInvalid
	}
	r := bytes.NewReader(b[len(requestDomain)+1:])
	c := &q.Context
	if binary.Read(r, binary.BigEndian, &c.NetworkID) != nil || binary.Read(r, binary.BigEndian, &c.PartitionID) != nil {
		return Request{}, ErrInvalid
	}
	shard, err := readBytes(r, MaxShardBytes)
	if err != nil || len(shard) == 0 {
		return Request{}, ErrInvalid
	}
	if err := c.ShardID.UnmarshalText([]byte("0x" + hex.EncodeToString(shard))); err != nil || c.ShardID.Length() > 4096 || !bytes.Equal(c.ShardID.Bytes(), shard) {
		return Request{}, ErrInvalid
	}
	for _, p := range []*uint64{&c.ShardEpoch, &c.RootEpoch} {
		if binary.Read(r, binary.BigEndian, p) != nil {
			return Request{}, ErrInvalid
		}
	}
	if _, err := io.ReadFull(r, c.FullShardConfHash[:]); err != nil {
		return Request{}, ErrInvalid
	}
	if _, err := io.ReadFull(r, c.RegistryAddress[:]); err != nil {
		return Request{}, ErrInvalid
	}
	for _, p := range []*[32]byte{&c.RegistryCodeHash, &c.GenesisCommitment, &c.EVMGenesisHash} {
		if _, err := io.ReadFull(r, p[:]); err != nil {
			return Request{}, ErrInvalid
		}
	}
	c.ExecutionIdentity, err = readBytes(r, MaxContextBytes)
	if err != nil {
		return Request{}, ErrInvalid
	}
	if _, err = io.ReadFull(r, q.BlockHash[:]); err != nil || r.Len() != 0 || !validRequest(q) {
		return Request{}, ErrInvalid
	}
	return q, nil
}

func validRecord(rec *Record) bool {
	if rec == nil {
		return false
	}
	total := 0
	for name, v := range fields(rec) {
		if name == "parent-accounting" {
			if len(v) != 0 {
				return false
			}
			continue
		}
		if len(v) == 0 || len(v) > MaxChunkBytes {
			return false
		}
		total += len(v)
	}
	for k, v := range rec.Extensions {
		if len(k) == 0 || len(k) > 64 || reserved(k) || len(v) == 0 || len(v) > MaxChunkBytes {
			return false
		}
		total += len(v)
	}
	return total <= MaxRecordBytes && len(rec.Extensions) <= 16
}

func EncodeResponse(s Response) ([]byte, error) {
	q, err := EncodeRequest(s.Request)
	if err != nil {
		return nil, err
	}
	if (s.Outcome == OK) != (s.Record != nil) || s.Outcome < OK || s.Outcome > Invalid {
		return nil, ErrInvalid
	}
	var b bytes.Buffer
	b.WriteString(responseDomain)
	b.WriteByte(Version)
	putBytes(&b, q)
	b.WriteByte(byte(s.Outcome))
	if s.Outcome == OK {
		if !validRecord(s.Record) {
			return nil, ErrInvalid
		}
		for _, name := range required {
			putBytes(&b, fields(s.Record)[name])
		}
		// Extensions have a deterministic order and cannot masquerade as required chunks.
		keys := sortedExtensions(s.Record.Extensions)
		b.WriteByte(byte(len(keys)))
		for _, k := range keys {
			putBytes(&b, []byte(k))
			putBytes(&b, s.Record.Extensions[k])
		}
	}
	return b.Bytes(), nil
}

func DecodeResponse(b []byte) (Response, error) {
	var s Response
	if len(b) > MaxWireBytes || len(b) < len(responseDomain)+1+5 || !bytes.Equal(b[:len(responseDomain)], []byte(responseDomain)) || b[len(responseDomain)] != Version {
		return s, ErrInvalid
	}
	r := bytes.NewReader(b[len(responseDomain)+1:])
	q, err := readBytes(r, MaxRequestBytes)
	if err != nil {
		return s, ErrInvalid
	}
	s.Request, err = DecodeRequest(q)
	if err != nil {
		return Response{}, err
	}
	o, err := r.ReadByte()
	if err != nil || o < byte(OK) || o > byte(Invalid) {
		return Response{}, ErrInvalid
	}
	s.Outcome = Outcome(o)
	if s.Outcome != OK {
		if r.Len() != 0 {
			return Response{}, ErrInvalid
		}
		return s, nil
	}
	rec := &Record{}
	f := make(map[string][]byte, len(required))
	for _, name := range required {
		f[name], err = readBytes(r, MaxChunkBytes)
		if err != nil {
			return Response{}, ErrInvalid
		}
	}
	rec.Header = f["header"]
	rec.Body = f["body"]
	rec.CanonicalRootInput = f["root-input"]
	rec.OriginalUC = f["original-uc"]
	rec.OriginalTR = f["original-tr"]
	rec.ResultingUC = f["resulting-uc"]
	rec.ResultingTR = f["resulting-tr"]
	rec.Companion = f["companion"]
	rec.ParentAccounting = f["parent-accounting"]
	n, err := r.ReadByte()
	if err != nil || n > 16 {
		return Response{}, ErrInvalid
	}
	rec.Extensions = make(map[string][]byte, n)
	last := ""
	for i := 0; i < int(n); i++ {
		k, e := readBytes(r, 64)
		if e != nil || string(k) <= last || reserved(string(k)) {
			return Response{}, ErrInvalid
		}
		last = string(k)
		v, e := readBytes(r, MaxChunkBytes)
		if e != nil {
			return Response{}, ErrInvalid
		}
		rec.Extensions[last] = v
	}
	if r.Len() != 0 || !validRecord(rec) {
		return Response{}, ErrInvalid
	}
	s.Record = rec
	return s, nil
}

// DecodeFor enforces the consumer's immutable local target before exposing a
// provider's record. It does not authenticate the record contents.
func DecodeFor(want Request, wire []byte) (Response, error) {
	s, err := DecodeResponse(wire)
	if err != nil {
		return Response{}, err
	}
	a, err := EncodeRequest(want)
	if err != nil {
		return Response{}, err
	}
	b, _ := EncodeRequest(s.Request)
	if !bytes.Equal(a, b) {
		return Response{}, ErrInvalid
	}
	return s, nil
}
