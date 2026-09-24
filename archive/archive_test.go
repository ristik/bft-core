package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func fixture() (Request, *Record) {
	r := &Record{Header: []byte{0xc1, 0x80}, Body: []byte("body"), CanonicalRootInput: []byte("input"), OriginalUC: []byte("ouc"), OriginalTR: []byte("otr"), ResultingUC: []byte("ruc"), ResultingTR: []byte("rtr"), Companion: []byte("companion"), ParentAccounting: []byte("accounting"), Extensions: map[string][]byte{"future-proof": []byte("proof")}}
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte("0x010203040580")); err != nil {
		panic(err)
	}
	q := Request{Context: Context{NetworkID: 1, PartitionID: 2, ShardID: shard, ShardEpoch: 4, RootEpoch: 5, ExecutionIdentity: []byte("identity-v1")}}
	q.Context.FullShardConfHash[0] = 6
	q.Context.RegistryAddress[0] = 7
	q.Context.RegistryCodeHash[0] = 8
	q.Context.GenesisCommitment[0] = 9
	q.Context.EVMGenesisHash[0] = 10
	copy(q.BlockHash[:], crypto.Keccak256(r.Header))
	return q, r
}

func TestAtomicPublicationAndFault(t *testing.T) {
	q, r := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected after chunk")
	s.Fault = func(point string) error {
		if point == "after-chunk" {
			return fault
		}
		return nil
	}
	if err = s.Put(q, r); !errors.Is(err, fault) {
		t.Fatal("fault ignored")
	}
	s.Fault = nil
	if _, err = s.Get(q); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("partial publication: %v", err)
	}
	if err = s.Put(q, r); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(s.dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(q)
	if err != nil || !bytes.Equal(got.CanonicalRootInput, r.CanonicalRootInput) {
		t.Fatalf("reopen: %v", err)
	}
	if err = reopened.Put(q, r); err != nil {
		t.Fatal(err)
	}
	r.Body = []byte("changed")
	if err = reopened.Put(q, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("mutable publication: %v", err)
	}
}

func TestMissingChunkAndWrongSubject(t *testing.T) {
	q, r := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(q, r); err != nil {
		t.Fatal(err)
	}
	wrong := q
	wrong.Context.RootEpoch++
	if _, err := s.Get(wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong context: %v", err)
	}
	wrong = q
	wrong.BlockHash[0]++
	if _, err := s.Get(wrong); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong hash: %v", err)
	}
	if err := s.Put(wrong, r); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hash accepted: %v", err)
	}
	loc, _ := location(q)
	if err := os.Remove(filepath.Join(s.dir, loc, fileName("body"))); err != nil {
		t.Fatal(err)
	}
	if got := s.Serve(q); got.Outcome != Unavailable || got.Record != nil {
		t.Fatalf("partial success: %+v", got)
	}
}

func TestCodecVectorAndBounds(t *testing.T) {
	q, r := fixture()
	wire, err := EncodeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(wire)
	const requestSHA = "513185311c1a0f09ed673141bde270acf7ca6786ff71ced28aab8b841cbf7523"
	if hex.EncodeToString(digest[:]) != requestSHA {
		t.Fatalf("request vector: %x", digest)
	}
	decoded, err := DecodeRequest(wire)
	if err != nil || !bytes.Equal(decoded.Context.ExecutionIdentity, q.Context.ExecutionIdentity) {
		t.Fatalf("request decode: %v", err)
	}
	w, err := EncodeResponse(Response{q, OK, r})
	if err != nil {
		t.Fatal(err)
	}
	digest = sha256.Sum256(w)
	const responseSHA = "1ff29ae4ed96986375fd84e2ec7ad82acd107ec193a0d6746e41b07e2e6628a3"
	if hex.EncodeToString(digest[:]) != responseSHA {
		t.Fatalf("response vector: %x", digest)
	}
	s, err := DecodeResponse(w)
	if err != nil || s.Outcome != OK || !bytes.Equal(s.Record.ParentAccounting, r.ParentAccounting) {
		t.Fatalf("response decode: %v", err)
	}
	if _, err = DecodeResponse(w[:len(w)-1]); !errors.Is(err, ErrInvalid) {
		t.Fatal("truncated success")
	}
	wrong := q
	wrong.Context.RootEpoch++
	if _, err = DecodeFor(wrong, w); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong response context: %v", err)
	}
	wrong = q
	wrong.BlockHash[0]++
	if _, err = DecodeFor(wrong, w); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong response hash: %v", err)
	}
	if _, err = DecodeFor(q, w); err != nil {
		t.Fatalf("correct response: %v", err)
	}
	if _, err = DecodeRequest(append(wire, 0)); !errors.Is(err, ErrInvalid) {
		t.Fatal("trailing request")
	}
	q.Context.ExecutionIdentity = bytes.Repeat([]byte{1}, MaxContextBytes+1)
	if _, err = EncodeRequest(q); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize context")
	}
	q, _ = fixture()
	r.Body = bytes.Repeat([]byte{1}, MaxChunkBytes+1)
	if _, err = EncodeResponse(Response{q, OK, r}); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize chunk")
	}
	if _, err = DecodeResponse(make([]byte, MaxWireBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatal("oversize response")
	}
}

func TestBeforePublishFaultAndCorruptChunk(t *testing.T) {
	q, r := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected before publish")
	s.Fault = func(point string) error {
		if point == "before-publish" {
			return fault
		}
		return nil
	}
	if err := s.Put(q, r); !errors.Is(err, fault) {
		t.Fatal("fault ignored")
	}
	if _, err := s.Get(q); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("prepublication visibility: %v", err)
	}
	s.Fault = nil
	if err := s.Put(q, r); err != nil {
		t.Fatal(err)
	}
	loc, _ := location(q)
	if err := os.WriteFile(filepath.Join(s.dir, loc, fileName("body")), []byte("bad!"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := s.Serve(q); got.Outcome != Unavailable || got.Record != nil {
		t.Fatalf("corrupt success: %+v", got)
	}
}

func TestCanonicalDecoding(t *testing.T) {
	q, rec := fixture()
	request, err := EncodeRequest(q)
	if err != nil {
		t.Fatal(err)
	}
	response, err := EncodeResponse(Response{q, OK, rec})
	if err != nil {
		t.Fatal(err)
	}
	clone := func(b []byte) []byte { return bytes.Clone(b) }
	badRequestDomain := clone(request)
	badRequestDomain[0] ^= 1
	badRequestVersion := clone(request)
	badRequestVersion[len(requestDomain)]++
	// The shard byte string follows domain, version, network and partition.
	shardLen := len(requestDomain) + 1 + 2 + 4
	badShard := clone(request)
	badShard[shardLen+4+len(q.Context.ShardID.Bytes())-1] = 0
	badShardLength := clone(request)
	binary.BigEndian.PutUint32(badShardLength[shardLen:], MaxShardBytes+1)
	for name, wire := range map[string][]byte{"request domain": badRequestDomain, "request version": badRequestVersion, "noncanonical shard": badShard, "shard cap": badShardLength} {
		if _, err := DecodeRequest(wire); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	badResponseDomain := clone(response)
	badResponseDomain[0] ^= 1
	badResponseVersion := clone(response)
	badResponseVersion[len(responseDomain)]++
	badResponseLength := clone(response)
	binary.BigEndian.PutUint32(badResponseLength[len(responseDomain)+1:], MaxRequestBytes+1)
	for name, wire := range map[string][]byte{"response domain": badResponseDomain, "response version": badResponseVersion, "request cap": badResponseLength} {
		if _, err := DecodeResponse(wire); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	makeRaw := func(outcome Outcome, count byte, keys []string, trailing []byte) []byte {
		var b bytes.Buffer
		b.WriteString(responseDomain)
		b.WriteByte(Version)
		putBytes(&b, request)
		b.WriteByte(byte(outcome))
		if outcome == OK {
			f := fields(rec)
			for _, name := range required {
				putBytes(&b, f[name])
			}
			b.WriteByte(count)
			for _, key := range keys {
				putBytes(&b, []byte(key))
				putBytes(&b, []byte("value"))
			}
		}
		b.Write(trailing)
		return b.Bytes()
	}
	for name, wire := range map[string][]byte{
		"unsorted extensions":  makeRaw(OK, 2, []string{"z", "a"}, nil),
		"duplicate extensions": makeRaw(OK, 2, []string{"a", "a"}, nil),
		"empty extension":      makeRaw(OK, 1, []string{""}, nil),
		"reserved extension":   makeRaw(OK, 1, []string{"body"}, nil),
		"extension count":      makeRaw(OK, 17, nil, nil),
		"refusal payload":      makeRaw(Unavailable, 0, nil, []byte{1}),
		"out of range outcome": makeRaw(Outcome(5), 0, nil, nil),
	} {
		if _, err := DecodeResponse(wire); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	rec.Extensions["body"] = []byte("shadow")
	if _, err := EncodeResponse(Response{q, OK, rec}); !errors.Is(err, ErrInvalid) {
		t.Errorf("reserved extension encoded: %v", err)
	}
}

func TestOrphanTemporaryDirectoryIsIgnored(t *testing.T) {
	q, rec := fixture()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	orphan := filepath.Join(s.dir, ".writing-orphan")
	if err := os.Mkdir(orphan, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "manifest"), []byte("incomplete"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(q); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("orphan was visible: %v", err)
	}
	if err := s.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(q); err != nil {
		t.Fatal(err)
	}
}
