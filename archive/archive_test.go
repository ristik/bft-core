package archive

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

func fixture() (Request, *Record) {
	r := &Record{Header: []byte{0xc1, 0x80}, Body: []byte("body"), CanonicalRootInput: []byte("input"), OriginalUC: []byte("ouc"), OriginalTR: []byte("otr"), ResultingUC: []byte("ruc"), ResultingTR: []byte("rtr"), Companion: []byte("companion"), ParentAccounting: []byte("accounting"), Extensions: map[string][]byte{"future-proof": []byte("proof")}}
	q := Request{Context: Context{NetworkID: 1, PartitionID: 2, ShardID: 3, ShardEpoch: 4, RootEpoch: 5, ExecutionIdentity: []byte("identity-v1")}}
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
	s.Fault = func(point string) error {
		if point == "after-chunk" {
			return errors.New("crash")
		}
		return nil
	}
	if err = s.Put(q, r); err == nil {
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
	s, _ := Open(t.TempDir())
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
	const requestSHA = "53853248a64fbef792e6c66c9648c9c9879e932cc72f5e28c4e82b926c01d1a8"
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
	const responseSHA = "a854a78c3b817bba7f76d32c7da8e6d209b697dc44c43c6098f37d495cab6c79"
	if hex.EncodeToString(digest[:]) != responseSHA {
		t.Fatalf("response vector: %x", digest)
	}
	s, err := DecodeResponse(w)
	if err != nil || s.Outcome != OK || !bytes.Equal(s.Record.ParentAccounting, r.ParentAccounting) {
		t.Fatalf("response decode: %v", err)
	}
	if _, err = DecodeResponse(w[:len(w)-1]); err == nil {
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
	if _, err = DecodeRequest(append(wire, 0)); err == nil {
		t.Fatal("trailing request")
	}
	q.Context.ExecutionIdentity = bytes.Repeat([]byte{1}, MaxContextBytes+1)
	if _, err = EncodeRequest(q); err == nil {
		t.Fatal("oversize context")
	}
	q, _ = fixture()
	r.Body = bytes.Repeat([]byte{1}, MaxChunkBytes+1)
	if _, err = EncodeResponse(Response{q, OK, r}); err == nil {
		t.Fatal("oversize chunk")
	}
	if _, err = DecodeResponse(make([]byte, MaxWireBytes+1)); err == nil {
		t.Fatal("oversize response")
	}
}

func TestBeforePublishFaultAndCorruptChunk(t *testing.T) {
	q, r := fixture()
	s, _ := Open(t.TempDir())
	s.Fault = func(point string) error {
		if point == "before-publish" {
			return errors.New("crash")
		}
		return nil
	}
	if err := s.Put(q, r); err == nil {
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
	if got := s.Serve(q); got.Outcome != Invalid || got.Record != nil {
		t.Fatalf("corrupt success: %+v", got)
	}
}
