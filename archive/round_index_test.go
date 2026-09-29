package archive

import (
	"bytes"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRoundLookupContextAndRestart(t *testing.T) {
	q, rec := fixture()
	var uc types.UnicityCertificate
	uc.InputRecord = &types.InputRecord{RoundNumber: 7, BlockHash: q.BlockHash[:]}
	var err error
	rec.ResultingUC, err = types.Cbor.Marshal(&uc)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	query := RoundRequest{Context: q.Context, Round: 7}
	encoded, err := EncodeRoundRequest(query)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRoundRequest(encoded)
	if err != nil || decoded.Round != query.Round || !bytes.Equal(decoded.Context.ExecutionIdentity, query.Context.ExecutionIdentity) {
		t.Fatalf("round request round trip: %+v %v", decoded, err)
	}
	if _, _, err := s.GetLatest(query); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("empty index: %v", err)
	}
	if err := s.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	q2, rec2 := q, *rec
	rec2.Header = append(bytes.Clone(rec.Header), 0x08)
	copy(q2.BlockHash[:], crypto.Keccak256(rec2.Header))
	uc.InputRecord.RoundNumber = 8
	uc.InputRecord.BlockHash = q2.BlockHash[:]
	rec2.ResultingUC, err = types.Cbor.Marshal(&uc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(q2, &rec2); err != nil {
		t.Fatal(err)
	}
	for _, store := range []*Store{s} {
		found, _, err := store.GetLatest(query)
		if err != nil || found.BlockHash != q.BlockHash {
			t.Fatalf("live index: %x %v", found.BlockHash, err)
		}
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if found, _, err := reopened.GetLatest(query); err != nil || found.BlockHash != q.BlockHash {
		t.Fatalf("rebuilt index: %x %v", found.BlockHash, err)
	}
	query.Round = 8
	if found, _, err := reopened.GetLatest(query); err != nil || found.BlockHash != q2.BlockHash {
		t.Fatalf("newest certified round: %x %v", found.BlockHash, err)
	}
	query.Round = 6
	if _, _, err := reopened.GetLatest(query); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("future record selected: %v", err)
	}
	query.Round = 7
	query.Context.RootEpoch++
	if _, _, err := reopened.GetLatest(query); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("wrong epoch selected: %v", err)
	}
	for _, raw := range [][]byte{nil, encoded[:len(encoded)-1], append([]byte(nil), encoded...)} {
		if len(raw) == len(encoded) {
			raw[0] ^= 1
		}
		if _, err := DecodeRoundRequest(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("malformed query accepted: %v", err)
		}
	}
}

func TestLatestReceiptCompleteSkipsNewerV1AndSurvivesRestart(t *testing.T) {
	q, rec := fixture()
	var uc types.UnicityCertificate
	uc.InputRecord = &types.InputRecord{RoundNumber: 7, BlockHash: q.BlockHash[:]}
	var err error
	rec.ResultingUC, err = types.Cbor.Marshal(&uc)
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	v1 := *rec
	if err := s.Put(q, &v1); err != nil {
		t.Fatal(err)
	}
	rec.Extensions = map[string][]byte{ReceiptListKey: {0xc0}}
	if err := s.Put(q, rec); err != nil {
		t.Fatal(err)
	}
	q2, rec2 := q, *rec
	rec2.Extensions = nil
	rec2.Header = append(bytes.Clone(rec.Header), 0x08)
	copy(q2.BlockHash[:], crypto.Keccak256(rec2.Header))
	uc.InputRecord = &types.InputRecord{RoundNumber: 8, BlockHash: q2.BlockHash[:]}
	rec2.ResultingUC, err = types.Cbor.Marshal(&uc)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(q2, &rec2); err != nil {
		t.Fatal(err)
	}
	query := RoundRequest{Context: q.Context, Round: 8}
	if got, _, err := s.GetLatestReceiptComplete(query); err != nil || got.BlockHash != q.BlockHash {
		t.Fatalf("latest receipt-complete record: %x %v", got.BlockHash, err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, rec, err := reopened.GetLatestReceiptComplete(query); err != nil || got.BlockHash != q.BlockHash || !HasReceiptList(rec) {
		t.Fatalf("rebuilt receipt-complete index: %x %v", got.BlockHash, err)
	}
}
