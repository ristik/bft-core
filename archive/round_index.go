package archive

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"

	"github.com/unicitynetwork/bft-go-base/types"
)

// GetLatest uses an in-memory round index rebuilt from the immutable, synced
// archive manifests after restart. The index is a locator, never evidence of
// certification or freshness. The selected record is fully reread on use.
func (s *Store) GetLatest(q RoundRequest) (Request, *Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := roundKey(q)
	if err != nil {
		return Request{}, nil, err
	}
	if s.rounds == nil {
		if err := s.buildRoundIndex(); err != nil {
			return Request{}, nil, err
		}
	}
	var chosen []Request
	var highest uint64
	for round, requests := range s.rounds[key] {
		if round <= q.Round && round >= highest {
			highest, chosen = round, requests
		}
	}
	if len(chosen) == 0 {
		return Request{}, nil, ErrUnavailable
	}
	if len(chosen) != 1 {
		return Request{}, nil, ErrCorrupt
	}
	rec, err := s.get(chosen[0])
	return chosen[0], rec, err
}

func roundKey(q RoundRequest) (string, error) {
	raw, err := EncodeRoundRequest(q)
	if err != nil {
		return "", err
	}
	return string(raw[:len(raw)-8]), nil
}

func (s *Store) indexRecord(q Request, rec *Record) {
	if rec == nil {
		return
	}
	var uc types.UnicityCertificate
	if types.Cbor.Unmarshal(rec.ResultingUC, &uc) != nil || uc.InputRecord == nil ||
		!bytes.Equal(uc.InputRecord.BlockHash, q.BlockHash[:]) || uc.InputRecord.RoundNumber == 0 {
		return
	}
	key, err := roundKey(RoundRequest{Context: q.Context, Round: 1})
	if err != nil {
		return
	}
	if s.rounds[key] == nil {
		s.rounds[key] = make(map[uint64][]Request)
	}
	for _, old := range s.rounds[key][uc.InputRecord.RoundNumber] {
		if old.BlockHash == q.BlockHash {
			return
		}
	}
	s.rounds[key][uc.InputRecord.RoundNumber] = append(s.rounds[key][uc.InputRecord.RoundNumber], q)
}

func (s *Store) buildRoundIndex() error {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	s.rounds = make(map[string]map[uint64][]Request)
	for _, entry := range entries {
		if !entry.IsDir() || len(entry.Name()) != 64 {
			continue
		}
		manifest, err := readBounded(filepath.Join(s.dir, entry.Name(), "manifest"), 16<<10)
		if err != nil || len(manifest) < 8+4+1+32 || !bytes.Equal(manifest[:8], []byte("ARCHIVE1")) {
			continue
		}
		digest := sha256.Sum256(manifest[:len(manifest)-32])
		if !bytes.Equal(digest[:], manifest[len(manifest)-32:]) {
			continue
		}
		reader := bytes.NewReader(manifest[8 : len(manifest)-32])
		raw, err := readBytes(reader, MaxRequestBytes)
		if err != nil {
			continue
		}
		q, err := DecodeRequest(raw)
		if err != nil {
			continue
		}
		location, err := location(q)
		if err != nil || location != entry.Name() {
			continue
		}
		rec, err := s.get(q)
		if err == nil {
			s.indexRecord(q, rec)
		}
	}
	return nil
}
