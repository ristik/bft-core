package b1ref_test

import (
	"encoding/hex"
	"errors"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref"
)

// TestReuseIsPerCall: a second call repeats every read and check; nothing is remembered across calls.
func TestReuseIsPerCall(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		if v.ID != "reuse.one-seal.three-claims" {
			continue
		}
		counts := countWork(t)
		for i := 0; i < 2; i++ {
			if got, err := evaluate(t, v); err != nil || !got.Valid {
				t.Fatal(got, err)
			}
		}
		for kind, n := range v.Expected.Counters {
			if counts[kind] != 2*n {
				t.Fatalf("%s: %d over two calls, want %d", kind, counts[kind], 2*n)
			}
		}
		return
	}
	t.Fatal("vector missing")
}

// failingState fails every read: a Host failure, never a verdict.
type failingState struct{}

func (failingState) Word([32]byte) ([32]byte, error) {
	return [32]byte{}, errors.New("database closed")
}

func TestHostFailure(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		if v.ID != "cert.single.ok" {
			continue
		}
		req, _ := hex.DecodeString(v.Request)
		_, pins := state(t, v.PreState)
		out, used, err := b1ref.Run(b1ref.OpCertBatch, req, failingState{}, pins, v.Expected.Gas)
		if !errors.Is(err, b1ref.ErrHost) || !errors.Is(err, b1ref.ErrInfrastructure) || used != 0 || out != nil {
			t.Fatalf("out=%x used=%d err=%v", out, used, err)
		}
		return
	}
	t.Fatal("vector missing")
}
