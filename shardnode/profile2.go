package shardnode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrProfile2Unready        = errors.New("shardnode: handoff evidence required")
	ErrProfile2Epoch          = errors.New("shardnode: certificate outside installed epoch")
	ErrProfile2TerminalRepeat = errors.New("shardnode: historical terminal repeat")
)

// Profile2Consumer keeps the authenticated handoff and its epoch floor in one
// durable record. The caller supplies the old trust base from verified lineage.
type Profile2Consumer struct {
	mu           sync.Mutex
	path         string
	partition    types.PartitionID
	old          evmroot.D4TrustBase
	orderedRound uint64
	proof        *evmroot.HandoffProof
	verified     *evmroot.VerifiedHandoff
	ready        bool
}

type profile2Checkpoint struct {
	Version    uint32
	EpochFloor uint64
	Proof      evmroot.HandoffProof
}

func NewProfile2Consumer(path string, partition types.PartitionID, old evmroot.D4TrustBase, orderedRound uint64) (*Profile2Consumer, error) {
	c := &Profile2Consumer{path: path, partition: partition, old: old, orderedRound: orderedRound}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var cp profile2Checkpoint
	if err = json.Unmarshal(data, &cp); err != nil {
		return nil, err
	}
	if cp.Version != 1 {
		return nil, ErrProfile2Epoch
	}
	v, err := evmroot.VerifyHandoff(cp.Proof, old)
	if err != nil {
		return nil, err
	}
	if v.Epoch == ^uint64(0) || cp.EpochFloor != v.Epoch+1 || (orderedRound != 0 && orderedRound != v.OrderRound) || !hasProfile2Partition(v, partition) {
		return nil, ErrProfile2Epoch
	}
	c.proof, c.verified = &cp.Proof, &v
	c.orderedRound = v.OrderRound
	return c, nil
}

func hasProfile2Partition(v evmroot.VerifiedHandoff, partition types.PartitionID) bool {
	for _, s := range v.Snapshot.Shards {
		if s.Partition == partition {
			return true
		}
	}
	return false
}

// i-b/H4 proof-transport hook: the future fetcher passes its authenticated
// proof here; missing evidence leaves Classify in the unready state.
// Install verifies before replacing the single checkpoint. A crash exposes
// either the old file or the complete proof and epoch floor, never half of each.
func (c *Profile2Consumer) Install(proof evmroot.HandoffProof) error {
	v, err := evmroot.VerifyHandoff(proof, c.old)
	if err != nil {
		return err
	}
	if v.Epoch == ^uint64(0) || (c.orderedRound != 0 && c.orderedRound != v.OrderRound) || !hasProfile2Partition(v, c.partition) {
		return ErrProfile2Epoch
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verified != nil {
		if bytes.Equal(c.verified.RecordID, v.RecordID) {
			return nil
		}
		return ErrProfile2Epoch
	}
	data, err := json.Marshal(profile2Checkpoint{Version: 1, EpochFloor: v.Epoch + 1, Proof: proof})
	if err != nil {
		return err
	}
	dir := filepath.Dir(c.path)
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".profile2-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), c.path); err != nil {
		return err
	}
	if err = syncDirectory(dir); err != nil {
		return err
	}
	c.proof, c.verified = &proof, &v
	c.orderedRound = v.OrderRound
	return nil
}

// SetReady is called only after the authenticated shard checkpoint has been
// imported. Readiness is intentionally not restored from the proof file.
func (c *Profile2Consumer) SetReady() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verified == nil {
		return ErrProfile2Unready
	}
	c.ready = true
	return nil
}

func (c *Profile2Consumer) EpochFloor() (uint64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.verified == nil {
		return 0, false
	}
	return c.verified.Epoch + 1, true
}

func (c *Profile2Consumer) Classify(prev, next *types.UnicityCertificate) (UCClass, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if next == nil || next.InputRecord == nil || next.UnicitySeal == nil {
		return UCValid, ErrImpossibleUCOrder
	}
	if c.verified == nil {
		if prev == nil || next.GetRootEpoch() != c.old.Epoch {
			return UCValid, ErrProfile2Unready
		}
		if prev != nil && next.GetRootEpoch() != prev.GetRootEpoch() {
			return UCValid, ErrProfile2Unready
		}
		if prev != nil && (c.orderedRound == 0 || next.GetRootRoundNumber() >= c.orderedRound) && next.GetRootRoundNumber() > prev.GetRootRoundNumber() {
			same, err := sameInputRecord(prev, next)
			if err != nil {
				return UCValid, err
			}
			if same {
				return UCValid, ErrProfile2Unready
			}
		}
		return ClassifyUC(prev, next)
	}
	v := c.verified
	if next.GetRootEpoch() == v.Epoch {
		for _, s := range v.Snapshot.Shards {
			if s.Partition != c.partition {
				continue
			}
			ir, err := next.InputRecord.Bytes()
			if err != nil {
				return UCValid, err
			}
			if next.GetRootRoundNumber() >= v.OrderRound && bytes.Equal(next.UnicitySeal.Hash, v.Root) && bytes.Equal(ir, s.InputRecord) {
				return UCStale, ErrProfile2TerminalRepeat
			}
		}
		return UCStale, ErrProfile2Epoch
	}
	if next.GetRootEpoch() != v.Epoch+1 {
		return UCValid, ErrProfile2Epoch
	}
	if !c.ready {
		return UCValid, ErrProfile2Unready
	}
	if prev != nil && prev.GetRootEpoch() == v.Epoch+1 {
		return ClassifyUC(prev, next)
	}
	for _, s := range v.Snapshot.Shards {
		if s.Partition != c.partition {
			continue
		}
		var terminal types.InputRecord
		if err := types.Cbor.Unmarshal(s.InputRecord, &terminal); err != nil {
			return UCValid, fmt.Errorf("terminal input record: %w", err)
		}
		if next.GetRoundNumber() < terminal.RoundNumber {
			return UCValid, ErrImpossibleUCOrder
		}
		if next.GetRoundNumber() == terminal.RoundNumber {
			ir, err := next.InputRecord.Bytes()
			if err != nil {
				return UCValid, err
			}
			if !bytes.Equal(ir, s.InputRecord) {
				return UCValid, ErrEquivocatingUC
			}
			return UCRepeat, nil
		}
		// The base helper checks shard-state continuity. Its scalar root-round
		// precondition is made equal only in this local comparison; the signed
		// certificate and its authenticated (epoch, round) remain untouched.
		comparison := *next
		seal := *next.UnicitySeal
		seal.RootChainRoundNumber = 0
		comparison.UnicitySeal = &seal
		old := *next
		old.InputRecord = &terminal
		oldSeal := seal
		oldSeal.RootChainRoundNumber = 0
		old.UnicitySeal = &oldSeal
		if err := types.CheckNonEquivocatingCertificates(&old, &comparison); err != nil {
			return UCValid, fmt.Errorf("%w: %w", ErrEquivocatingUC, err)
		}
		return UCValid, nil
	}
	return UCValid, ErrProfile2Epoch
}
