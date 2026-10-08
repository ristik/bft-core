//go:build q4shim

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/crypto"

	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4shim"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// q4ShimDirEnv names the directory of a Q4 fault lane's shim: control.json is read from it, status.json and trace.jsonl are written to
// it. A binary built with -tags q4shim and started without it runs the shim with no rules, which only records the trace.
const q4ShimDirEnv = "UBFT_Q4_SHIM_DIR"

// wrapRootNet puts the Q4 fault shim between the consensus manager and the libp2p network. Test and lane binaries only (-tags
// q4shim): the shim holds the node's signing key for its Byzantine adapter, which a production binary must never carry.
func wrapRootNet(ctx context.Context, net consensus.RootNet, self peer.ID, signer crypto.Signer, signing func(uint64) (votesig.Config, error), log *slog.Logger) (consensus.RootNet, func(), error) {
	dir := os.Getenv(q4ShimDirEnv)
	if dir == "" {
		return nil, nil, fmt.Errorf("q4shim build: %s is not set", q4ShimDirEnv)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	traceFile, err := os.OpenFile(filepath.Join(dir, "trace.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, nil, err
	}
	var mu sync.Mutex
	enc := json.NewEncoder(traceFile)
	sink := func(ev q4shim.Event) {
		mu.Lock()
		defer mu.Unlock()
		if err := enc.Encode(ev); err != nil {
			log.Error("q4shim trace write failed", "error", err)
		}
	}
	shim := q4shim.New(net, q4shim.Config{Self: self, Signing: signing, Signer: signer, Trace: sink, KeepRaw: true})
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		shim.Watch(watchCtx, filepath.Join(dir, "control.json"), filepath.Join(dir, "status.json"), 100*time.Millisecond)
		close(done)
	}()
	log.Warn("Q4 FAULT SHIM ACTIVE: this root node can drop, hold, duplicate and (when told) equivocate; never a production binary", "dir", dir)
	stop := func() {
		cancel()
		<-done
		shim.Close()
		if err := shim.Finish(); err != nil && !errors.Is(err, q4shim.ErrRuleNotHit) {
			log.Error("q4shim finished with a fault", "error", err)
		}
		_ = traceFile.Close()
	}
	return shim, stop, nil
}
