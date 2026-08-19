package shardnode

import (
	"context"
	"fmt"
	"log/slog"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"golang.org/x/sync/errgroup"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// Node is a fully wired shard node: a BFTClient (root-chain protocol) and a
// Round (round logic) pointed at each other, driving one Executor. This is
// the type cli/ubft/cmd/shard_node_run.go constructs; everything it needs
// is already assembled by New — the CLI layer only supplies the pieces that
// come from flags and files (peer, network, signer, trust base, executor,
// store).
type Node struct {
	client       *BFTClient
	round        *Round
	store        *FileStore
	disseminator Disseminator
}

// runnable is implemented by Disseminators with their own background
// delivery loop — NetDisseminator, not LoopbackDisseminator, which needs
// none. Node.Run starts it alongside BFTClient.Run when present.
type runnable interface {
	Run(ctx context.Context) error
}

// New wires a shard node. It resolves the BFTClient/Round construction
// cycle described in BFTClient.SetDriver: BFTClient is built first (usable
// immediately as a Submitter, even with no driver yet), Round is built
// against it, and then SetDriver closes the loop.
//
// If store has a previously persisted certificate, it is loaded and seeded
// into the client before Run is ever called, so a restarted node's
// non-equivocation check has continuity instead of starting blind — see
// docs/engine-api-adapter-plan.md task C1.4.
func New(
	peer *network.Peer,
	net *network.ShardNetwork,
	signer abcrypto.Signer,
	partitionID types.PartitionID,
	shardID types.ShardID,
	trustBaseStore TrustBaseStore,
	executor Executor,
	disseminator Disseminator,
	store *FileStore,
	log *slog.Logger,
	clientOpts BFTClientOptions,
) (*Node, error) {
	client, err := NewBFTClient(peer, net, signer, partitionID, shardID, trustBaseStore, nil, log, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("creating BFT client: %w", err)
	}

	if store != nil {
		luc, err := store.LoadLUC()
		if err != nil {
			return nil, fmt.Errorf("loading persisted certificate: %w", err)
		}
		if luc != nil {
			client.SeedLUC(luc)
			if log != nil {
				log.Info("resumed from persisted certificate",
					slog.Uint64("round", luc.GetRoundNumber()), slog.Uint64("rootRound", luc.GetRootRoundNumber()))
			}
		}
	}

	round := NewRound(peer.ID().String(), partitionID, shardID, executor, disseminator, signer, client, log)
	client.SetDriver(&persistingDriver{driver: round, store: store})

	return &Node{client: client, round: round, store: store, disseminator: disseminator}, nil
}

// Run blocks until ctx is done or either the client or the disseminator's
// own delivery loop (if it has one — see runnable) hits a fatal error.
func (n *Node) Run(ctx context.Context) error {
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return n.client.Run(gctx) })
	if r, ok := n.disseminator.(runnable); ok {
		g.Go(func() error { return r.Run(gctx) })
	}
	return g.Wait()
}

// persistingDriver wraps Round so every accepted certificate is durably
// saved (see store.go) after it's been handled — placed here rather than
// inside Round itself, since persistence is a CLI/deployment concern
// (where does the file live, is it configured at all) that the round logic
// itself has no opinion about and round_test.go should not need to set up.
type persistingDriver struct {
	driver RoundDriver
	store  *FileStore
}

func (p *persistingDriver) HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	if err := p.driver.HandleCertificate(ctx, uc, tr); err != nil {
		return err
	}
	if p.store == nil {
		return nil
	}
	if err := p.store.SaveLUC(uc); err != nil {
		return fmt.Errorf("persisting certificate: %w", err)
	}
	return nil
}
