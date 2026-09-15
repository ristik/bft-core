package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"log/slog"
	"time"

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
	health       *Health

	// recoveryDeps is what EnableRecovery needs and New already has. Kept rather than added to
	// New's signature because whether a node serves or recovers is a deployment decision made after
	// the node is wired, alongside SetAwaitTimeout and SetMetrics.
	recoveryDeps RecoveryDeps
	recovery     *RecoveryStack
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
	shardConfHash []byte,
	trustBaseStore TrustBaseStore,
	executor Executor,
	disseminator Disseminator,
	store *FileStore,
	log *slog.Logger,
	clientOpts BFTClientOptions,
) (*Node, error) {
	// Checked before anything is built: a node with no configured shard configuration cannot check
	// what configuration a certificate was issued under, live or restored (#134). One value, cloned
	// once here, is then used by the client, by restoration and by recovery — enabling serving or
	// recovery cannot introduce a second, different expected identity.
	if len(shardConfHash) == 0 {
		return nil, errors.New("no shard configuration hash: this node could not tell a certificate for its own shard configuration from one issued under another")
	}
	if err := validateShardConfHashWidth(shardConfHash); err != nil {
		return nil, err
	}
	shardConfHash = bytes.Clone(shardConfHash)

	client, err := NewBFTClient(peer, net, signer, partitionID, shardID, shardConfHash, trustBaseStore, nil, log, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("creating BFT client: %w", err)
	}

	round := NewRound(peer.ID().String(), partitionID, shardID, executor, disseminator, signer, client, log)

	if store != nil {
		luc, err := store.LoadLUC()
		if err != nil {
			return nil, fmt.Errorf("loading persisted certificate: %w", err)
		}
		if luc != nil {
			// Authenticate before seeding. The stored certificate becomes this node's
			// non-equivocation authority: every certificate arriving from the network is
			// judged against it, and a classification failure leaves it in place, so an
			// unauthenticated one wedges the node against genuine, correctly signed
			// certificates. It was previously installed on the strength of having decoded.
			//
			// The trust base comes from the configured store, never from the checkpoint —
			// the checkpoint names a root epoch, and that name is exactly what is in
			// question, so an unknown or untrusted epoch must fail rather than be adopted.
			if err := verifyRestoredLUC(luc, trustBaseStore, partitionID, shardID, shardConfHash); err != nil {
				return nil, fmt.Errorf("authenticating persisted certificate (round %d, root round %d): %w",
					luc.GetRoundNumber(), luc.GetRootRoundNumber(), err)
			}
			resumeFrom(client, round, luc)
			if log != nil {
				log.Info("resumed from persisted certificate: with a local signing key this node is NON-VOTING for the rest of this process; through a signing authority it signs only what the authority's record admits, after P-id (#105)",
					slog.Uint64("round", luc.GetRoundNumber()), slog.Uint64("rootRound", luc.GetRootRoundNumber()))
			}
		}
	}

	client.SetDriver(&persistingDriver{driver: round, store: store})

	health := NewHealth()
	client.SetHealth(health)
	round.SetHealth(health)

	return &Node{
		client: client, round: round, store: store, disseminator: disseminator, health: health,
		recoveryDeps: RecoveryDeps{
			Host:          peer,
			Executor:      executor,
			PartitionID:   partitionID,
			ShardID:       shardID,
			ShardConfHash: shardConfHash,
			TrustBases:    trustBaseStore,
			Gate:          NewFinalityGate(),
			Log:           log,
		},
	}, nil
}

/*
resumeFrom installs an authenticated persisted certificate, and is the only place production code
calls SeedLUC.

The two calls are here together, in one function, on purpose. They are two halves of one decision —
"this process is a resumption" — and the defect they fix was precisely that the first half was
performed and the second was not: New verified the checkpoint, seeded the certificate cursor, and
then built an unrestricted Round that signed from the next certificate onward. Restoring the cursor
without applying the signing gate should not be expressible in this file, so it is not.

See Round.MarkRestored for why an authenticated checkpoint is not authorization to vote, and design
§6.1 for the contract (#105) that will eventually let a restored node vote again.
*/
func resumeFrom(client *BFTClient, round *Round, luc *types.UnicityCertificate) {
	client.SeedLUC(luc)
	round.MarkRestored(luc.GetRoundNumber())
}

// SetAwaitTimeout bounds how long this node waits for the round leader's disseminated block before
// abstaining. Call after New, before Run. Callers should derive it from the shard's T2 with
// AwaitTimeoutForT2 rather than picking a value: see that function for what a budget longer than T2
// does to a validator whose leader has gone quiet.
func (n *Node) SetAwaitTimeout(d time.Duration) {
	n.round.SetAwaitTimeout(d)
}

// SetMetrics attaches an optional Metrics recorder to both the round loop
// and the root-chain client. Call after New, before Run.
func (n *Node) SetMetrics(m *Metrics) {
	n.client.SetMetrics(m)
	n.round.SetMetrics(m)
}

// SetCertificationSigner routes this node's certification requests through the given signer. Call
// after New, before Run. See Round.SetCertificationSigner: it is an explicit deployment step, P-id
// still applies ahead of it, a refusal is an abstention, and a node resumed from its checkpoint signs
// only through a signer built by NewAuthoritySigner (Round.abstainRestored).
func (n *Node) SetCertificationSigner(s CertificationSigner) {
	n.round.SetCertificationSigner(s)
}

// SetCertifiedRecordStatus reports the outcome of reloading the certified-block record (#14) in health. It
// is a status only: nothing about rounds, voting or signing reads it.
func (n *Node) SetCertifiedRecordStatus(outcome, detail string) {
	n.health.updateCertifiedRecord(outcome, detail)
}

// SetCommitObserver attaches an observer told about every block the round commits on a certificate's
// authority (#14 W2). Call after New, before Run.
func (n *Node) SetCommitObserver(o CommitObserver) {
	n.round.SetCommitObserver(o)
}

// Health returns this node's live status snapshot — see health.go. Always
// non-nil; wire it into an HTTP handler to expose it (see
// cli/ubft/cmd/shard_node_run.go).
func (n *Node) Health() *Health {
	return n.health
}

/*
EnableRecovery turns on authenticated-evidence anchor recovery (#92, design §6), either half of it.

Call after New, before Run. Serving and recovering are separate switches because they have different
costs: serving retains certificates this node has already authenticated and answers bounded requests,
taking no new dependency; recovering depends on peers answering and ends in a finality-changing
executor call. A node that enables neither behaves exactly as it did before any of this existed.

The finality gate is installed with the stack, and it is what keeps a recovery commit from
interleaving with the round's own (finality.go).
*/
// The shard configuration hash travels in RecoveryOptions rather than through New: New does not
// receive the shard configuration (the gap verifyRestoredLUC documents, F2/#10), and recovery refuses
// to start without it — an absent hash does not make that check lenient, it removes it.
func (n *Node) EnableRecovery(opts RecoveryOptions) error {
	stack, err := NewRecoveryStack(opts, n.recoveryDeps)
	if err != nil {
		return err
	}
	if stack == nil {
		return nil
	}
	n.recovery = stack
	n.round.SetRecovery(stack)
	return nil
}

// Run blocks until ctx is done or either the client or the disseminator's
// own delivery loop (if it has one — see runnable) hits a fatal error.
//
// The recovery lifecycle's background work is stopped on the way out, so a node that returns from
// Run leaves no fetch running against a peer that is no longer being listened to.
func (n *Node) Run(ctx context.Context) error {
	defer n.recovery.Close()
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

/*
verifyRestoredLUC authenticates a certificate loaded from local storage before it is
allowed to become this node's non-equivocation authority (issue #86, delivery step 4).

What it checks, via the same types.UnicityCertificate.Verify the network path uses: the
seal's root-quorum signatures against the trust base for the certificate's root epoch,
the shard-tree and unicity-tree inclusion paths against the sealed root hash, and that
the certificate is for this node's partition and shard.

The expected shard configuration hash is supplied from this node's startup configuration,
not the checkpoint. Both live delivery and restoration compare it through UC.Verify.
An absent or malformed expected hash is refused before it can disable that comparison.

The trust base is taken from the configured store, never from the checkpoint. An epoch
the store does not know is a failure, not a reason to trust the file: the checkpoint
names its own epoch, and that name is precisely what is in question.

Startup is a synchronous, local operation and the configured store is file-backed, so
this uses a background context rather than threading one through New.
*/
func verifyRestoredLUC(uc *types.UnicityCertificate, trustBaseStore TrustBaseStore, partitionID types.PartitionID, shardID types.ShardID, shardConfHash []byte) error {
	if trustBaseStore == nil {
		return errors.New("no trust base store configured")
	}
	// Without the configured hash the comparison is not lenient, it is absent (#134): the checkpoint
	// on disk is exactly the thing whose configuration is in question, so its own claim cannot supply
	// the expectation.
	if len(shardConfHash) == 0 {
		return errors.New("no shard configuration hash configured, so the certificate's shard configuration cannot be checked")
	}
	if err := validateShardConfHashWidth(shardConfHash); err != nil {
		return err
	}
	tb, err := trustBaseStore.GetByEpoch(context.Background(), uc.GetRootEpoch())
	if err != nil {
		return fmt.Errorf("loading trust base for root epoch %d: %w", uc.GetRootEpoch(), err)
	}
	if err := uc.Verify(tb, crypto.SHA256, partitionID, shardID, shardConfHash); err != nil {
		return fmt.Errorf("verifying certificate: %w", err)
	}
	return nil
}

// validateShardConfHashWidth rejects malformed local expectations before network work.
// The certificate profile and configuration hash routine both use SHA-256.
func validateShardConfHashWidth(hash []byte) error {
	if len(hash) != crypto.SHA256.Size() {
		return fmt.Errorf("malformed shard configuration hash: got %d bytes, want %d", len(hash), crypto.SHA256.Size())
	}
	return nil
}
