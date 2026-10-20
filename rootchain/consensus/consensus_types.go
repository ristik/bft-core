package consensus

import (
	"context"
	"crypto"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	basetypes "github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootevidence"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-core/utbstore"
)

const (
	BlockRate     = 900
	LocalTimeout  = 10000
	HashAlgorithm = crypto.SHA256
	// MaxClockSkew is the DEV live-voting tolerance for UC seal time.
	MaxClockSkew = 30 * time.Second
)

type (
	// Parameters are basic consensus parameters that need to be the same in all root validators.
	// Extracted from root genesis where all validators in the root cluster must have signed them to signal agreement
	Parameters struct {
		BlockRate             time.Duration // also known as T3
		LocalTimeout          time.Duration
		ConsensusThreshold    uint32
		HashAlgorithm         crypto.Hash
		NetworkProfileVersion uint64 // 1 is the legacy root profile; 2 enables handoff
	}
	// Optional are common optional parameters for consensus managers
	Optional struct {
		Params           *Parameters
		FrontierSampler  *FrontierSamplerConfig
		FrontierSigning  bool
		RecoveryProfile2 bool
		RecoveryHistory  *trusthistorystore.Store
		Q3               Q3Authority
		Witnesses        WitnessFetcher
		// UTBPrevious gives the finalized signed trust-base entry of an epoch (the predecessor of the entry a handoff of that epoch produces).
		// Set, the manager endorses the successor entry in the committing votes of epochs configured with votesig.Config.UTB and refuses a
		// certificate of such an epoch whose endorsement is not the one its executed state implies.
		UTBPrevious func(epoch uint64) (*basetypes.RootTrustBaseV2, error)
		// UTBStore is the permanent store of finalized signed entries. Set, it backs UTBPrevious, receives the endorsed entry of every committing
		// certificate before the commit is applied, and is where the installers append the entry of the epoch they install.
		UTBStore *utbstore.Store
		// Evidence is the evidence service's ingress tap: every decoded root vote is offered to it before any filter of onVoteMsg.
		Evidence *rootevidence.Observer
	}

	Option func(c *Optional)
)

func NewConsensusParams() *Parameters {
	return &Parameters{
		BlockRate:     time.Duration(BlockRate) * time.Millisecond,
		LocalTimeout:  time.Duration(LocalTimeout) * time.Millisecond,
		HashAlgorithm: HashAlgorithm,
	}
}

func WithConsensusParams(params Parameters) Option {
	return func(c *Optional) {
		c.Params = &params
	}
}

// WithFrontierSampler opts into the local, unsigned diagnostic sampler.
func WithFrontierSampler(config FrontierSamplerConfig) Option {
	return func(c *Optional) { c.FrontierSampler = &config }
}

// WithFrontierSigning opts into root-signed frontier responses. It requires
// WithFrontierSampler and does not register a transport or production caller.
func WithFrontierSigning() Option {
	return func(c *Optional) { c.FrontierSigning = true }
}

// WithRecoveryProfile2 enables per-certificate historical LastCR verification.
func WithRecoveryProfile2(history *trusthistorystore.Store) Option {
	return func(c *Optional) { c.RecoveryProfile2, c.RecoveryHistory = true, history }
}

// WithUTBPrevious wires the signed trust-base entry (UTB) endorsement: previous returns the finalized entry of an epoch.
func WithUTBPrevious(previous func(epoch uint64) (*basetypes.RootTrustBaseV2, error)) Option {
	return func(c *Optional) { c.UTBPrevious = previous }
}

// WithUTBStore wires the permanent entry store: the finalized entries are read from it, and every committing certificate's endorsed entry and every
// installed epoch's entry is appended to it before the commit or the install is visible.
func WithUTBStore(store *utbstore.Store) Option {
	return func(c *Optional) { c.UTBStore = store }
}

// WithEvidenceObserver wires the evidence service's ingress tap (S3). It only observes: the vote is offered, never changed or admitted, and the
// observer's failures do not reach consensus.
func WithEvidenceObserver(o *rootevidence.Observer) Option {
	return func(c *Optional) { c.Evidence = o }
}

// Q3Authority is the verified Q3 history the manager reads: the signer admission of every epoch (the safety module takes it as
// its activation gate) and the verified entry of an activated epoch (q3active.Runtime). It is what lets a restart across an
// activation recover an epoch anchor whose lineage is a V3 body the V1/V2 recovery history does not hold.
type Q3Authority interface {
	ActivationGate
	Activated(epoch uint64) (q3format.Entry, bool)
	// Lineage is the recovery history a StateMsg is verified against: the base's record for the genesis epoch and the verified
	// history's own exact-weight projection for an activated one.
	Lineage(base abdrc.HistoricalTrustBases) abdrc.HistoricalTrustBases
	// FreezeRules is the V3 rule set the old committee applies when it endorses and orders the Freeze of a V3 successor.
	FreezeRules() storage.V3FreezeRules
	// ProtocolConfig is the protocol tuple a V3 body this chain plans carries: its network and root genesis from the verified history.
	ProtocolConfig() (q3format.ProtocolConfig, error)
}

// WithQ3 gives the manager the verified Q3 history. Without it nothing changes.
func WithQ3(a Q3Authority) Option {
	return func(c *Optional) { c.Q3 = a }
}

// WitnessFetcher retrieves a control witness of at most maxBytes by its SHA-256 from the given peers, in order. A returned witness has been checked against
// the hash.
type WitnessFetcher func(ctx context.Context, hash [32]byte, peers []peer.ID, maxBytes int) ([]byte, error)

// WithWitnessFetcher lets the manager fetch the witnesses of a block's controls from the other root nodes before it executes the block.
// Without it a block whose witnesses are not already retained is refused as unavailable.
func WithWitnessFetcher(f WitnessFetcher) Option {
	return func(c *Optional) { c.Witnesses = f }
}

func LoadConf(opts []Option) (*Optional, error) {
	conf := &Optional{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(conf)
	}

	if conf.Params == nil {
		conf.Params = NewConsensusParams()
	}

	return conf, nil
}
