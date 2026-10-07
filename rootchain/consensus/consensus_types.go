package consensus

import (
	"crypto"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

const (
	BlockRate     = 900
	LocalTimeout  = 10000
	HashAlgorithm = crypto.SHA256
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
