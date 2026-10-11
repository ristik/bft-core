package bridgeprofile

import (
	gocrypto "crypto"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Deployment is the full deterministic DEV deployment behind the oracle's
// tests and the candidate corpus: the Cfg fixture, an EVM shard holding the
// vault, a root authority with its trust base and an aggregator
// shard. Every value is a DEV fixture input, not a production parameter.
type Deployment struct {
	F      *Fixture
	Auth   *Authority
	TB     *types.RootTrustBaseV1
	Trust  *TrustInput // the one pinned SDK trust-base document
	EVMPDR *types.PartitionDescriptionRecord
	Pin    *DeploymentPin
	World  *LockWorld
	Agg    *AggregatorWorld
}

// Deployment constants.
const (
	DevChainID   = 31337
	DevRootRound = 40 // root round of the embedded lock certificates
	DevAggPart   = 11
	DevEVMPart   = 7
	DevNetwork   = 3
)

// NewDeployment builds the DEV deployment.
func NewDeployment() (*Deployment, error) {
	auth, err := NewAuthority("root-1")
	if err != nil {
		return nil, err
	}
	tb, err := auth.TrustBase(DevNetwork, 1)
	if err != nil {
		return nil, err
	}
	tbJSON, err := RenderTrustBaseJSON(tb)
	if err != nil {
		return nil, err
	}
	trust, err := LoadTrustInput(tbJSON)
	if err != nil {
		return nil, err
	}
	// The DN-B topology: one aggregator partition, depth 1, shards 40 and c0.
	left, right := types.ShardID{}.Split()
	var aggPDRs []*types.PartitionDescriptionRecord
	var confs [][32]byte
	for i, sh := range []types.ShardID{left, right} {
		pdr := FixtureShardPDR(DevNetwork, DevAggPart, sh, DevChainID, fmt.Sprint("agg-", i))
		aggConf, err := pdr.Hash(gocrypto.SHA256)
		if err != nil {
			return nil, err
		}
		var conf [32]byte
		copy(conf[:], aggConf)
		aggPDRs = append(aggPDRs, pdr)
		confs = append(confs, conf)
	}
	f := NewFixture(DevChainID, DevAggPart, confs...)
	evm := FixturePDR(DevNetwork, DevEVMPart, DevChainID, "evm")
	w := &LockWorld{Vault: f.Cfg.Vault, VaultCodeHash: H([]byte("fixture-vault-runtime")), Locks: map[uint64][32]byte{}, Filler: 5}
	return &Deployment{F: f, Auth: auth, TB: tb, Trust: trust, EVMPDR: evm,
		Pin: &DeploymentPin{Genesis: evm, VaultCodeHash: w.VaultCodeHash}, World: w,
		Agg: &AggregatorWorld{PDRs: aggPDRs, Auth: auth, TB: tb}}, nil
}

// LockDigestFor is the digest the vault stores for a mint of amount to p0.
func (d *Deployment) LockDigestFor(n uint64, amount *big.Int, p0 Predicate) [32]byte {
	c := d.F.Cfg
	ch := c.Hash()
	id := DeriveTokenID(DeriveSalt(ch, n), c.Network)
	return LockDigest(ch, n, LockRecord(c.ZeroAddress, c.Ty, c.Aid, amount, id, H(p0.Bytes())))
}

// Backed locks (n, amount, keys[0]) in the world and builds a history whose
// mint embeds the real, certified lock proof.
func (d *Deployment) Backed(n uint64, amount *big.Int, keys []*secp256k1.PrivateKey) (*History, *LockProof, error) {
	d.World.Locks[n] = d.LockDigestFor(n, amount, sigPred(keys[0]))
	lp, err := d.World.Certified(d.F, d.Auth, d.EVMPDR, d.Trust, DevRootRound, n, 9)
	if err != nil {
		return nil, nil, err
	}
	h, err := d.F.BuildTokenWith(n, amount, keys, BuildOpts{Proof: lp})
	return h, lp, err
}
