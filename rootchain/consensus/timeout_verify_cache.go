package consensus

import (
	"crypto/sha256"
	"slices"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

// verifyTimeoutVote is the one verification of a timeout message (the signature of the author, its high QC and its last TC).
func (x *ConsensusManager) verifyTimeoutVote(vote *abdrc.TimeoutMsg) error {
	if x.timeoutVerify != nil {
		return x.timeoutVerify(vote)
	}
	return vote.Verify(x.trustBaseStore)
}

// Invariant the remembered verification rests on: the manager keeps one trust-base store and one genesis pin for the cache's lifetime (the
// pin is set while the manager is constructed; QuorumCert.VerifyWith reads it as well as the signing configuration), an installed epoch's
// trust base never changes (TrustBaseStore.Store refuses a second one; InstallV2Projection refuses conflicting installed keys or weights),
// and the cache lives in the vote register, which every round start clears. Any future replacement of the store or the pin must clear the
// register's remembered messages or become part of verifyContext.
//
// timeoutCacheKey is the identity under which a verified and counted timeout message is remembered: the SHA-256 of the complete encoded
// message (signature, full high QC, full last TC, anchors, scheme: any change is a different message) and the signing configuration of every
// epoch the verification depends on. ok is false when the message cannot be encoded or a configuration is unknown: then nothing is
// ever remembered or found for it, and it takes the ordinary path.
func (x *ConsensusManager) timeoutCacheKey(vote *abdrc.TimeoutMsg) (digest [32]byte, ctx verifyContext, ok bool) {
	start := time.Now()
	defer func() { x.profile.digestTime += time.Since(start) }()
	raw, err := types.Cbor.Marshal(vote)
	if err != nil {
		return digest, ctx, false
	}
	digest = sha256.Sum256(raw)
	epochs := []uint64{vote.Timeout.Epoch}
	if hqc := vote.Timeout.HighQc; hqc != nil && hqc.VoteInfo != nil {
		epochs = append(epochs, hqc.VoteInfo.Epoch)
	}
	if tc := vote.LastTC; tc != nil && tc.Timeout != nil {
		epochs = append(epochs, tc.Timeout.Epoch)
		if hqc := tc.Timeout.HighQc; hqc != nil && hqc.VoteInfo != nil {
			epochs = append(epochs, hqc.VoteInfo.Epoch)
		}
	}
	slices.Sort(epochs)
	epochs = slices.Compact(epochs)
	if len(epochs) > len(ctx.epochs) {
		return digest, ctx, false
	}
	for i, e := range epochs {
		cfg, err := x.trustBaseStore.SigningConfig(e)
		if err != nil {
			return digest, ctx, false
		}
		ctx.epochs[i], ctx.cfgs[i] = e, cfg
	}
	ctx.n = len(epochs)
	return digest, ctx, true
}
