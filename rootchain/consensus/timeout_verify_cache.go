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
// timeoutCacheKey is the identity under which a verified and counted timeout message is remembered: a SHA-256 over the complete message
// (signature, full high QC, full last TC, anchors, scheme: any change is a different message) and the signing configuration of every epoch the
// verification depends on. ok is false when the message cannot be encoded or a configuration is unknown: then nothing is ever remembered or
// found for it, and it takes the ordinary path.
//
// A message received from the network is identified by the digest of the bytes it was decoded from (TakeWireDigest) instead of being encoded
// again (at 128 members that encoding was about half of the handling of a retransmitted vote, #982). It is the same identity: the codec is
// deterministic and canonical, so an honest sender's bytes are the encoding of its message, and a hit means the bytes equal those of the
// counted message (or its encoding), which is what the encoded digest established before: decoding them gives the same content. Bytes that are
// not a canonical encoding match only themselves. A message built in memory (this node's own vote, looped back) is encoded as before.
// This rests on an ownership invariant, not on the type: a decoded message reaches here unchanged (the stream handler decodes it and the
// loop hands it over as it is). Any future path that decodes a timeout message and edits it before it is handled must drop the digest
// (TakeWireDigest) when it edits, or a changed message would be taken for the verified one.
func (x *ConsensusManager) timeoutCacheKey(vote *abdrc.TimeoutMsg) (digest [32]byte, ctx verifyContext, ok bool) {
	start := time.Now()
	defer func() { x.profile.digestTime += time.Since(start) }()
	if wire, decoded := vote.TakeWireDigest(); decoded {
		digest = wire
	} else {
		raw, err := types.Cbor.Marshal(vote)
		if err != nil {
			return digest, ctx, false
		}
		digest = sha256.Sum256(raw)
	}
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
