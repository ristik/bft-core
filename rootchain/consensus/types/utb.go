package types

import (
	"crypto/sha256"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/utbentry"
)

// UTBVote is the endorsement a committing vote carries when the committed state holds the outgoing handoff: the unsigned successor entry
// (types.RootTrustBaseV2.SigBytes) and the voter's signature over exactly those bytes. The entry's identity is SHA-256 of Unsigned.
type UTBVote struct {
	_         struct{} `cbor:",toarray"`
	Unsigned  hex.Bytes
	Signature hex.Bytes
}

// EntryID is the identity of the endorsed entry.
func (v *UTBVote) EntryID() [32]byte { return sha256.Sum256(v.Unsigned) }

// UTBCertificate is the aggregate of the endorsements of a certificate's voters: the unsigned entry and the signatures of the old committee's members.
type UTBCertificate struct {
	_          struct{} `cbor:",toarray"`
	Unsigned   hex.Bytes
	Signatures map[string]hex.Bytes
}

func (c *UTBCertificate) EntryID() [32]byte { return sha256.Sum256(c.Unsigned) }

// strictCertMode refuses duplicate map keys, which the default decoder would silently collapse.
var strictCertMode = func() cbor.DecMode {
	m, err := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden, MaxNestedLevels: 8,
		MaxArrayElements: 64, MaxMapPairs: 1024}.DecMode()
	if err != nil {
		panic(err)
	}
	return m
}()

func (c *UTBCertificate) UnmarshalCBOR(data []byte) error {
	type alias UTBCertificate
	var a alias
	if err := strictCertMode.Unmarshal(data, &a); err != nil {
		return fmt.Errorf("%w: %w", votesig.ErrUTB, err)
	}
	*c = UTBCertificate(a)
	return nil
}

// qcV3Wire is the version 3 envelope of a certificate: [3, inner, utb|null].
type qcV3Wire struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Inner   cbor.RawMessage
	UTB     *UTBCertificate
}

// ErrEnvelope helpers ----------------------------------------------------------------------------------------------------------------------------

// checkEnvelope is the epoch rule: a version 3 envelope exactly in a UTB epoch. The genesis certificate is fixed by the software and exempt.
func (x *QuorumCert) checkEnvelope(cfg votesig.Config) error {
	if x.GetRound() == GenesisRootRound {
		return nil
	}
	if cfg.UTB != (x.Envelope == votesig.EnvelopeUTB) {
		return fmt.Errorf("%w: certificate envelope %d, epoch UTB=%v", votesig.ErrEnvelope, x.Envelope, cfg.UTB)
	}
	if x.Envelope != votesig.EnvelopeUTB && x.UTB != nil {
		return fmt.Errorf("%w: endorsement outside the version 3 envelope", votesig.ErrEnvelope)
	}
	return nil
}

// verifyUTB checks the certificate's endorsement, if it has one. It is structural and cryptographic only: that the entry is the one the committed
// state implies is the contextual binding the committer checks (the executed block is needed for it). The endorsement is bound to the certificate:
// it is of a committing certificate, of the epoch after the certificate's, of the configured network, signed by exactly the certificate's voters
// (strictly, every signature valid, no unknown signer) and its weight reaches the voting committee's threshold.
func (x *QuorumCert) verifyUTB(tb types.RootTrustBase, cfg votesig.Config) error {
	if x.UTB == nil {
		return nil
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{votesig.ErrUTB}, a...)...)
	}
	if x.GetRound() == GenesisRootRound {
		return bad("the genesis certificate carries none")
	}
	if len(x.LedgerCommitInfo.Hash) == 0 && x.LedgerCommitInfo.RootChainRoundNumber == 0 {
		return bad("a non-committing certificate carries one")
	}
	entry, err := utbentry.Decode(x.UTB.Unsigned)
	if err != nil {
		return bad("%v", err)
	}
	if entry.Epoch != x.VoteInfo.Epoch+1 || uint64(entry.NetworkID) != cfg.Network {
		return bad("entry epoch %d network %d, certificate epoch %d network %d", entry.Epoch, entry.NetworkID, x.VoteInfo.Epoch, cfg.Network)
	}
	if len(x.UTB.Signatures) != len(x.Signatures) {
		return fmt.Errorf("%w: %d endorsements for %d voters", votesig.ErrSignerSets, len(x.UTB.Signatures), len(x.Signatures))
	}
	for id, sig := range x.UTB.Signatures {
		if _, ok := x.Signatures[id]; !ok {
			return fmt.Errorf("%w: %q endorsed but did not vote", votesig.ErrSignerSets, id)
		}
		if err := votesig.CheckSignatureShape(sig); err != nil {
			return bad("signature of %q: %v", id, err)
		}
	}
	if _, err := quorumweight.VerifySignedStrict(tb, x.UTB.Unsigned, x.UTB.Signatures); err != nil {
		return bad("%v", err)
	}
	return nil
}
