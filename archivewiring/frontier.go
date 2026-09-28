package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

// CertifiedBinding uses the node's independently configured trust base. It
// never accepts a trust anchor from the archive record being checked.
type CertifiedBinding struct {
	Context configuredprogress.Context
	Subject archive.Context
}

func (v CertifiedBinding) VerifyCertified(r frontier.Record, rec *archive.Record) error {
	if rec == nil || !sameArchiveContext(r.Subject.Context, v.Subject) {
		return frontier.ErrContext
	}
	var header gethtypes.Header
	var body gethtypes.Body
	if rlp.DecodeBytes(rec.Header, &header) != nil || rlp.DecodeBytes(rec.Body, &body) != nil || header.Number == nil || header.Number.Uint64() != r.Height || header.Hash() != common.Hash(r.Subject.BlockHash) || header.Root != common.Hash(r.StateRoot) || header.UncleHash != gethtypes.EmptyUncleHash || header.Difficulty == nil || header.Difficulty.Sign() != 0 {
		return frontier.ErrInvalid
	}
	if header.TxHash != gethtypes.DeriveSha(gethtypes.Transactions(body.Transactions), trie.NewStackTrie(nil)) || len(body.Uncles) != 0 || len(body.Withdrawals) != 0 || header.WithdrawalsHash == nil || *header.WithdrawalsHash != gethtypes.DeriveSha(gethtypes.Withdrawals{}, trie.NewStackTrie(nil)) {
		return frontier.ErrInvalid
	}
	var original, result types.UnicityCertificate
	if types.Cbor.Unmarshal(rec.OriginalUC, &original) != nil || types.Cbor.Unmarshal(rec.ResultingUC, &result) != nil {
		return frontier.ErrInvalid
	}
	// Decode the technical records into their concrete type and authenticate
	// each pair against the local root trust base.
	var ot, rt certification.TechnicalRecord
	if types.Cbor.Unmarshal(rec.OriginalTR, &ot) != nil || types.Cbor.Unmarshal(rec.ResultingTR, &rt) != nil {
		return frontier.ErrInvalid
	}
	for _, pair := range []struct {
		value any
		raw   []byte
	}{{&original, rec.OriginalUC}, {&ot, rec.OriginalTR}, {&result, rec.ResultingUC}, {&rt, rec.ResultingTR}} {
		canonical, err := types.Cbor.Marshal(pair.value)
		if err != nil || !bytes.Equal(canonical, pair.raw) {
			return frontier.ErrInvalid
		}
	}
	ctx := context.Background()
	if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, v.Context.Observation, &original, &ot); err != nil {
		return fmt.Errorf("%w: original: %v", frontier.ErrInvalid, err)
	}
	if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, v.Context.Observation, &result, &rt); err != nil {
		return fmt.Errorf("%w: resulting: %v", frontier.ErrInvalid, err)
	}
	rootEpoch := r.Epoch
	if rootEpoch == 0 {
		rootEpoch = v.Subject.RootEpoch
	}
	if result.InputRecord == nil || result.GetRootEpoch() != rootEpoch || result.GetRootRoundNumber() != r.Round || !bytes.Equal(result.InputRecord.BlockHash, r.Subject.BlockHash[:]) || !bytes.Equal(result.InputRecord.Hash, r.StateRoot[:]) || ot.Round != result.InputRecord.RoundNumber || rootinput.CheckEpochCertificates(&original, &result) != nil || original.GetRootEpoch() == result.GetRootEpoch() && original.GetRootRoundNumber() >= result.GetRootRoundNumber() {
		return frontier.ErrInvalid
	}
	var companion engineapi.SealCompanion
	if json.Unmarshal(rec.Companion, &companion) != nil || len(companion.RootInput) == 0 || len(companion.Witnesses) != engineapi.SealCompanionWitnessCount || !bytes.Equal(companion.RootInput, rec.CanonicalRootInput) || !bytes.Equal(companion.Witnesses[0], rec.OriginalUC) || !bytes.Equal(companion.Witnesses[1], rec.OriginalTR) {
		return frontier.ErrInvalid
	}
	canonical, _ := json.Marshal(companion)
	commitment := sha256.Sum256(rec.CanonicalRootInput)
	beacon := common.Hash(evmroot.DeriveBeaconRoot(original.GetRootRoundNumber(), result.InputRecord.RoundNumber))
	if !bytes.Equal(canonical, rec.Companion) || !bytes.Equal(header.Extra, commitment[:]) || header.ParentBeaconRoot == nil || *header.ParentBeaconRoot != beacon {
		return frontier.ErrInvalid
	}
	return nil
}

func sameArchiveContext(a, b archive.Context) bool {
	if !bytes.Equal(a.ExecutionIdentity, b.ExecutionIdentity) {
		return false
	}
	a.ExecutionIdentity, b.ExecutionIdentity = nil, nil
	return reflect.DeepEqual(a, b)
}

// ReplicaAvailability re-reads a complete response from the static peer
// endpoint. A put acknowledgement never establishes this predicate.
type ReplicaAvailability struct {
	Context  context.Context
	Host     shardnode.EvidenceHost
	Replicas [2]peer.ID
	Limits   Limits
}

func (v ReplicaAvailability) VerifyAvailable(name string, q archive.Request, expected [32]byte) error {
	var id peer.ID
	for _, configured := range v.Replicas {
		if name == configured.String() {
			id = configured
			break
		}
	}
	if id == "" || v.Host == nil || !v.Limits.valid() {
		return frontier.ErrContext
	}
	ctx := v.Context
	if ctx == nil {
		ctx = context.Background()
	}
	request, err := archive.EncodeRequest(q)
	if err != nil {
		return err
	}
	answer, err := exchange(ctx, v.Host, id, append([]byte{2}, request...), v.Limits)
	if err != nil {
		return fmt.Errorf("%w: %v", frontier.ErrUnavailable, err)
	}
	response, err := archive.DecodeFor(q, answer)
	if err != nil || response.Outcome != archive.OK || response.Record == nil {
		return frontier.ErrUnavailable
	}
	got, err := archive.ManifestDigest(q, response.Record)
	if err != nil || got != expected {
		return frontier.ErrUnavailable
	}
	return nil
}
