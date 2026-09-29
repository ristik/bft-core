// Package archivewiring publishes journal-certified execution records to the
// bounded archive store and configured replica peers.
package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrUncertified = errors.New("archive wiring: no certified association")
var ErrBinding = errors.New("archive wiring: certified block binding invalid")

// ContextFrom binds archive keys to the node's checked deployment and complete
// canonical execution configuration bytes, never to a peer-supplied identity.
func ContextFrom(c configuredprogress.Context, identity []byte) (archive.Context, error) {
	proof := c.Record.Registry
	var out archive.Context
	out.NetworkID, out.PartitionID, out.ShardID = c.Record.NetworkID, c.Record.PartitionID, c.Record.ShardID
	out.ShardEpoch, out.RootEpoch = proof.ShardEpoch, proof.RootEpoch
	if len(c.Record.FullShardConfHash) != 32 {
		return archive.Context{}, archive.ErrInvalid
	}
	copy(out.FullShardConfHash[:], c.Record.FullShardConfHash)
	copy(out.RegistryAddress[:], proof.RegistryAddress[:])
	copy(out.RegistryCodeHash[:], proof.RegistryCodeHash[:])
	copy(out.GenesisCommitment[:], proof.GenesisCommitment[:])
	copy(out.EVMGenesisHash[:], proof.EVMGenesisHash[:])
	return archive.WithIdentity(out, archive.RawIdentity(identity))
}

// FromJournal rechecks the two certificate roles and reconstructs the exact
// execution bytes. With an adapter it also rechecks the parent witness and
// canonical root input before local publication. A replica may omit that
// time-limited witness read: its own journal admitted the candidate through
// CheckBlockBinding before certification. It still compares every archive byte
// with the authenticated local journal association.
func FromJournal(ctx context.Context, c configuredprogress.Context, subject archive.Context, adapter *engineapi.Adapter, e configuredprogress.JournalEntry) (archive.Request, *archive.Record, error) {
	if !e.Certified || e.ResultingUC == nil || e.ResultingTR == nil || e.Candidate.AuthorizingUC == nil || e.Candidate.AuthorizingTR == nil {
		return archive.Request{}, nil, ErrUncertified
	}
	b := e.Candidate
	if len(b.Hash) != 32 || len(b.StateRoot) != 32 || len(b.ParentHash) != 32 || len(b.ParentState) != 32 {
		return archive.Request{}, nil, ErrBinding
	}
	if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, b.AuthorizingUC, b.AuthorizingTR); err != nil {
		return archive.Request{}, nil, fmt.Errorf("%w: original pair: %v", ErrBinding, err)
	}
	if _, err := rootinput.AuthenticateHistoricalObservationV2(ctx, c.Observation, e.ResultingUC, e.ResultingTR); err != nil {
		return archive.Request{}, nil, fmt.Errorf("%w: resulting pair: %v", ErrBinding, err)
	}
	if e.ResultingUC.InputRecord.RoundNumber != b.Round || !bytes.Equal(e.ResultingUC.InputRecord.BlockHash, b.Hash) || !bytes.Equal(e.ResultingUC.InputRecord.Hash, b.StateRoot) || rootinput.CheckEpochCertificates(b.AuthorizingUC, e.ResultingUC) != nil || b.AuthorizingUC.GetRootEpoch() == e.ResultingUC.GetRootEpoch() && b.AuthorizingUC.GetRootRoundNumber() >= e.ResultingUC.GetRootRoundNumber() {
		return archive.Request{}, nil, ErrBinding
	}
	seal, err := shardnode.SealHash(b.AuthorizingUC)
	if err != nil {
		return archive.Request{}, nil, fmt.Errorf("%w: authorizing seal: %v", ErrBinding, err)
	}
	block := shardnode.Block{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot, ParentHash: b.ParentHash, Raw: b.Raw, BlockSize: b.BlockSize, StateSize: b.StateSize}
	p := shardnode.RoundParams{Round: b.Round, Epoch: b.AuthorizingTR.Epoch, Timestamp: b.AuthorizingUC.UnicitySeal.Timestamp, SealHash: seal, Leader: b.AuthorizingTR.Leader, Parent: shardnode.BlockRef{Number: b.ParentNumber, Hash: b.ParentHash, StateRoot: b.ParentState}, AuthorizingCertificate: b.AuthorizingUC, AuthorizingTechnicalRecord: b.AuthorizingTR}
	if adapter != nil {
		if err := adapter.CheckBlockBinding(adapter.HistoricalContext(ctx), block, p); err != nil {
			return archive.Request{}, nil, fmt.Errorf("%w: %v", ErrBinding, err)
		}
	}
	header, body, root, companion, err := engineapi.ArchiveParts(block, b.AuthorizingUC.GetRootRoundNumber(), b.Round)
	if err != nil {
		return archive.Request{}, nil, fmt.Errorf("%w: %v", ErrBinding, err)
	}
	originalUC, err := types.Cbor.Marshal(b.AuthorizingUC)
	if err != nil {
		return archive.Request{}, nil, err
	}
	originalTR, err := types.Cbor.Marshal(b.AuthorizingTR)
	if err != nil {
		return archive.Request{}, nil, err
	}
	resultingUC, err := types.Cbor.Marshal(e.ResultingUC)
	if err != nil {
		return archive.Request{}, nil, err
	}
	resultingTR, err := types.Cbor.Marshal(e.ResultingTR)
	if err != nil {
		return archive.Request{}, nil, err
	}
	q := archive.Request{Context: subject}
	copy(q.BlockHash[:], b.Hash)
	rec := &archive.Record{Header: header, Body: body, CanonicalRootInput: root, OriginalUC: originalUC, OriginalTR: originalTR, ResultingUC: resultingUC, ResultingTR: resultingTR, Companion: companion}
	if _, err := archive.ManifestDigest(q, rec); err != nil {
		return archive.Request{}, nil, fmt.Errorf("%w: manifest: %v", ErrBinding, err)
	}
	return q, rec, nil
}
