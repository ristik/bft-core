/*
Package certifiedstore is the durable store for the certified-block record of
docs/design/f6a-certified-record-crash-contract.md: one record per certified EVM block B, holding the
authenticated context, B's identity, the certificate and technical record that certify B, and witness(B).

It publishes a record, the head pointer that names it and the retention deletions in ONE bbolt transaction,
and it loads the head record by re-verifying everything against configuration supplied by the caller:
nothing in the store is trusted because it is there. It never falls back to an older retained record.

It is storage only. It decides durable readiness for B (the record verifies), not readiness for B's child:
continuity to the held certificate (§6.1 of the contract), the executor comparison, startup and network
acquisition belong to the node wiring unit. It holds no signing state. Nothing in production imports it
(inert_test.go). docs/design/f6b-certified-record-store.md records what a successful commit guarantees and
what still depends on the operating system and filesystem.
*/
package certifiedstore

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// RecordVersion is the only record version this build writes or reads.
const RecordVersion uint32 = 1

// MaxRecordBytes bounds a stored value before it is decoded, and a record before it is written.
const MaxRecordBytes = 1 << 20

var (
	ErrNoRecord        = errors.New("certifiedstore: no durable record")
	ErrRecordUntrusted = errors.New("certifiedstore: stored record is damaged or unreadable")
	ErrRecordVersion   = errors.New("certifiedstore: unsupported record version")
	ErrWrongContext    = errors.New("certifiedstore: record or certificate is for another context")
	ErrCertificate     = errors.New("certifiedstore: certificate does not authenticate")
	ErrWrongBlock      = errors.New("certifiedstore: record, certificate and witness do not name the same block")
	ErrTechnicalRecord = errors.New("certifiedstore: technical record is not the one the certificate commits to")
	ErrWitness         = errors.New("certifiedstore: witness does not verify")
	ErrEpoch           = errors.New("certifiedstore: authenticated certificate is for an epoch the configuration does not support")
	ErrWrongRound      = errors.New("certifiedstore: certified partition round is not the round the witness shows executed")
	ErrConfig          = errors.New("certifiedstore: invalid configuration")
	ErrSettings        = errors.New("certifiedstore: invalid settings")
)

// TrustBases is the configured trust base store, keyed by root epoch. It has the method set of
// shardnode.TrustBaseStore, stated here so this package does not import shardnode.
type TrustBases interface {
	GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
}

// Context is what the node brings to publication and loading. Every value comes from configuration
// verified at startup (#153 §5.3), never from the store.
type Context struct {
	NetworkID         types.NetworkID
	PartitionID       types.PartitionID
	ShardID           types.ShardID
	FullShardConfHash []byte
	Registry          registryproof.Context
	TrustBases        TrustBases
	EpochAuthority    interface{ CurrentRootEpoch() (uint64, bool) }
}

func (c Context) check() error {
	if len(c.FullShardConfHash) != gocrypto.SHA256.Size() {
		return fmt.Errorf("%w: shard configuration hash is %d bytes", ErrConfig, len(c.FullShardConfHash))
	}
	if c.TrustBases == nil {
		return fmt.Errorf("%w: no trust base store", ErrConfig)
	}
	return nil
}

// Record is a certified-block record as a caller supplies it for publication.
type Record struct {
	BlockHash      common.Hash
	BlockNumber    uint64
	StateRoot      common.Hash
	PartitionRound uint64
	Certificate    *types.UnicityCertificate
	Technical      *certification.TechnicalRecord
	Witness        registryproof.Evidence
}

type storedContext struct {
	_                 struct{} `cbor:",toarray"`
	NetworkID         uint64
	PartitionID       uint64
	ShardID           []byte
	FullShardConfHash []byte
	RegistryCodeHash  []byte
	GenesisCommitment []byte
	EVMGenesisHash    []byte
	ShardEpoch        uint64
	RootEpoch         uint64
}

func contextOf(c Context) storedContext {
	return storedContext{
		NetworkID: uint64(c.NetworkID), PartitionID: uint64(c.PartitionID), ShardID: c.ShardID.Bytes(),
		FullShardConfHash: bytes.Clone(c.FullShardConfHash), RegistryCodeHash: c.Registry.RegistryCodeHash.Bytes(),
		GenesisCommitment: c.Registry.GenesisCommitment.Bytes(), EVMGenesisHash: c.Registry.EVMGenesisHash.Bytes(),
		ShardEpoch: c.Registry.ShardEpoch, RootEpoch: c.Registry.RootEpoch,
	}
}

// storedRecord is the encoded record. It has no field for signing state: the signing record lives in the
// signing authority's memory (ADR 0009) and is never read from or written to this store.
type storedRecord struct {
	_              struct{} `cbor:",toarray"`
	Version        uint32
	Context        storedContext
	BlockHash      []byte
	BlockNumber    uint64
	StateRoot      []byte
	PartitionRound uint64
	Certificate    []byte // canonical CBOR of types.UnicityCertificate
	Technical      []byte // canonical CBOR of certification.TechnicalRecord
	WitnessHeader  []byte
	WitnessAccount [][]byte
	WitnessStorage [][][]byte
}

type envelope struct {
	_       struct{} `cbor:",toarray"`
	Version uint32
	Payload []byte
	Digest  []byte
}

func encodeRecord(c Context, r Record) ([]byte, storedRecord, error) {
	if r.Certificate == nil || r.Technical == nil {
		return nil, storedRecord{}, fmt.Errorf("%w: record has no certificate or technical record", ErrWrongBlock)
	}
	uc, err := types.Cbor.Marshal(r.Certificate)
	if err != nil {
		return nil, storedRecord{}, fmt.Errorf("encoding certificate: %w", err)
	}
	tr, err := types.Cbor.Marshal(r.Technical)
	if err != nil {
		return nil, storedRecord{}, fmt.Errorf("encoding technical record: %w", err)
	}
	sr := storedRecord{
		Version: RecordVersion, Context: contextOf(c), BlockHash: r.BlockHash.Bytes(), BlockNumber: r.BlockNumber,
		StateRoot: r.StateRoot.Bytes(), PartitionRound: r.PartitionRound, Certificate: uc, Technical: tr,
		WitnessHeader: bytes.Clone(r.Witness.Header), WitnessAccount: cloneNodes(r.Witness.AccountProof),
		WitnessStorage: cloneProofs(r.Witness.StorageProofs),
	}
	payload, err := types.Cbor.Marshal(sr)
	if err != nil {
		return nil, storedRecord{}, err
	}
	sum := sha256.Sum256(payload)
	out, err := types.Cbor.Marshal(envelope{Version: RecordVersion, Payload: payload, Digest: sum[:]})
	if err != nil {
		return nil, storedRecord{}, err
	}
	if len(out) > MaxRecordBytes {
		return nil, storedRecord{}, fmt.Errorf("%w: record encodes to %d bytes, bound %d", ErrRecordUntrusted, len(out), MaxRecordBytes)
	}
	return out, sr, nil
}

func decodeRecord(raw []byte) (storedRecord, error) {
	if len(raw) > MaxRecordBytes {
		return storedRecord{}, fmt.Errorf("%w: %d bytes exceeds %d", ErrRecordUntrusted, len(raw), MaxRecordBytes)
	}
	var env envelope
	if err := types.Cbor.Unmarshal(raw, &env); err != nil {
		return storedRecord{}, fmt.Errorf("%w: envelope: %v", ErrRecordUntrusted, err)
	}
	if env.Version != RecordVersion {
		return storedRecord{}, fmt.Errorf("%w: %d", ErrRecordVersion, env.Version)
	}
	sum := sha256.Sum256(env.Payload)
	if !bytes.Equal(sum[:], env.Digest) {
		return storedRecord{}, fmt.Errorf("%w: digest mismatch", ErrRecordUntrusted)
	}
	var sr storedRecord
	if err := types.Cbor.Unmarshal(env.Payload, &sr); err != nil {
		return storedRecord{}, fmt.Errorf("%w: payload: %v", ErrRecordUntrusted, err)
	}
	if sr.Version != env.Version {
		return storedRecord{}, fmt.Errorf("%w: payload version %d in envelope %d", ErrRecordUntrusted, sr.Version, env.Version)
	}
	return sr, nil
}

// Loaded is a verified record. It is opaque; accessors return copies.
type Loaded struct {
	record   storedRecord
	snapshot registryproof.Snapshot
}

// BlockHash is the recorded block's hash.
func (l Loaded) BlockHash() common.Hash { return common.BytesToHash(l.record.BlockHash) }

// BlockNumber is the recorded block's number.
func (l Loaded) BlockNumber() uint64 { return l.record.BlockNumber }

// StateRoot is the recorded block's state root.
func (l Loaded) StateRoot() common.Hash { return common.BytesToHash(l.record.StateRoot) }

// PartitionRound is the partition round the certificate certified.
func (l Loaded) PartitionRound() uint64 { return l.record.PartitionRound }

// Snapshot is the verified registry snapshot proven by witness(B).
func (l Loaded) Snapshot() registryproof.Snapshot { return l.snapshot }

// Certificate returns a newly decoded copy of the recorded certificate.
func (l Loaded) Certificate() (*types.UnicityCertificate, error) {
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(l.record.Certificate, &uc); err != nil {
		return nil, err
	}
	return &uc, nil
}

// Technical returns a newly decoded copy of the recorded technical record.
func (l Loaded) Technical() (*certification.TechnicalRecord, error) {
	var tr certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(l.record.Technical, &tr); err != nil {
		return nil, err
	}
	return &tr, nil
}

// Witness returns a copy of witness(B).
func (l Loaded) Witness() registryproof.Evidence { return evidenceOf(l.record) }

func evidenceOf(sr storedRecord) registryproof.Evidence {
	return registryproof.Evidence{Header: bytes.Clone(sr.WitnessHeader), AccountProof: cloneNodes(sr.WitnessAccount), StorageProofs: cloneProofs(sr.WitnessStorage)}
}

/*
verify re-verifies a decoded record in the order of the contract's §6: version; context against
configuration; certificate context, authentication against the configured trust base, and the block rule
for an ordinary or the configuration-bound genesis record; the technical record's binding; witness(B)
through registryproof.Verify with its provenance.
*/
func verify(ctx context.Context, c Context, sr storedRecord) (Loaded, error) {
	if err := c.check(); err != nil {
		return Loaded{}, err
	}
	if sr.Version != RecordVersion {
		return Loaded{}, fmt.Errorf("%w: %d", ErrRecordVersion, sr.Version)
	}
	want, err := types.Cbor.Marshal(contextOf(c))
	if err != nil {
		return Loaded{}, err
	}
	got, err := types.Cbor.Marshal(sr.Context)
	if err != nil || !bytes.Equal(want, got) {
		return Loaded{}, ErrWrongContext
	}
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(sr.Certificate, &uc); err != nil || uc.InputRecord == nil {
		return Loaded{}, fmt.Errorf("%w: certificate does not decode", ErrRecordUntrusted)
	}
	var tr certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(sr.Technical, &tr); err != nil {
		return Loaded{}, fmt.Errorf("%w: technical record does not decode", ErrRecordUntrusted)
	}
	// Context before authentication, so another chain and a forgery are distinct refusals (#92 §3).
	if uc.GetPartitionID() != c.PartitionID || !uc.GetShardID().Equal(c.ShardID) || !bytes.Equal(uc.ShardConfHash, c.FullShardConfHash) {
		return Loaded{}, fmt.Errorf("%w: certificate", ErrWrongContext)
	}
	tb, err := c.TrustBases.GetByEpoch(ctx, uc.GetRootEpoch())
	if err != nil {
		return Loaded{}, fmt.Errorf("%w: root epoch %d: %v", ErrCertificate, uc.GetRootEpoch(), err)
	}
	if err := uc.Verify(tb, gocrypto.SHA256, c.PartitionID, c.ShardID, c.FullShardConfHash); err != nil {
		return Loaded{}, fmt.Errorf("%w: %v", ErrCertificate, err)
	}
	trHash, err := tr.Hash()
	if err != nil || !bytes.Equal(trHash, uc.TRHash) {
		return Loaded{}, ErrTechnicalRecord
	}
	// UC.Verify authenticates the statement; it does not show the statement is for this deployment's single
	// shard epoch and root epoch (#153 O8). These come after authentication, so an authenticated certificate
	// for an unsupported epoch and a forgery are distinct refusals.
	current := c.Registry.RootEpoch
	if c.EpochAuthority != nil {
		var ready bool
		current, ready = c.EpochAuthority.CurrentRootEpoch()
		if !ready || current < c.Registry.RootEpoch {
			return Loaded{}, ErrEpoch
		}
	}
	if got := uc.GetRootEpoch(); got < c.Registry.RootEpoch || got > current {
		return Loaded{}, fmt.Errorf("%w: root epoch %d outside verified history %d..%d", ErrEpoch, got, c.Registry.RootEpoch, current)
	}
	if got := uc.InputRecord.Epoch; got != c.Registry.ShardEpoch {
		return Loaded{}, fmt.Errorf("%w: input record epoch %d, configured shard epoch %d", ErrEpoch, got, c.Registry.ShardEpoch)
	}
	if tr.Epoch != c.Registry.ShardEpoch {
		return Loaded{}, fmt.Errorf("%w: technical record epoch %d, configured shard epoch %d", ErrEpoch, tr.Epoch, c.Registry.ShardEpoch)
	}
	if len(sr.BlockHash) != common.HashLength || len(sr.StateRoot) != common.HashLength {
		return Loaded{}, fmt.Errorf("%w: block hash or state root has the wrong width", ErrWrongBlock)
	}
	ir := uc.InputRecord
	if sr.BlockNumber == 0 {
		// The configuration-bound genesis record: the configured EVM genesis, and a certificate that is
		// genesis history (#153 §7.3 E2), naming no block, at the genesis state.
		if !bytes.Equal(sr.BlockHash, c.Registry.EVMGenesisHash.Bytes()) {
			return Loaded{}, fmt.Errorf("%w: a block-0 record names %x, the configured EVM genesis is %s", ErrWrongBlock, sr.BlockHash, c.Registry.EVMGenesisHash)
		}
		if len(ir.BlockHash) != 0 || ir.RoundNumber != sr.PartitionRound || !bytes.Equal(ir.Hash, sr.StateRoot) || !bytes.Equal(ir.PreviousHash, sr.StateRoot) {
			return Loaded{}, fmt.Errorf("%w: the genesis certificate is not genesis history at the genesis state", ErrWrongBlock)
		}
	} else if len(ir.BlockHash) == 0 || !bytes.Equal(ir.BlockHash, sr.BlockHash) || !bytes.Equal(ir.Hash, sr.StateRoot) || ir.RoundNumber != sr.PartitionRound {
		return Loaded{}, fmt.Errorf("%w: certificate names round %d block %x", ErrWrongBlock, ir.RoundNumber, ir.BlockHash)
	}
	s, err := registryproof.Verify(c.Registry, common.BytesToHash(sr.BlockHash), evidenceOf(sr))
	if err != nil {
		return Loaded{}, fmt.Errorf("%w: %w", ErrWitness, err)
	}
	if s.Number() != sr.BlockNumber || s.StateRoot() != common.BytesToHash(sr.StateRoot) {
		return Loaded{}, fmt.Errorf("%w: witness proves block %d state %s", ErrWrongBlock, s.Number(), s.StateRoot())
	}
	// An ordinary record's certified round is the round B executed: the proof reader has bound the
	// finalized outcomes to RoundAuthorized. The genesis record is exempt, because quiet genesis history
	// advances its certificate round without executing a block (#153 §7.3 E2).
	if sr.BlockNumber != 0 {
		if executed := s.Fields().RoundAuthorized; executed != sr.PartitionRound {
			return Loaded{}, fmt.Errorf("%w: certified round %d, witness executed round %d", ErrWrongRound, sr.PartitionRound, executed)
		}
	}
	return Loaded{record: sr, snapshot: s}, nil
}

func cloneNodes(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = bytes.Clone(n)
	}
	return out
}

func cloneProofs(in [][][]byte) [][][]byte {
	if in == nil {
		return nil
	}
	out := make([][][]byte, len(in))
	for i, p := range in {
		out[i] = cloneNodes(p)
	}
	return out
}
