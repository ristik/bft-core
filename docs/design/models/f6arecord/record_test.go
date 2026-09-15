package f6arecord

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

/*
The certified-block record: one record per certified EVM block B, written in ONE transaction together with
the head pointer that names it, and holding everything a node needs to be ready for B's child after a
restart: the authenticated context, B's identity, the certificate and technical record that certify B, and
witness(B).

The certificate and technical record are modelled by their binding fields. In the implementation they are
the CBOR bytes of types.UnicityCertificate and certification.TechnicalRecord, authenticated on reload by
the same verifyRestoredLUC path the node uses today (UC.Verify against the configured trust base, partition,
shard and shard configuration hash, and TRHash against the technical record). The model's authenticate
function stands in for that verification; it is not a model of signature checking.
*/

const recordVersion uint32 = 1

// maxRecordBytes bounds a stored record before it is decoded: a certificate and technical record well under
// 64 KiB, and witness(B) within registryproof's 256 KiB node bound.
const maxRecordBytes = 1 << 20

// recordContext is the authenticated context a record is valid in. Every field comes from the node's
// configuration, verified at startup (#153 §5.3), never from the record itself.
type recordContext struct {
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

func contextFor(d *deployment, network, partition uint64, shard []byte) recordContext {
	c := d.ctx
	return recordContext{
		NetworkID: network, PartitionID: partition, ShardID: bytes.Clone(shard),
		FullShardConfHash: c.FullShardConfHash.Bytes(), RegistryCodeHash: c.RegistryCodeHash.Bytes(),
		GenesisCommitment: c.GenesisCommitment.Bytes(), EVMGenesisHash: c.EVMGenesisHash.Bytes(),
		ShardEpoch: c.ShardEpoch, RootEpoch: c.RootEpoch,
	}
}

func (c recordContext) equal(o recordContext) bool {
	a, errA := bfttypes.Cbor.Marshal(c)
	b, errB := bfttypes.Cbor.Marshal(o)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

// certificate carries the binding fields of a unicity certificate for one partition round.
type certificate struct {
	_              struct{} `cbor:",toarray"`
	NetworkID      uint64
	PartitionID    uint64
	ShardID        []byte
	ShardConfHash  []byte
	PartitionRound uint64
	PreviousHash   []byte // IR.h' , the state before the round
	StateHash      []byte // IR.h, the certified state; the EVM state root on this branch
	BlockHash      []byte // IR.h_b; nil for a quiet round
	TRHash         []byte // commits to the technical record
	RootRound      uint64
	Epoch          uint64 // IR epoch, the shard configuration epoch
	Timestamp      uint64 // IR timestamp
}

// inputRecordIdentity models InputRecord.Bytes(): every input-record field and nothing outside it. The root
// round, the technical record and the signatures are not part of it, so an honest repeat of a round has
// the same identity (#92 design, f6b-quiet-tail-anchor-recovery.md §2.2).
func (c certificate) inputRecordIdentity() []byte {
	b, _ := bfttypes.Cbor.Marshal([]any{c.PartitionRound, c.Epoch, c.PreviousHash, c.StateHash, c.BlockHash, c.Timestamp})
	return b
}

func (c certificate) digest() [32]byte {
	b, _ := bfttypes.Cbor.Marshal(c)
	return sha256.Sum256(b)
}

// technicalRecord carries the fields of certification.TechnicalRecord this contract reads.
type technicalRecord struct {
	_     struct{} `cbor:",toarray"`
	Round uint64   // the partition round assigned next
	Epoch uint64
}

func (tr technicalRecord) digest() []byte {
	b, _ := bfttypes.Cbor.Marshal(tr)
	sum := sha256.Sum256(b)
	return sum[:]
}

// certifiedRecord is the stored record. It has no field for signing state: the signing record lives in
// the authority's memory for the life of its key (ADR 0009) and is never read from, or written to, this
// store (TestTheRecordHoldsNoSigningState).
type certifiedRecord struct {
	_              struct{} `cbor:",toarray"`
	Version        uint32
	Context        recordContext
	BlockHash      []byte
	BlockNumber    uint64
	StateRoot      []byte
	PartitionRound uint64
	Certificate    certificate
	Technical      technicalRecord
	WitnessHeader  []byte
	WitnessAccount [][]byte
	WitnessStorage [][][]byte
}

// envelope is what is written under a record key: the encoded record and its SHA-256. A digest mismatch is
// damage the backend did not detect.
type envelope struct {
	_       struct{} `cbor:",toarray"`
	Version uint32
	Payload []byte
	Digest  []byte
}

var (
	errNoRecord         = errors.New("record: no durable record")
	errRecordUntrusted  = errors.New("record: stored record is damaged or unreadable")
	errRecordVersion    = errors.New("record: unsupported record version")
	errWrongContext     = errors.New("record: record or certificate is for another context")
	errCertificate      = errors.New("record: certificate does not authenticate")
	errWrongBlock       = errors.New("record: record, certificate and witness do not name the same block")
	errTechnicalRecord  = errors.New("record: technical record is not the one the certificate commits to")
	errWitness          = errors.New("record: witness does not verify")
	errExecutorBehind   = errors.New("readiness: the executor is behind the durable record")
	errExecutorAhead    = errors.New("readiness: the executor is ahead of the durable record")
	errExecutorDiverged = errors.New("readiness: the executor is on another block at the record's height")
	errStale            = errors.New("readiness: the live certificate is not for the recorded block")
	errNoWitness        = errors.New("pipeline: no verified witness to persist")
)

// envelopeFor wraps an arbitrary payload with a correct digest, as a record written by another version
// of this contract would be.
func envelopeFor(version uint32, payload []byte) ([]byte, error) {
	sum := sha256.Sum256(payload)
	return bfttypes.Cbor.Marshal(envelope{Version: version, Payload: payload, Digest: sum[:]})
}

func encodeRecord(r certifiedRecord) ([]byte, error) {
	payload, err := bfttypes.Cbor.Marshal(r)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(payload)
	out, err := bfttypes.Cbor.Marshal(envelope{Version: recordVersion, Payload: payload, Digest: sum[:]})
	if err != nil {
		return nil, err
	}
	if len(out) > maxRecordBytes {
		return nil, fmt.Errorf("record is %d bytes, bound %d", len(out), maxRecordBytes)
	}
	return out, nil
}

func decodeRecord(raw []byte) (certifiedRecord, error) {
	if len(raw) > maxRecordBytes {
		return certifiedRecord{}, fmt.Errorf("%w: %d bytes exceeds %d", errRecordUntrusted, len(raw), maxRecordBytes)
	}
	var env envelope
	if err := bfttypes.Cbor.Unmarshal(raw, &env); err != nil {
		return certifiedRecord{}, fmt.Errorf("%w: envelope: %v", errRecordUntrusted, err)
	}
	if env.Version != recordVersion {
		return certifiedRecord{}, fmt.Errorf("%w: %d", errRecordVersion, env.Version)
	}
	sum := sha256.Sum256(env.Payload)
	if !bytes.Equal(sum[:], env.Digest) {
		return certifiedRecord{}, fmt.Errorf("%w: digest mismatch", errRecordUntrusted)
	}
	var r certifiedRecord
	if err := bfttypes.Cbor.Unmarshal(env.Payload, &r); err != nil {
		return certifiedRecord{}, fmt.Errorf("%w: payload: %v", errRecordUntrusted, err)
	}
	if r.Version != env.Version {
		return certifiedRecord{}, fmt.Errorf("%w: payload version %d in envelope %d", errRecordUntrusted, r.Version, env.Version)
	}
	return r, nil
}

// config is what the node brings to a reload: nothing in it comes from the store.
type config struct {
	context      recordContext
	proofContext registryproof.Context
	authenticate func(certificate) error
}

func (r certifiedRecord) evidence() registryproof.Evidence {
	return registryproof.Evidence{Header: r.WitnessHeader, AccountProof: r.WitnessAccount, StorageProofs: r.WitnessStorage}
}

/*
verifyRecord re-verifies a decoded record completely, in the order a reload must: version, context against
configuration, certificate authentication and context, the certificate's block identity against the
record, the technical record against the certificate's commitment, and witness(B) through
registryproof.Verify with its provenance against the record. Nothing is taken from the record without
being checked against configuration or authenticated evidence.
*/
func verifyRecord(cfg config, r certifiedRecord) (registryproof.Snapshot, error) {
	if r.Version != recordVersion {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %d", errRecordVersion, r.Version)
	}
	if !r.Context.equal(cfg.context) {
		return registryproof.Snapshot{}, errWrongContext
	}
	if err := cfg.authenticate(r.Certificate); err != nil {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %v", errCertificate, err)
	}
	c := r.Certificate
	if c.NetworkID != cfg.context.NetworkID || c.PartitionID != cfg.context.PartitionID ||
		!bytes.Equal(c.ShardID, cfg.context.ShardID) || !bytes.Equal(c.ShardConfHash, cfg.context.FullShardConfHash) {
		return registryproof.Snapshot{}, fmt.Errorf("%w: certificate", errWrongContext)
	}
	if r.BlockNumber == 0 {
		// The configuration-bound genesis record. Its block identity is the configured EVM genesis, proven by
		// the genesis witness below, and its certificate is genesis history (#153 §7.3 E2): it names no block,
		// and its state and previous state are the genesis state.
		if !bytes.Equal(r.BlockHash, cfg.proofContext.EVMGenesisHash.Bytes()) {
			return registryproof.Snapshot{}, fmt.Errorf("%w: a block-0 record names %x, the configured EVM genesis is %s", errWrongBlock, r.BlockHash, cfg.proofContext.EVMGenesisHash)
		}
		if len(c.BlockHash) != 0 || c.PartitionRound != r.PartitionRound || !bytes.Equal(c.StateHash, r.StateRoot) || !bytes.Equal(c.PreviousHash, r.StateRoot) {
			return registryproof.Snapshot{}, fmt.Errorf("%w: the genesis certificate is not genesis history at the genesis state", errWrongBlock)
		}
	} else if len(c.BlockHash) == 0 || !bytes.Equal(c.BlockHash, r.BlockHash) || !bytes.Equal(c.StateHash, r.StateRoot) || c.PartitionRound != r.PartitionRound {
		return registryproof.Snapshot{}, fmt.Errorf("%w: certificate names round %d block %x", errWrongBlock, c.PartitionRound, c.BlockHash)
	}
	if !bytes.Equal(r.Technical.digest(), c.TRHash) {
		return registryproof.Snapshot{}, errTechnicalRecord
	}
	if len(r.BlockHash) != common.HashLength {
		return registryproof.Snapshot{}, fmt.Errorf("%w: block hash is %d bytes", errWrongBlock, len(r.BlockHash))
	}
	s, err := registryproof.Verify(cfg.proofContext, common.BytesToHash(r.BlockHash), r.evidence())
	if err != nil {
		return registryproof.Snapshot{}, fmt.Errorf("%w: %w", errWitness, err)
	}
	if s.Number() != r.BlockNumber || !bytes.Equal(s.StateRoot().Bytes(), r.StateRoot) {
		return registryproof.Snapshot{}, fmt.Errorf("%w: witness proves block %d state %s", errWrongBlock, s.Number(), s.StateRoot())
	}
	return s, nil
}
