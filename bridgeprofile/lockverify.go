package bridgeprofile

import (
	"bytes"
	"fmt"
	"math"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
)

// DeploymentPin is the immutable per-deployment expectation the embedded
// evidence is checked against: the pinned EVM shard configuration (genesis
// section) and the vault runtime code hash.
type DeploymentPin struct {
	Genesis       *types.PartitionDescriptionRecord
	VaultCodeHash [32]byte
}

// VerifyMintBacking fully verifies, offline, the lock justification of a
// projected mint: it parses J under cfg, reconstructs the lock digest from the
// actual mint (nonce, amount, token ID, recipient) and verifies the embedded
// proof against the supplied trust base and deployment. No network, node or URL is
// read; a missing or unknown proof is a rejection, never a fetch.
func VerifyMintBacking(cfg *Cfg, h *History, tr *TrustInput, pin *DeploymentPin) error {
	n, lp, err := ParseJustification(cfg, h.Mint.Justification)
	if err != nil {
		return err
	}
	amount, err := parseMintData(cfg, h.Mint.Data)
	if err != nil {
		return err
	}
	ch := cfg.Hash()
	salt := DeriveSalt(ch, n)
	if h.Mint.Salt != salt {
		return ErrMintSalt
	}
	id := DeriveTokenID(salt, cfg.Network)
	d := LockDigest(ch, n, LockRecord(cfg.ZeroAddress, cfg.Ty, cfg.Aid, amount, id, H(h.Mint.Recipient.Bytes())))
	return VerifyLockProof(lp, cfg, n, d, tr, pin)
}

// VerifyLockProof verifies the embedded proof for the lock digest want of
// nonce n. Order: the caller's trust base must be the one the proof names;
// network, root epoch, the SDK's UC verification (signatures, quorum, folds); the carried PDR against
// the certificate's configuration commitment and the pinned deployment; the
// header against the certified input record; the vault account and its code
// hash under the header state root; the lock word under the storage root.
func VerifyLockProof(p *LockProof, cfg *Cfg, n uint64, want [32]byte, tr *TrustInput, pin *DeploymentPin) error {
	if p == nil || pin == nil || pin.Genesis == nil {
		return ErrLockPDR
	}
	if p.Cfg != cfg.Hash() {
		return ErrLockProofCfg
	}
	if tr == nil || tr.Base == nil {
		return ErrTrustBaseDigest
	}
	if tr.Base.GetNetworkID() != types.NetworkID(cfg.Network) {
		return ErrEpochMismatch
	}
	tb := tr.Base
	var uc types.UnicityCertificate
	if err := types.Cbor.Unmarshal(p.UC, &uc); err != nil {
		return fmt.Errorf("%w: decode: %v", ErrLockUC, err)
	}
	canonical, err := types.Cbor.Marshal(&uc)
	if err != nil || !bytes.Equal(canonical, p.UC) || uc.InputRecord == nil || uc.UnicitySeal == nil {
		return fmt.Errorf("%w: noncanonical or incomplete", ErrLockUC)
	}
	if err := checkFixedProfile(p, tr, &uc); err != nil {
		return err
	}
	pdr, pdrHash, err := verifyLockPDR(p, cfg, &uc, pin)
	if err != nil {
		return err
	}
	var shard types.ShardID
	if err := shard.UnmarshalText([]byte("0x" + fmt.Sprintf("%x", cfg.EVMShard))); err != nil || !bytes.Equal(shard.Bytes(), cfg.EVMShard) {
		return ErrLockPDR
	}
	if err := verifyNativeUC(tb, &uc, types.PartitionID(cfg.EVMPartition), shard, pdrHash[:]); err != nil {
		return fmt.Errorf("%w: %v", ErrLockUC, err)
	}
	if err := weightvalidation.EVMSet(pdr.Validators, weightvalidation.ModeOfTrustBase(tb)); err != nil {
		return fmt.Errorf("%w: validators: %v", ErrLockPDR, err)
	}
	header, err := bindHeader(p, &uc)
	if err != nil {
		return err
	}
	acct, err := mptVerify(header.Root, AccountTrieKey(cfg.Vault), p.AccountNodes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLockAccount, err)
	}
	root, codeHash, err := decodeAccount(acct)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLockAccount, err)
	}
	if codeHash != pin.VaultCodeHash {
		return ErrLockCodeHash
	}
	val, err := mptVerify(root, StorageTrieKey(LockDigestSlot(n)), p.StorageNodes)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLockStorage, err)
	}
	got, err := StorageValueFromRLP(val)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrLockStorage, err)
	}
	if got == ([32]byte{}) || got != want {
		return ErrLockDigest
	}
	return nil
}

// verifyLockPDR checks the carried PDR: canonical, hashes to the
// certificate's configuration commitment, names the deployment's network,
// partition and shard, changes no non-membership setting of the pinned
// genesis configuration, and is the assignment of the certified epoch.
func verifyLockPDR(p *LockProof, cfg *Cfg, uc *types.UnicityCertificate, pin *DeploymentPin) (*types.PartitionDescriptionRecord, [32]byte, error) {
	var pdr types.PartitionDescriptionRecord
	if err := types.Cbor.Unmarshal(p.PDR, &pdr); err != nil {
		return nil, [32]byte{}, fmt.Errorf("%w: decode: %v", ErrLockPDR, err)
	}
	if again, err := types.Cbor.Marshal(&pdr); err != nil || !bytes.Equal(again, p.PDR) {
		return nil, [32]byte{}, fmt.Errorf("%w: noncanonical", ErrLockPDR)
	}
	hash, err := evmassign.PDRHash(&pdr)
	if err != nil || !bytes.Equal(hash[:], uc.ShardConfHash) {
		return nil, [32]byte{}, fmt.Errorf("%w: does not hash to the certificate's configuration", ErrLockPDR)
	}
	if uint16(pdr.NetworkID) != cfg.Network || uint32(pdr.PartitionID) != cfg.EVMPartition || !bytes.Equal(pdr.ShardID.Bytes(), cfg.EVMShard) {
		return nil, [32]byte{}, fmt.Errorf("%w: names another network, partition or shard", ErrLockPDR)
	}
	g := pin.Genesis
	if g.NetworkID != pdr.NetworkID || g.PartitionID != pdr.PartitionID || !g.ShardID.Equal(pdr.ShardID) {
		return nil, [32]byte{}, fmt.Errorf("%w: not of the pinned deployment", ErrLockPDR)
	}
	want, err1 := evmassign.ConfigHash(g)
	got, err2 := evmassign.ConfigHash(&pdr)
	if err1 != nil || err2 != nil || want != got {
		return nil, [32]byte{}, fmt.Errorf("%w: changes a non-membership setting of the genesis pin", ErrLockPDR)
	}
	if uc.InputRecord.Epoch != pdr.Epoch {
		return nil, [32]byte{}, fmt.Errorf("%w: certified shard epoch %d, configuration epoch %d", ErrLockPDR, uc.InputRecord.Epoch, pdr.Epoch)
	}
	return &pdr, hash, nil
}

// bindHeader requires keccak256(headerRLP) == InputRecord.blockHash and
// header.stateRoot == InputRecord.hash, with the pinned native execution
// profile's header encoding: a signature over an unrelated state root is not
// enough.
func bindHeader(p *LockProof, uc *types.UnicityCertificate) (*gethtypes.Header, error) {
	ir := uc.InputRecord
	if len(ir.BlockHash) != 32 || len(ir.Hash) != 32 {
		return nil, ErrLockHeader
	}
	var header gethtypes.Header
	if err := rlp.DecodeBytes(p.Header, &header); err != nil || header.Number == nil || !header.Number.IsUint64() {
		return nil, ErrLockHeader
	}
	if again, err := rlp.EncodeToBytes(&header); err != nil || !bytes.Equal(again, p.Header) {
		return nil, ErrLockHeader
	}
	if !bytes.Equal(gethcrypto.Keccak256(p.Header), ir.BlockHash) || !bytes.Equal(header.Root[:], ir.Hash) {
		return nil, ErrLockHeader
	}
	if header.Number.Uint64() > math.MaxInt64 || header.UncleHash != gethtypes.EmptyUncleHash || header.Difficulty == nil || header.Difficulty.Sign() != 0 ||
		header.BaseFee == nil || header.BaseFee.Sign() <= 0 || !header.BaseFee.IsUint64() || header.WithdrawalsHash == nil || *header.WithdrawalsHash != gethtypes.EmptyWithdrawalsHash ||
		header.BlobGasUsed == nil || *header.BlobGasUsed != 0 || header.ExcessBlobGas == nil || *header.ExcessBlobGas != 0 || header.ParentBeaconRoot == nil || len(header.Extra) > 32 {
		return nil, ErrLockHeader
	}
	return &header, nil
}

// decodeAccount reads the canonical account RLP [nonce,balance,storageRoot,codeHash].
func decodeAccount(b []byte) (storageRoot, codeHash [32]byte, err error) {
	it, derr := rlpDecode(b)
	if derr != nil || !it.list || len(it.kids) != 4 {
		return storageRoot, codeHash, ErrMPTNode
	}
	for i := 0; i < 2; i++ {
		if _, ok := it.kids[i].uintBytes(); !ok {
			return storageRoot, codeHash, ErrMPTNode
		}
	}
	if it.kids[2].list || len(it.kids[2].str) != 32 || it.kids[3].list || len(it.kids[3].str) != 32 {
		return storageRoot, codeHash, ErrMPTNode
	}
	copy(storageRoot[:], it.kids[2].str)
	copy(codeHash[:], it.kids[3].str)
	return storageRoot, codeHash, nil
}
