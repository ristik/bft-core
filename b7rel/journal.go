package b7rel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// JournalDomain opens every journal.
var JournalDomain = [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.b7.journal.v1")))

// ErrJournal is any journal that is not the canonical encoding of a valid Journal.
var ErrJournal = errors.New("b7rel: malformed journal")

// Release is the kernel result a direct redemption hands the vault, without its per-leaf list: the vault's consumption routine
// is shared by the direct and the succinct path, so the journal carries exactly these fields.
type Release struct {
	Cfg                [32]byte
	Nonce              *big.Int // uint256
	Amount             *big.Int // uint256
	TokenID            [32]byte
	Salt               [32]byte
	FirstPredicateHash [32]byte
	LockDigest         [32]byte
	ReleaseTo          [20]byte
	Nullifier          [32]byte
}

// EpochUse is one root epoch the proven history uses: its cached commitment and the lowest and highest root round of the
// certificates verified under it.
type EpochUse struct {
	Epoch      uint64
	Commitment [32]byte
	MinRound   uint64
	MaxRound   uint64
}

// Journal is the public output of a B7 proof.
type Journal struct {
	RelationID        [32]byte
	ChainID           *big.Int // uint256
	GenesisCommitment [32]byte // the registry's genesisCommitment
	ProfileHash       [32]byte // the registry's b1.profileHash
	WitnessCommitment [32]byte
	Release           Release
	Epochs            []EpochUse // 1..MaxEpochs, strictly ascending by epoch
}

const (
	headerWords   = 16 // domain, relation, chain, genesis, profile, witness, 9 release words, epoch count
	epochUseWords = 4
)

// Encode is the canonical journal: 32-byte big-endian words, the header then four words per epoch use, nothing else. It refuses
// what Decode would refuse.
func (j Journal) Encode() ([]byte, error) {
	out := make([]byte, 0, 32*(headerWords+epochUseWords*len(j.Epochs)))
	put := func(w [32]byte) { out = append(out, w[:]...) }
	u256 := func(v *big.Int) ([32]byte, error) {
		var w [32]byte
		if v == nil || v.Sign() < 0 || v.BitLen() > 256 {
			return w, ErrJournal
		}
		v.FillBytes(w[:])
		return w, nil
	}
	chain, err := u256(j.ChainID)
	if err != nil {
		return nil, err
	}
	nonce, err := u256(j.Release.Nonce)
	if err != nil {
		return nil, err
	}
	amount, err := u256(j.Release.Amount)
	if err != nil {
		return nil, err
	}
	var to [32]byte
	copy(to[12:], j.Release.ReleaseTo[:])
	for _, w := range [][32]byte{JournalDomain, j.RelationID, chain, j.GenesisCommitment, j.ProfileHash, j.WitnessCommitment,
		j.Release.Cfg, nonce, amount, j.Release.TokenID, j.Release.Salt, j.Release.FirstPredicateHash, j.Release.LockDigest, to,
		j.Release.Nullifier, word(uint64(len(j.Epochs)))} {
		put(w)
	}
	for _, e := range j.Epochs {
		put(word(e.Epoch))
		put(e.Commitment)
		put(word(e.MinRound))
		put(word(e.MaxRound))
	}
	if _, err := Decode(out); err != nil {
		return nil, err
	}
	return out, nil
}

func u64(w []byte) (uint64, bool) {
	for _, b := range w[:24] {
		if b != 0 {
			return 0, false
		}
	}
	return binary.BigEndian.Uint64(w[24:]), true
}

// Decode accepts exactly the canonical encoding: the domain word, an epoch count in 1..MaxEpochs that matches the length, no
// trailing bytes, uint64 fields and the address with zero high bytes, epochs strictly ascending and minRound <= maxRound.
func Decode(b []byte) (Journal, error) {
	var j Journal
	if len(b) < 32*headerWords || len(b)%32 != 0 {
		return j, fmt.Errorf("%w: length %d", ErrJournal, len(b))
	}
	w := func(i int) []byte { return b[32*i : 32*i+32] }
	if [32]byte(w(0)) != JournalDomain {
		return j, fmt.Errorf("%w: domain", ErrJournal)
	}
	n, ok := u64(w(15))
	if !ok || n == 0 || n > MaxEpochs {
		return j, fmt.Errorf("%w: epoch count", ErrJournal)
	}
	if uint64(len(b)) != 32*(headerWords+epochUseWords*n) {
		return j, fmt.Errorf("%w: length %d for %d epochs", ErrJournal, len(b), n)
	}
	for _, c := range w(13)[:12] {
		if c != 0 {
			return j, fmt.Errorf("%w: releaseTo is not an address", ErrJournal)
		}
	}
	j.RelationID, j.ChainID = [32]byte(w(1)), new(big.Int).SetBytes(w(2))
	j.GenesisCommitment, j.ProfileHash, j.WitnessCommitment = [32]byte(w(3)), [32]byte(w(4)), [32]byte(w(5))
	j.Release = Release{Cfg: [32]byte(w(6)), Nonce: new(big.Int).SetBytes(w(7)), Amount: new(big.Int).SetBytes(w(8)), TokenID: [32]byte(w(9)),
		Salt: [32]byte(w(10)), FirstPredicateHash: [32]byte(w(11)), LockDigest: [32]byte(w(12)), ReleaseTo: [20]byte(w(13)[12:]),
		Nullifier: [32]byte(w(14))}
	for i := uint64(0); i < n; i++ {
		base := headerWords + int(i)*epochUseWords
		epoch, ok1 := u64(w(base))
		minR, ok2 := u64(w(base + 2))
		maxR, ok3 := u64(w(base + 3))
		if !ok1 || !ok2 || !ok3 {
			return Journal{}, fmt.Errorf("%w: epoch use %d is not uint64", ErrJournal, i)
		}
		if minR > maxR {
			return Journal{}, fmt.Errorf("%w: epoch %d minRound > maxRound", ErrJournal, epoch)
		}
		if i > 0 && epoch <= j.Epochs[i-1].Epoch {
			return Journal{}, fmt.Errorf("%w: epochs not strictly ascending at %d", ErrJournal, epoch)
		}
		j.Epochs = append(j.Epochs, EpochUse{Epoch: epoch, Commitment: [32]byte(w(base + 1)), MinRound: minR, MaxRound: maxR})
	}
	return j, nil
}

// Digest is keccak256 of the encoded journal: the public-values digest a verifier binds.
func Digest(encoded []byte) [32]byte { return [32]byte(ethcrypto.Keccak256Hash(encoded)) }
