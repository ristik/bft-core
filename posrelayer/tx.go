package posrelayer

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/evmassign"
)

// The relayer's transactions. All of them are ordinary calls of the contracts' public entry points: the possession-proof submission and the
// finalization are open to anyone, and a joiner's onboarding is signed by the joiner's own keys. The relayer holds no authority: a wrong
// transaction is a revert or a result the root does not accept.

const writeABI = `[
 {"type":"function","name":"submitAssignmentPoPs","stateMutability":"nonpayable","inputs":[{"type":"bytes32"},{"type":"tuple[]","components":[
   {"name":"id","type":"uint64"},{"name":"evmKey","type":"bytes"},{"name":"signature","type":"bytes"}]}],"outputs":[]},
 {"type":"function","name":"finalizeCandidate","stateMutability":"nonpayable","inputs":[{"type":"bytes32"}],"outputs":[]},
 {"type":"function","name":"admitDelegation","stateMutability":"nonpayable","inputs":[{"type":"tuple","components":[
   {"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"binding","type":"tuple","components":[
     {"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},{"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},
     {"name":"operatorPayee","type":"address"}]},
   {"name":"roleNonce","type":"uint64"},{"name":"delegationNonce","type":"uint64"},{"name":"expiry","type":"uint64"}]},{"type":"bytes"},{"type":"bytes"}],"outputs":[]},
 {"type":"function","name":"delegationDigest","stateMutability":"view","inputs":[{"type":"tuple","components":[
   {"name":"id","type":"uint64"},{"name":"generation","type":"uint64"},{"name":"binding","type":"tuple","components":[
     {"name":"rootNodeID","type":"bytes32"},{"name":"rootKey","type":"bytes"},{"name":"evmNodeID","type":"bytes32"},{"name":"evmKey","type":"bytes"},
     {"name":"operatorPayee","type":"address"}]},
   {"name":"roleNonce","type":"uint64"},{"name":"delegationNonce","type":"uint64"},{"name":"expiry","type":"uint64"}]}],"outputs":[{"type":"bytes32"}]},
 {"type":"function","name":"register","stateMutability":"nonpayable","inputs":[{"type":"bytes"},{"type":"bytes"},{"type":"address"}],"outputs":[{"type":"uint64"}]},
 {"type":"function","name":"bond","stateMutability":"payable","inputs":[{"type":"uint64"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"registerNonce","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint64"}]},
 {"type":"function","name":"nextStakingID","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
 {"type":"function","name":"network","stateMutability":"view","inputs":[],"outputs":[{"type":"bytes32"}]}
]`

var writes abi.ABI

func init() {
	var err error
	if writes, err = abi.JSON(strings.NewReader(writeABI)); err != nil {
		panic(fmt.Sprintf("posrelayer: write ABI: %v", err))
	}
}

type popInput struct {
	Id        uint64
	EvmKey    []byte
	Signature []byte
}

// SubmitPoPsCalldata is election.submitAssignmentPoPs(resultID, pops): the members' EVM possession proofs, in the order given.
func SubmitPoPsCalldata(resultID [32]byte, pops []evmassign.EVMPoP) ([]byte, error) {
	in := make([]popInput, len(pops))
	for i, p := range pops {
		in[i] = popInput{Id: p.ID, EvmKey: p.EVMKey, Signature: p.Signature}
	}
	return writes.Pack("submitAssignmentPoPs", resultID, in)
}

// FinalizeCalldata is election.finalizeCandidate(resultID).
func FinalizeCalldata(resultID [32]byte) ([]byte, error) {
	return writes.Pack("finalizeCandidate", resultID)
}

// BondCalldata is custody.bond(id); the value is the bond.
func BondCalldata(id uint64) ([]byte, error) { return writes.Pack("bond", id) }

// Joiner is an identity that is not yet in the system: its owner, root and EVM keys, withdrawal and payee addresses, and its two peer ids.
type Joiner struct {
	OwnerKey, RootKey     *ecdsa.PrivateKey
	EVM                   EVMPossessor
	Withdrawal, Payee     [20]byte
	RootNodeID, EVMNodeID string
	Expiry                uint64 // UC seconds the delegation is valid until
}

// EVMPossessor holds a joiner's EVM key: it names the key and signs the delegation possession (P85 v5 section 2). A validator whose key
// lives in a signing authority uses the authority's SignDelegationPossession, which recomputes the digest itself; LocalEVM signs with a key
// the operator holds.
type EVMPossessor interface {
	PublicKey() []byte
	Possess(ctx context.Context, network, chain [32]byte, election [20]byte, r DelegationRequest) ([]byte, error)
}

type localEVM struct{ key *ecdsa.PrivateKey }

// LocalEVM is an EVMPossessor over a key the operator holds (the contracts' own tests, devnets with local signing).
func LocalEVM(key *ecdsa.PrivateKey) EVMPossessor { return localEVM{key} }

func (l localEVM) PublicKey() []byte { return compressed(l.key) }

func (l localEVM) Possess(_ context.Context, network, chain [32]byte, election [20]byte, r DelegationRequest) ([]byte, error) {
	return signDigest(l.key, evmassign.DelegationDigest(network, chain, election, r))
}

func compressed(k *ecdsa.PrivateKey) []byte { return ethcrypto.CompressPubkey(&k.PublicKey) }

// signDigest is the contracts' signature format: r || s || v with v = 27/28 and low s.
func signDigest(key *ecdsa.PrivateKey, digest [32]byte) ([]byte, error) {
	sig, err := ethcrypto.Sign(digest[:], key)
	if err != nil {
		return nil, err
	}
	sig[64] += 27
	return sig, nil
}

func word(v uint64) []byte { return new(big.Int).SetUint64(v).FillBytes(make([]byte, 32)) }

func addrWord(a [20]byte) []byte { return append(make([]byte, 12), a[:]...) }

// RegisterDigest is what the identity's root key signs to register (custody.register's proof of possession).
func RegisterDigest(network [32]byte, chainID *big.Int, custodyAddr, owner, withdrawal [20]byte, rootKey []byte, nonce uint64) [32]byte {
	domain := ethcrypto.Keccak256Hash([]byte("unicity.p85.pop.register"))
	chain := chainID.FillBytes(make([]byte, 32))
	return ethcrypto.Keccak256Hash(domain[:], network[:], chain, addrWord(custodyAddr), addrWord(owner), addrWord(withdrawal),
		ethcrypto.Keccak256(rootKey), word(nonce))
}

// DelegationRequest is the payload admitDelegation takes (evmassign's: the authority signs the same type).
type DelegationRequest = evmassign.DelegationRequest

func chainWord(chainID *big.Int) [32]byte {
	var w [32]byte
	chainID.FillBytes(w[:])
	return w
}

// DelegationDigest is what both the owner and the EVM key sign (ElectionPolicy.delegationDigest), computed here so that the signature never
// depends on what an RPC says the digest is.
func DelegationDigest(network [32]byte, chainID *big.Int, election [20]byte, r DelegationRequest) [32]byte {
	return evmassign.DelegationDigest(network, chainWord(chainID), election, r)
}

func (j Joiner) request(id uint64) (DelegationRequest, error) {
	rw, err1 := evmassign.NodeIDWord(j.RootNodeID)
	ew, err2 := evmassign.NodeIDWord(j.EVMNodeID)
	if err := errors.Join(err1, err2); err != nil {
		return DelegationRequest{}, err
	}
	var r DelegationRequest
	r.Id, r.Generation, r.Expiry = id, 1, j.Expiry
	r.Binding.RootNodeID, r.Binding.RootKey = rw, compressed(j.RootKey)
	r.Binding.EvmNodeID, r.Binding.EvmKey = ew, j.EVM.PublicKey()
	r.Binding.OperatorPayee = ethcommon.Address(j.Payee)
	return r, nil
}

// chainView reads the three words the onboarding signs over.
func chainView(ctx context.Context, rd Reader, m Modules, owner [20]byte) (network [32]byte, nonce, next uint64, err error) {
	b := builder{rd, m}
	o, err := b.call(ctx, m.Custody, writes, "network")
	if err != nil {
		return
	}
	network, _ = o[0].([32]byte)
	if o, err = b.call(ctx, m.Custody, writes, "registerNonce", ethcommon.Address(owner)); err != nil {
		return
	}
	nonce, _ = o[0].(uint64)
	if o, err = b.call(ctx, m.Custody, writes, "nextStakingID"); err != nil {
		return
	}
	next, _ = o[0].(uint64)
	return
}

// RegisterCalldata is custody.register(rootKey, proof, withdrawal) for the joiner, signed with its root key over the digest the contract
// derives, and the id the identity will get. The joiner's owner sends the transaction.
func (j Joiner) RegisterCalldata(ctx context.Context, rd Reader, m Modules, chainID *big.Int) (data []byte, id uint64, err error) {
	owner := ethcrypto.PubkeyToAddress(j.OwnerKey.PublicKey)
	network, nonce, next, err := chainView(ctx, rd, m, owner)
	if err != nil {
		return nil, 0, err
	}
	digest := RegisterDigest(network, chainID, m.Custody, owner, j.Withdrawal, compressed(j.RootKey), nonce)
	proof, err := signDigest(j.RootKey, digest)
	if err != nil {
		return nil, 0, err
	}
	data, err = writes.Pack("register", compressed(j.RootKey), proof, ethcommon.Address(j.Withdrawal))
	return data, next + 1, err
}

// AdmitCalldata is election.admitDelegation(request, ownerSignature, evmPossession) for the registered identity id (generation 1, fresh
// nonces). Both signatures are over the digest computed locally; the contract's own view of it is read and must agree.
func (j Joiner) AdmitCalldata(ctx context.Context, rd Reader, m Modules, chainID *big.Int, id uint64) ([]byte, error) {
	owner := ethcrypto.PubkeyToAddress(j.OwnerKey.PublicKey)
	network, _, _, err := chainView(ctx, rd, m, owner)
	if err != nil {
		return nil, err
	}
	r, err := j.request(id)
	if err != nil {
		return nil, err
	}
	digest := DelegationDigest(network, chainID, m.Election, r)
	b := builder{rd, m}
	o, err := b.call(ctx, m.Election, writes, "delegationDigest", r)
	if err != nil {
		return nil, err
	}
	if got, _ := o[0].([32]byte); got != digest {
		return nil, fmt.Errorf("%w: the election's delegation digest is not the one computed here", ErrBuild)
	}
	ownerSig, err1 := signDigest(j.OwnerKey, digest)
	evmSig, err2 := j.EVM.Possess(ctx, network, chainWord(chainID), m.Election, r)
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	return writes.Pack("admitDelegation", r, ownerSig, evmSig)
}

// Sender sends transactions from one account to one execution client.
type Sender struct {
	Client  *rpc.Client
	Key     *ecdsa.PrivateKey
	ChainID *big.Int
	// Wait bounds the wait for a receipt (default 90 s).
	Wait time.Duration
}

// Send signs and sends an EIP-1559 transaction, waits for its receipt and fails unless it succeeded.
func (s Sender) Send(ctx context.Context, to [20]byte, value *big.Int, data []byte) (ethcommon.Hash, error) {
	from := ethcrypto.PubkeyToAddress(s.Key.PublicKey)
	var nonce hexutil.Uint64
	if err := s.Client.CallContext(ctx, &nonce, "eth_getTransactionCount", from, "pending"); err != nil {
		return ethcommon.Hash{}, err
	}
	var head struct {
		BaseFee *hexutil.Big `json:"baseFeePerGas"`
	}
	if err := s.Client.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return ethcommon.Hash{}, err
	}
	tip := big.NewInt(1_000_000_000)
	feeCap := new(big.Int).Set(tip)
	if head.BaseFee != nil {
		feeCap.Add(new(big.Int).Mul(head.BaseFee.ToInt(), big.NewInt(2)), tip)
	}
	if value == nil {
		value = new(big.Int)
	}
	toAddr := ethcommon.Address(to)
	est := map[string]any{"from": from, "to": toAddr, "data": hexutil.Bytes(data), "value": (*hexutil.Big)(value)}
	var gas hexutil.Uint64
	if err := s.Client.CallContext(ctx, &gas, "eth_estimateGas", est); err != nil {
		return ethcommon.Hash{}, fmt.Errorf("the transaction would revert or run out of gas: %w", err)
	}
	tx, err := types.SignNewTx(s.Key, types.LatestSignerForChainID(s.ChainID), &types.DynamicFeeTx{ChainID: s.ChainID, Nonce: uint64(nonce),
		GasTipCap: tip, GasFeeCap: feeCap, Gas: uint64(gas) * 13 / 10, To: &toAddr, Value: value, Data: data})
	if err != nil {
		return ethcommon.Hash{}, err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return ethcommon.Hash{}, err
	}
	if err := s.Client.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Bytes(raw)); err != nil {
		return ethcommon.Hash{}, err
	}
	wait := s.Wait
	if wait == 0 {
		wait = 90 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		var out *struct {
			Status hexutil.Uint64 `json:"status"`
		}
		if err := s.Client.CallContext(ctx, &out, "eth_getTransactionReceipt", tx.Hash()); err != nil {
			return tx.Hash(), err
		}
		if out != nil {
			if out.Status != 1 {
				return tx.Hash(), fmt.Errorf("transaction %s reverted", tx.Hash())
			}
			return tx.Hash(), nil
		}
		select {
		case <-ctx.Done():
			return tx.Hash(), ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return tx.Hash(), fmt.Errorf("transaction %s was not mined within %s", tx.Hash(), wait)
}

// DecodeAdmit reads admitDelegation calldata back: the request and the two signatures (for tests and for an operator checking what a
// joiner's transaction carries).
func DecodeAdmit(data []byte) (r DelegationRequest, ownerSig, evmSig []byte, err error) {
	if len(data) < 4 || !bytes.Equal(data[:4], writes.Methods["admitDelegation"].ID) {
		return r, nil, nil, fmt.Errorf("%w: not admitDelegation calldata", ErrBuild)
	}
	out, err := writes.Methods["admitDelegation"].Inputs.Unpack(data[4:])
	if err != nil {
		return r, nil, nil, err
	}
	if len(out) != 3 {
		return r, nil, nil, fmt.Errorf("%w: admitDelegation takes three arguments", ErrBuild)
	}
	if r, err = decode[DelegationRequest](out[0]); err != nil {
		return r, nil, nil, err
	}
	ownerSig, _ = out[1].([]byte)
	evmSig, _ = out[2].([]byte)
	return r, ownerSig, evmSig, nil
}
