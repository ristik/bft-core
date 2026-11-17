// Package vrfake is an in-memory JSON-RPC endpoint that serves a ValidatorRegistry and its PoaElection module the way a public ureth
// endpoint does, for the unit tests of the validator CLI: eth_call of VR's, the module's and the SealRegistry's views, and owner
// transactions (register, proposeBinding, submitApplication, withdrawApplication, requestExit, rejoin) through eth_estimateGas and
// eth_sendRawTransaction, with VR's checks (shape, nonces, tombstoned keys, proofs of possession) and the module's state guards. Reverts
// carry the contracts' ABI errors as JSON-RPC error data. It is a model for tests, not a VR implementation: governance is set directly.
package vrfake

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// Identity is one VR identity of the model.
type Identity struct {
	Owner        ethcommon.Address
	Generation   uint64
	Current      vrclient.Registration
	Staged       *vrclient.Registration
	BindingNonce uint64
}

// Chain is the model's state. Tests read and set it under Mu.
type Chain struct {
	Mu sync.Mutex

	ChainID  *big.Int
	Network  [32]byte
	Registry ethcommon.Address
	Module   ethcommon.Address
	Seal     ethcommon.Address
	Tag      [32]byte

	Identities map[uint64]*Identity
	RegNonce   map[ethcommon.Address]uint64
	KeyOwner   map[[32]byte]uint64
	Poa        map[uint64][2]uint64 // state, since
	Committee  []uint64
	Config     vrclient.ConfigView
	Changes    map[uint64]vrclient.ChangeView
	Pending    []uint64
	Open       [32]byte
	Outputs    map[[32]byte]vrclient.OutputView
	Pair       [32]byte

	Progress, UcTime, RecordCount, RecordCursor uint64

	Head     uint64
	HeadTime uint64
	BaseFee  *big.Int
	Nonces   map[ethcommon.Address]uint64
	Balances map[ethcommon.Address]*big.Int
	Receipts map[ethcommon.Hash]map[string]any
	Logs     []map[string]any
	// Sent records every accepted transaction's calldata, in order.
	Sent [][]byte
	// NoLogs makes eth_getLogs fail, as an endpoint that refuses wide log queries.
	NoLogs bool
}

// New returns a chain with VR at 0xff..03, PoaElection at 0xff..07 and the SealRegistry at 0xff..02, chain id 3, no identities.
func New() *Chain {
	c := &Chain{ChainID: big.NewInt(3), Network: vrschema.DomainWord("vrfake.network"), Registry: vrclient.DefaultRegistry,
		Module: ethcommon.HexToAddress("0xff00000000000000000000000000000000000007"), Seal: vrclient.DefaultSealRegistry,
		Tag: vrclient.ModuleTagPoA, Identities: map[uint64]*Identity{}, RegNonce: map[ethcommon.Address]uint64{}, KeyOwner: map[[32]byte]uint64{},
		Poa: map[uint64][2]uint64{}, Changes: map[uint64]vrclient.ChangeView{}, Outputs: map[[32]byte]vrclient.OutputView{},
		Head: 100, HeadTime: 1_700_000_000, BaseFee: big.NewInt(1_000_000), Nonces: map[ethcommon.Address]uint64{},
		Balances: map[ethcommon.Address]*big.Int{}, Receipts: map[ethcommon.Hash]map[string]any{}, Progress: 5000, UcTime: 1_700_000_000}
	c.Config = vrclient.ConfigView{Network: c.Network, NMin: 4, NTarget: 4, NMax: 16, VMax: 16, LMax: 1, RMax: 4, MaxBatch: 32,
		DelayRounds: 2000, DelaySeconds: 3600, KnownRootEpoch: 1}
	return c
}

// AddMember registers a genesis member: an identity owned by owner, Active, in the committee.
func (c *Chain) AddMember(owner ethcommon.Address, r vrclient.Registration) uint64 {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	id := uint64(len(c.Identities) + 1)
	c.Identities[id] = &Identity{Owner: owner, Generation: 1, Current: r}
	c.KeyOwner[ethcrypto.Keccak256Hash(r.RootKey)] = id
	c.KeyOwner[ethcrypto.Keccak256Hash(r.EvmKey)] = id
	c.Poa[id] = [2]uint64{uint64(vrclient.PoaActive), 0}
	c.Committee = append(c.Committee, id)
	return id
}

// SetState sets an identity's PoA state (the Foundation's actions and boundaries are not modelled).
func (c *Chain) SetState(id uint64, state uint8) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.Poa[id] = [2]uint64{uint64(state), c.Progress}
}

// State is an identity's PoA state.
func (c *Chain) State(id uint64) uint8 {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return uint8(c.Poa[id][0])
}

// Sends is the number of accepted transactions.
func (c *Chain) Sends() int {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	return len(c.Sent)
}

// Identity is a copy of an identity (nil when unknown).
func (c *Chain) Identity(id uint64) *Identity {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	idn := c.Identities[id]
	if idn == nil {
		return nil
	}
	cp := *idn
	return &cp
}

// With runs f under the chain's lock, for tests that change the model.
func (c *Chain) With(f func(c *Chain)) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	f(c)
}

// Fund gives an account a balance.
func (c *Chain) Fund(a ethcommon.Address, wei *big.Int) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	c.Balances[a] = wei
}

// Serve starts the endpoint; the caller closes it.
func (c *Chain) Serve() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(c.handle))
}

type request struct {
	ID     json.RawMessage   `json:"id"`
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (c *Chain) handle(w http.ResponseWriter, r *http.Request) {
	var req request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	res, rerr := c.locked(req)
	out := map[string]any{"jsonrpc": "2.0", "id": req.ID}
	if rerr != nil {
		out["error"] = rerr
	} else {
		out["result"] = res
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (c *Chain) locked(req request) (res any, rerr *rpcError) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			res, rerr = nil, &rpcError{Code: -32603, Message: fmt.Sprintf("vrfake: %v", r)}
		}
	}()
	return c.dispatch(req)
}

type callArgs struct {
	From *ethcommon.Address `json:"from"`
	To   ethcommon.Address  `json:"to"`
	Data hexutil.Bytes      `json:"data"`
}

func (c *Chain) dispatch(req request) (any, *rpcError) {
	switch req.Method {
	case "eth_chainId":
		return (*hexutil.Big)(c.ChainID), nil
	case "eth_blockNumber":
		return hexutil.Uint64(c.Head), nil
	case "eth_syncing":
		return false, nil
	case "eth_getBlockByNumber":
		return map[string]any{"number": hexutil.Uint64(c.Head), "timestamp": hexutil.Uint64(c.HeadTime), "baseFeePerGas": (*hexutil.Big)(c.BaseFee)}, nil
	case "eth_getBalance":
		var a ethcommon.Address
		_ = json.Unmarshal(req.Params[0], &a)
		b := c.Balances[a]
		if b == nil {
			b = new(big.Int)
		}
		return (*hexutil.Big)(b), nil
	case "eth_getTransactionCount":
		var a ethcommon.Address
		_ = json.Unmarshal(req.Params[0], &a)
		return hexutil.Uint64(c.Nonces[a]), nil
	case "eth_call", "eth_estimateGas":
		var a callArgs
		if err := json.Unmarshal(req.Params[0], &a); err != nil {
			return nil, &rpcError{Code: -32602, Message: err.Error()}
		}
		from := ethcommon.Address{}
		if a.From != nil {
			from = *a.From
		}
		ret, rerr := c.exec(from, a.To, a.Data, false)
		if rerr != nil {
			return nil, rerr
		}
		if req.Method == "eth_estimateGas" {
			return hexutil.Uint64(200_000), nil
		}
		return hexutil.Bytes(ret), nil
	case "eth_sendRawTransaction":
		var raw hexutil.Bytes
		_ = json.Unmarshal(req.Params[0], &raw)
		var tx types.Transaction
		if err := tx.UnmarshalBinary(raw); err != nil {
			return nil, &rpcError{Code: -32000, Message: err.Error()}
		}
		from, err := types.Sender(types.LatestSignerForChainID(c.ChainID), &tx)
		if err != nil {
			return nil, &rpcError{Code: -32000, Message: "invalid sender: " + err.Error()}
		}
		if tx.ChainId().Cmp(c.ChainID) != 0 {
			return nil, &rpcError{Code: -32000, Message: "wrong chain id"}
		}
		if tx.Nonce() != c.Nonces[from] {
			return nil, &rpcError{Code: -32000, Message: "nonce too low"}
		}
		c.Nonces[from]++
		c.Head++
		c.HeadTime += 2
		start := len(c.Logs)
		_, rerr := c.exec(from, *tx.To(), tx.Data(), true)
		status := hexutil.Uint64(1)
		if rerr != nil {
			status = 0
			c.Logs = c.Logs[:start]
		} else {
			c.Sent = append(c.Sent, tx.Data())
		}
		c.Receipts[tx.Hash()] = map[string]any{"status": status, "blockNumber": hexutil.Uint64(c.Head), "gasUsed": hexutil.Uint64(150_000),
			"logs": append([]map[string]any(nil), c.Logs[start:]...)}
		return tx.Hash(), nil
	case "eth_getTransactionReceipt":
		var h ethcommon.Hash
		_ = json.Unmarshal(req.Params[0], &h)
		if r, ok := c.Receipts[h]; ok {
			return r, nil
		}
		return nil, nil
	case "eth_getLogs":
		if c.NoLogs {
			return nil, &rpcError{Code: -32005, Message: "query returned more than 10000 results"}
		}
		var q struct {
			Topics []*ethcommon.Hash `json:"topics"`
		}
		_ = json.Unmarshal(req.Params[0], &q)
		var out []map[string]any
		for _, l := range c.Logs {
			ts := l["topics"].([]ethcommon.Hash)
			match := true
			for i, t := range q.Topics {
				if t != nil && (i >= len(ts) || ts[i] != *t) {
					match = false
				}
			}
			if match {
				out = append(out, l)
			}
		}
		return out, nil
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + req.Method}
}

func revert(a abi.ABI, name string, args ...any) *rpcError {
	e := a.Errors[name]
	data, err := e.Inputs.Pack(args...)
	if err != nil {
		panic(err)
	}
	return &rpcError{Code: 3, Message: "execution reverted", Data: hexutil.Encode(append(append([]byte(nil), e.ID[:4]...), data...))}
}

func pack(a abi.ABI, method string, vals ...any) []byte {
	b, err := a.Methods[method].Outputs.Pack(vals...)
	if err != nil {
		panic(fmt.Sprintf("vrfake: packing %s: %v", method, err))
	}
	return b
}

func (c *Chain) exec(from, to ethcommon.Address, data []byte, write bool) ([]byte, *rpcError) {
	if len(data) < 4 {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	var a abi.ABI
	switch to {
	case c.Registry:
		a = vrclient.VRABI
	case c.Module:
		a = vrclient.PoaABI
	case c.Seal:
		switch {
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("progress()"))[:4]):
			return u64word(c.Progress), nil
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("ucTime()"))[:4]):
			return u64word(c.UcTime), nil
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("recordCount()"))[:4]):
			return u64word(c.RecordCount), nil
		}
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	default:
		return nil, nil // no code: an empty return
	}
	m, err := a.MethodById(data[:4])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	if to == c.Module {
		return c.poa(from, m.Name, in, write)
	}
	return c.vr(from, m.Name, in, write)
}

func u64word(v uint64) []byte {
	w := vrschema.U64(v)
	return w[:]
}

func binding(r vrclient.Registration) vrclient.Binding {
	return vrclient.Binding{RootNodeWord: ethcrypto.Keccak256Hash([]byte(r.RootNodeID)), RootKeyHash: ethcrypto.Keccak256Hash(r.RootKey),
		EvmNodeWord: ethcrypto.Keccak256Hash([]byte(r.EvmNodeID)), EvmKeyHash: ethcrypto.Keccak256Hash(r.EvmKey), Payee: r.Payee,
		RootNodeID: r.RootNodeID, RootKey: r.RootKey, EvmNodeID: r.EvmNodeID, EvmKey: r.EvmKey}
}

func ref(r vrclient.Registration) [32]byte {
	b := binding(r)
	return ethcrypto.Keccak256Hash(b.RootNodeWord[:], b.RootKeyHash[:], b.EvmNodeWord[:], b.EvmKeyHash[:], b.Payee[:])
}

func toReg(v any) vrclient.Registration {
	var r vrclient.Registration
	abi.ConvertType(v, &r)
	return r
}

func (c *Chain) member(id uint64) bool {
	for _, m := range c.Committee {
		if m == id {
			return true
		}
	}
	return false
}

func (c *Chain) members() []vrclient.Member {
	var out []vrclient.Member
	for _, id := range c.Committee {
		idn := c.Identities[id]
		b := binding(idn.Current)
		out = append(out, vrclient.Member{Id: id, Generation: idn.Generation, Weight: 1, RawWeight: 1, RootNodeWord: b.RootNodeWord,
			RootKeyHash: b.RootKeyHash, EvmNodeWord: b.EvmNodeWord, EvmKeyHash: b.EvmKeyHash, Payee: b.Payee})
	}
	return out
}

// verifyPoP is KeyLib.verify: a 65-byte r||s||v (v 27/28) signature over the digest by the compressed key.
func verifyPoP(key []byte, digest [32]byte, sig []byte) bool {
	if len(sig) != 65 || (sig[64] != 27 && sig[64] != 28) {
		return false
	}
	s := append([]byte(nil), sig...)
	s[64] -= 27
	pub, err := ethcrypto.SigToPub(digest[:], s)
	if err != nil {
		return false
	}
	return bytes.Equal(ethcrypto.CompressPubkey(pub), key)
}

func (c *Chain) digest(binding bool, sender ethcommon.Address, id uint64, r vrclient.Registration) [32]byte {
	var chain vrschema.Word
	c.ChainID.FillBytes(chain[:])
	return vrschema.RegistrationDigest(binding, c.Network, chain, c.Registry, sender, id, vrschema.Registration{RootNodeID: r.RootNodeID,
		RootKey: r.RootKey, EVMNodeID: r.EvmNodeID, EVMKey: r.EvmKey, Payee: r.Payee, Nonce: r.Nonce})
}

func shape(r vrclient.Registration) uint8 {
	s := vrschema.Registration{RootNodeID: r.RootNodeID, RootKey: r.RootKey, EVMNodeID: r.EvmNodeID, EVMKey: r.EvmKey, Payee: r.Payee}
	if err := s.ValidShape(); err != nil {
		switch {
		case len(r.RootNodeID) < 1 || len(r.RootNodeID) > 128 || len(r.EvmNodeID) < 1 || len(r.EvmNodeID) > 128:
			return 1
		case bytes.Equal(r.RootKey, r.EvmKey):
			return 3
		case r.Payee == (ethcommon.Address{}):
			return 4
		}
		return 2
	}
	return 0
}

func (c *Chain) log(event string, topics []ethcommon.Hash, data []byte) {
	ev := vrclient.VRABI.Events[event]
	c.Logs = append(c.Logs, map[string]any{"address": c.Registry, "topics": append([]ethcommon.Hash{ev.ID}, topics...), "data": hexutil.Bytes(data)})
}

func idTopic(id uint64) ethcommon.Hash { return ethcommon.Hash(vrschema.U64(id)) }

func (c *Chain) vr(from ethcommon.Address, method string, in []any, write bool) ([]byte, *rpcError) {
	a := vrclient.VRABI
	switch method {
	case "identity":
		id := in[0].(uint64)
		v := vrclient.IdentityView{}
		if idn := c.Identities[id]; idn != nil {
			v = vrclient.IdentityView{Owner: idn.Owner, Generation: idn.Generation, CurrentRef: ref(idn.Current), BindingNonce: idn.BindingNonce,
				RegistrationNonce: c.RegNonce[idn.Owner], Current: binding(idn.Current)}
			if idn.Staged != nil {
				v.StagedRef, v.Staged = ref(*idn.Staged), binding(*idn.Staged)
			}
		}
		return pack(a, method, v), nil
	case "ownerOf":
		o := ethcommon.Address{}
		if idn := c.Identities[in[0].(uint64)]; idn != nil {
			o = idn.Owner
		}
		return pack(a, method, o), nil
	case "registrationNonce":
		return pack(a, method, c.RegNonce[in[0].(ethcommon.Address)]), nil
	case "config":
		return pack(a, method, c.Config), nil
	case "activeModule":
		return pack(a, method, vrclient.ModuleView{Module: c.Module, Meta: vrclient.ModuleMeta{ModuleTag: c.Tag}}), nil
	case "committee":
		return pack(a, method, c.members()), nil
	case "openOutput":
		return pack(a, method, c.Open), nil
	case "pendingPair":
		return pack(a, method, c.Pair), nil
	case "output":
		return pack(a, method, c.Outputs[in[0].([32]byte)]), nil
	case "pendingChanges":
		return pack(a, method, append([]uint64{}, c.Pending...)), nil
	case "change":
		return pack(a, method, c.Changes[in[0].(uint64)]), nil
	case "activationCount":
		return pack(a, method, uint32(0)), nil
	case "recordCursor":
		return pack(a, method, c.RecordCursor), nil
	case "register":
		r := toReg(in[0])
		if e := shape(r); e != 0 {
			return nil, revert(a, "RegistrationRefused", e)
		}
		if r.Nonce != c.RegNonce[from] {
			return nil, revert(a, "RegistrationRefused", uint8(5))
		}
		if c.KeyOwner[ethcrypto.Keccak256Hash(r.RootKey)] != 0 || c.KeyOwner[ethcrypto.Keccak256Hash(r.EvmKey)] != 0 {
			return nil, revert(a, "RegistrationRefused", uint8(6))
		}
		d := c.digest(false, from, 0, r)
		if !verifyPoP(r.RootKey, d, in[1].([]byte)) || !verifyPoP(r.EvmKey, d, in[2].([]byte)) {
			return nil, revert(a, "RegistrationRefused", uint8(7))
		}
		id := uint64(len(c.Identities) + 1)
		if write {
			c.RegNonce[from]++
			c.Identities[id] = &Identity{Owner: from, Generation: 1, Current: r}
			c.KeyOwner[ethcrypto.Keccak256Hash(r.RootKey)] = id
			c.KeyOwner[ethcrypto.Keccak256Hash(r.EvmKey)] = id
			rf := ref(r)
			c.log("Registered", []ethcommon.Hash{idTopic(id), ethcommon.BytesToHash(from.Bytes())}, rf[:])
		}
		return pack(a, method, id), nil
	case "proposeBinding":
		id := in[0].(uint64)
		r := toReg(in[1])
		idn := c.Identities[id]
		if idn == nil || idn.Owner != from {
			return nil, revert(a, "NotOwner")
		}
		if e := shape(r); e != 0 {
			return nil, revert(a, "RegistrationRefused", e)
		}
		if r.Nonce != idn.BindingNonce {
			return nil, revert(a, "RegistrationRefused", uint8(5))
		}
		if o := c.KeyOwner[ethcrypto.Keccak256Hash(r.RootKey)]; o != 0 && o != id {
			return nil, revert(a, "RegistrationRefused", uint8(6))
		}
		if o := c.KeyOwner[ethcrypto.Keccak256Hash(r.EvmKey)]; o != 0 && o != id {
			return nil, revert(a, "RegistrationRefused", uint8(6))
		}
		if ref(r) == ref(idn.Current) {
			return nil, revert(a, "RegistrationRefused", uint8(8))
		}
		d := c.digest(true, from, id, r)
		if !verifyPoP(r.RootKey, d, in[2].([]byte)) || !verifyPoP(r.EvmKey, d, in[3].([]byte)) {
			return nil, revert(a, "RegistrationRefused", uint8(7))
		}
		if write {
			idn.BindingNonce++
			idn.Staged = &r
			c.KeyOwner[ethcrypto.Keccak256Hash(r.RootKey)] = id
			c.KeyOwner[ethcrypto.Keccak256Hash(r.EvmKey)] = id
			c.log("BindingProposed", []ethcommon.Hash{idTopic(id)}, nil)
		}
		return nil, nil
	}
	return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + method + " not modelled)"}
}

func (c *Chain) poa(from ethcommon.Address, method string, in []any, write bool) ([]byte, *rpcError) {
	a := vrclient.PoaABI
	switch method {
	case "status":
		s := c.Poa[in[0].(uint64)]
		return pack(a, method, uint8(s[0]), s[1]), nil
	case "queue":
		var q []uint64
		for id, s := range c.Poa {
			if !c.member(id) && (s[0] == uint64(vrclient.PoaAdmitted) || s[0] == uint64(vrclient.PoaParked)) {
				q = append(q, id)
			}
		}
		sort.Slice(q, func(i, j int) bool { return q[i] < q[j] })
		return pack(a, method, q), nil
	}
	moves := map[string][3]uint8{
		vrclient.MethodSubmitApplication:   {vrclient.PoaNone, vrclient.PoaExited, vrclient.PoaApplied},
		vrclient.MethodWithdrawApplication: {vrclient.PoaApplied, vrclient.PoaApplied, vrclient.PoaNone},
		vrclient.MethodRequestExit:         {vrclient.PoaActive, vrclient.PoaActive, vrclient.PoaExitRequested},
		vrclient.MethodRejoin:              {vrclient.PoaParked, vrclient.PoaParked, vrclient.PoaAdmitted},
	}
	mv, ok := moves[method]
	if !ok {
		return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + method + " not modelled)"}
	}
	id := in[0].(uint64)
	idn := c.Identities[id]
	if idn == nil || idn.Owner != from {
		return nil, revert(a, "NotOwner")
	}
	s := uint8(c.Poa[id][0])
	if (s != mv[0] && s != mv[1]) || (mv[2] == vrclient.PoaApplied && c.member(id)) {
		return nil, revert(a, "BadState", s)
	}
	if write {
		c.Poa[id] = [2]uint64{uint64(mv[2]), c.Progress}
	}
	return nil, nil
}
