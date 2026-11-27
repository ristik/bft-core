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
	Custody  ethcommon.Address
	Election ethcommon.Address
	Tag      [32]byte
	// ClaimLots and ClaimCredit model a single withdrawal in the custody test fixture.
	ClaimLots   []*big.Int
	ClaimCredit *big.Int
	// Evidence is the evidence contract custody names (#1286); Pos models custody's positions, the exclusions and the election's
	// delegations and open result (nil: the claim fixture's fixed positions and no election views).
	Evidence ethcommon.Address
	Pos      *Pos
	// Terms models custody's report anchors (#1297/#1298); nil: contracts that predate them (no anchor views).
	Terms *Terms
	// Governor is the FoundationMultisig, Signers its five signers (ascending) and MsigNonce its approval nonce.
	Governor     ethcommon.Address
	Signers      [5]ethcommon.Address
	MsigNonce    uint64
	NextChangeID uint64

	Identities map[uint64]*Identity
	RegNonce   map[ethcommon.Address]uint64
	KeyOwner   map[[32]byte]uint64
	Poa        map[uint64][2]uint64 // state, since
	Committee  []uint64
	Config     vrclient.ConfigView
	Health     uint8
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
	// ExtraLogs are returned by every eth_getLogs, unfiltered: a non-compliant or hostile endpoint.
	ExtraLogs []map[string]any
	// FailSyncing makes eth_syncing fail.
	FailSyncing bool
	// FailActivations makes activationCount fail.
	FailActivations bool
	// FinalizedDelegations, when set, are the election's delegations as the finalized block (eth_getBlockByNumber "finalized") reads
	// them: a certified view that lags the latest one. Reads at any other block see Pos.Delegations.
	FinalizedDelegations map[[2]uint64]*Delegated
	atFinalized          bool
	// AfterSend, when set, runs under Mu after each accepted transaction with its calldata: a concurrent change landing in the same block.
	AfterSend func(c *Chain, data []byte)
	// AfterCall, when set, runs under Mu after each eth_call with its target, calldata and pinned block hash (MoveHeadLocked in it lands a block between two
	// reads of one caller).
	AfterCall func(c *Chain, to ethcommon.Address, data []byte, blockHash ethcommon.Hash)
	// history keeps the identities and the P85 state of the blocks MoveHeadLocked left behind, by block hash: an eth_call that names
	// one (EIP-1898) reads that block's state, as a node does.
	history map[ethcommon.Hash]*blockState
}

type blockState struct {
	identities  map[uint64]*Identity
	positions   map[uint64]*Position
	delegations map[[2]uint64]*Delegated
}

// headHash is the hash eth_getBlockByNumber reports for the head.
func (c *Chain) headHash() ethcommon.Hash {
	return ethcommon.BigToHash(new(big.Int).SetUint64(c.Head + 1))
}

// MoveHeadLocked mines an empty block that applies mutate, keeping the old head's state readable by its hash. The caller holds Mu (it is
// meant for AfterCall and AfterSend).
func (c *Chain) MoveHeadLocked(mutate func(c *Chain)) {
	st := &blockState{identities: map[uint64]*Identity{}, positions: map[uint64]*Position{}, delegations: map[[2]uint64]*Delegated{}}
	for id, idn := range c.Identities {
		cp := *idn
		if idn.Staged != nil {
			staged := *idn.Staged
			cp.Staged = &staged
		}
		st.identities[id] = &cp
	}
	if c.Pos != nil {
		for id, p := range c.Pos.Positions {
			cp := *p
			st.positions[id] = &cp
		}
		for k, d := range c.Pos.Delegations {
			cp := *d
			st.delegations[k] = &cp
		}
	}
	if c.history == nil {
		c.history = map[ethcommon.Hash]*blockState{}
	}
	c.history[c.headHash()] = st
	c.Head++
	c.HeadTime += 2
	mutate(c)
}

// finalizedHash is the finalized block's hash while FinalizedDelegations is set.
var finalizedHash = ethcommon.HexToHash("0xf1")

// New returns a chain with VR at 0xff..03, PoaElection at 0xff..07 and the SealRegistry at 0xff..02, chain id 3, no identities.
func New() *Chain {
	c := &Chain{ChainID: big.NewInt(3), Network: vrschema.DomainWord("vrfake.network"), Registry: vrclient.DefaultRegistry,
		Module: ethcommon.HexToAddress("0xff00000000000000000000000000000000000007"), Seal: vrclient.DefaultSealRegistry,
		Tag: vrclient.ModuleTagPoA, Identities: map[uint64]*Identity{}, RegNonce: map[ethcommon.Address]uint64{}, KeyOwner: map[[32]byte]uint64{},
		Poa: map[uint64][2]uint64{}, Changes: map[uint64]vrclient.ChangeView{}, Outputs: map[[32]byte]vrclient.OutputView{},
		Head: 100, HeadTime: 1_700_000_000, BaseFee: big.NewInt(1_000_000), Nonces: map[ethcommon.Address]uint64{},
		Balances: map[ethcommon.Address]*big.Int{}, Receipts: map[ethcommon.Hash]map[string]any{}, Progress: 5000, UcTime: 1_700_000_000}
	c.Governor = ethcommon.HexToAddress("0xff00000000000000000000000000000000000009")
	c.NextChangeID = 1
	c.Config = vrclient.ConfigView{Governor: c.Governor, Network: c.Network, NMin: 4, NTarget: 4, NMax: 16, VMax: 16, LMax: 1, RMax: 4, MaxBatch: 32,
		DelayRounds: 2000, DelaySeconds: 3600, KnownRootEpoch: 1, MaxGas: 184729388, SystemGas: 124729388}
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
		if c.FailSyncing {
			return nil, &rpcError{Code: -32601, Message: "the method eth_syncing does not exist/is not available"}
		}
		return false, nil
	case "eth_getBlockByNumber":
		var tag string
		_ = json.Unmarshal(req.Params[0], &tag)
		if tag == "finalized" && c.FinalizedDelegations != nil {
			return map[string]any{"number": hexutil.Uint64(c.Head - 1), "hash": finalizedHash, "timestamp": hexutil.Uint64(c.HeadTime), "baseFeePerGas": (*hexutil.Big)(c.BaseFee)}, nil
		}
		return map[string]any{"number": hexutil.Uint64(c.Head), "hash": ethcommon.BigToHash(new(big.Int).SetUint64(c.Head + 1)),
			"timestamp": hexutil.Uint64(c.HeadTime), "baseFeePerGas": (*hexutil.Big)(c.BaseFee)}, nil
	case "eth_getCode":
		return hexutil.Bytes{}, nil
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
		var blockHash ethcommon.Hash
		if len(req.Params) > 1 && bytes.HasPrefix(bytes.TrimSpace(req.Params[1]), []byte("{")) {
			var selector map[string]json.RawMessage
			if err := json.Unmarshal(req.Params[1], &selector); err != nil ||
				len(selector) != 2 || !bytes.Equal(selector["requireCanonical"], []byte("true")) ||
				json.Unmarshal(selector["blockHash"], &blockHash) != nil || blockHash == (ethcommon.Hash{}) {
				return nil, &rpcError{Code: -32602, Message: "expected a blockHash selector with requireCanonical: true"}
			}
			if blockHash != c.headHash() && c.history[blockHash] == nil &&
				!(c.FinalizedDelegations != nil && blockHash == finalizedHash) {
				return nil, &rpcError{Code: -32000, Message: "unknown canonical block"}
			}
		}
		c.atFinalized = c.FinalizedDelegations != nil && blockHash == finalizedHash
		var ret []byte
		var rerr *rpcError
		if old := c.history[blockHash]; old != nil && c.Pos != nil && !c.atFinalized {
			// a block MoveHeadLocked left behind: read its state
			idns, pos, dels := c.Identities, c.Pos.Positions, c.Pos.Delegations
			c.Identities, c.Pos.Positions, c.Pos.Delegations = old.identities, old.positions, old.delegations
			ret, rerr = c.exec(from, a.To, a.Data, false)
			c.Identities, c.Pos.Positions, c.Pos.Delegations = idns, pos, dels
		} else {
			ret, rerr = c.exec(from, a.To, a.Data, false)
		}
		c.atFinalized = false
		if c.AfterCall != nil && req.Method == "eth_call" {
			c.AfterCall(c, a.To, a.Data, blockHash)
		}
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
			if c.AfterSend != nil {
				c.AfterSend(c, tx.Data())
			}
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
		return append(out, c.ExtraLogs...), nil
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

// Terms is the anchor state: the SealRegistry's Closure records, the terms custody closed and anchored, and the lots still waiting.
type Terms struct {
	Closures   [][3][32]byte // assignmentID, hRecordID, terminalRoot, as the Closure records carry them
	Closed     map[[32]byte]bool
	Anchored   map[[32]byte]bool
	Unanchored map[string]uint32 // by lot id (decimal)
	Anchors    int               // anchorTerm transactions applied
	// Backs names the lots each term's assignment references (one exposure per term, its id the assignment id); NotReady terms refuse
	// anchorTerm (their successor epoch is not installed).
	Backs    map[[32]byte][]*big.Int
	NotReady map[[32]byte]bool
	// Seats are compact-seat lots per term (assignmentSeat), instead of Backs' legacy exposure; Race terms are anchored by another party
	// between the caller's preview and its transaction (the caller's send reverts).
	Seats map[[32]byte][]*big.Int
	Race  map[[32]byte]bool
}

type seatBinding struct {
	Id, Generation                             uint64
	RootNode, RootKeyHash, EvmNode, EvmKeyHash [32]byte
	Payee                                      ethcommon.Address
}

type assignmentSeat struct {
	Binding                               seatBinding
	Weight, RawWeight                     uint64
	BindingHash, ExposureID, MemberDigest [32]byte
	LotID                                 *big.Int
}

func (t *Terms) record(i uint64) vrclient.RootRecord {
	c := t.Closures[i]
	data := make([]byte, 6*32)
	copy(data[0:32], c[0][:])
	copy(data[64:96], c[1][:])
	copy(data[96:128], c[2][:])
	return vrclient.RootRecord{Index: i, Kind: vrclient.RecordKindClosure, Data: data}
}

func (c *Chain) terms(from ethcommon.Address, data []byte, write bool) ([]byte, *rpcError) {
	a := vrclient.CustodyTermsABI
	m, err := a.MethodById(data[:4])
	if err != nil || c.Terms == nil {
		return nil, nil
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	t := c.Terms
	switch m.Name {
	case "roots":
		return pack(a, "roots", c.Seal), nil
	case "lotUnanchoredTerms":
		return pack(a, "lotUnanchoredTerms", t.Unanchored[in[0].(*big.Int).String()]), nil
	case "termAnchors":
		return pack(a, "termAnchors", [32]byte{}, [32]byte{}, uint64(0), uint64(0), t.Anchored[in[0].([32]byte)]), nil
	case "assignments":
		return pack(a, "assignments", uint8(2), [32]byte{}, uint64(0), uint64(0), uint64(0), uint64(0), false, false, uint64(0), t.Closed[in[0].([32]byte)],
			uint64(0), uint64(0), [32]byte{}, [32]byte{}, [32]byte{}, uint32(0)), nil
	case "assignmentSeatCount":
		return pack(a, "assignmentSeatCount", big.NewInt(int64(len(t.Seats[in[0].([32]byte)])))), nil
	case "assignmentSeat":
		seats, i := t.Seats[in[0].([32]byte)], in[1].(*big.Int)
		if !i.IsInt64() || i.Int64() >= int64(len(seats)) {
			return nil, &rpcError{Code: 3, Message: "execution reverted"}
		}
		return pack(a, "assignmentSeat", assignmentSeat{LotID: seats[i.Int64()]}), nil
	case "assignmentExposures":
		aid := in[0].([32]byte)
		if len(t.Backs[aid]) == 0 {
			return pack(a, "assignmentExposures", [][32]byte{}), nil
		}
		return pack(a, "assignmentExposures", [][32]byte{aid}), nil
	case "exposureLots":
		lots := t.Backs[in[0].([32]byte)]
		if lots == nil {
			lots = []*big.Int{}
		}
		return pack(a, "exposureLots", lots), nil
	case "anchorTerm":
		aid := in[0].([32]byte)
		if !t.Closed[aid] || t.Anchored[aid] {
			return nil, &rpcError{Code: 3, Message: "execution reverted: TermNotPending"}
		}
		if t.NotReady[aid] {
			return nil, &rpcError{Code: 3, Message: "execution reverted: SuccessorNotInstalled"}
		}
		if write && t.Race[aid] {
			// another party's anchor lands first: the term is anchored, this transaction reverts
			t.Anchored[aid] = true
			for _, lot := range append(append([]*big.Int{}, t.Backs[aid]...), t.Seats[aid]...) {
				if n := t.Unanchored[lot.String()]; n > 0 {
					t.Unanchored[lot.String()] = n - 1
				}
			}
			return nil, &rpcError{Code: 3, Message: "execution reverted: TermNotPending"}
		}
		if write {
			t.Anchored[aid] = true
			t.Anchors++
			for _, lot := range append(append([]*big.Int{}, t.Backs[aid]...), t.Seats[aid]...) {
				if n := t.Unanchored[lot.String()]; n > 0 {
					t.Unanchored[lot.String()] = n - 1
				}
			}
		}
	}
	return nil, nil
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
		if to != c.Registry && to != c.Module && to != c.Seal && to != c.Governor {
			return nil, nil // a call to an account with no code succeeds and does nothing
		}
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	var a abi.ABI
	switch to {
	case c.Registry:
		a = vrclient.VRABI
	case c.Module:
		a = vrclient.PoaABI
	case c.Governor:
		return c.multisig(from, data, write)
	case c.Seal:
		switch {
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("progress()"))[:4]):
			return u64word(c.Progress), nil
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("ucTime()"))[:4]):
			return u64word(c.UcTime), nil
		case bytes.Equal(data[:4], ethcrypto.Keccak256([]byte("recordCount()"))[:4]):
			if c.Terms != nil {
				return u64word(uint64(len(c.Terms.Closures))), nil
			}
			return u64word(c.RecordCount), nil
		case c.Terms != nil && bytes.Equal(data[:4], vrclient.SealRecordsABI.Methods["recordAt"].ID):
			in, err := vrclient.SealRecordsABI.Methods["recordAt"].Inputs.Unpack(data[4:])
			if err != nil || in[0].(uint64) >= uint64(len(c.Terms.Closures)) {
				return nil, &rpcError{Code: 3, Message: "execution reverted"}
			}
			return pack(vrclient.SealRecordsABI, "recordAt", c.Terms.record(in[0].(uint64))), nil
		}
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	case c.Custody:
		if c.Custody == (ethcommon.Address{}) {
			return nil, nil
		}
		return c.custody(from, data, write)
	case c.Evidence:
		if c.Evidence == (ethcommon.Address{}) || c.Pos == nil {
			return nil, nil
		}
		return c.evidence(data)
	case c.Election:
		if c.Election != (ethcommon.Address{}) && c.Pos != nil {
			return c.election(from, data, write)
		}
		if c.Election != (ethcommon.Address{}) && bytes.Equal(data[:4], vrclient.PosPublishABI.Methods["openResult"].ID) {
			return pack(vrclient.PosPublishABI, "openResult", [32]byte{}), nil
		}
		return nil, nil
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

func (c *Chain) custody(from ethcommon.Address, data []byte, write bool) ([]byte, *rpcError) {
	a := vrclient.CustodyABI
	m, err := a.MethodById(data[:4])
	if err != nil {
		return c.terms(from, data, write)
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	switch m.Name {
	case "election":
		return pack(a, "election", c.Election), nil
	case "evidence":
		return pack(a, "evidence", c.Evidence), nil
	case "network":
		return pack(a, "network", c.Network), nil
	case "bondUnit":
		return pack(a, "bondUnit", big.NewInt(1e18)), nil
	case "registerNonce":
		return pack(a, "registerNonce", uint64(0)), nil
	case "positions":
		if c.Pos != nil {
			return c.position(in[0].(uint64)), nil
		}
		identity := c.Identities[in[0].(uint64)]
		if identity == nil {
			identity = &Identity{}
		}
		return pack(a, "positions", identity.Owner, identity.Owner, [32]byte{}, [32]byte{}, identity.Generation,
			uint64(0), uint32(len(c.ClaimLots)), uint32(len(c.ClaimLots)), true), nil
	case "register":
		if c.Pos != nil {
			return c.registerCustody(from, in, write)
		}
	case "bond":
		// A retired generation opens the next one only after every old lot is closed.
		if p := c.posOf(in[0].(uint64)); p != nil {
			if p.RetirementRequested && p.OpenLots != 0 {
				return nil, revert(vrclient.PosErrorsABI, "GenerationClosing")
			}
			if write {
				if p.RetirementRequested {
					p.Generation++
					p.RetirementRequested = false
					p.LotCount = 0
				}
				p.LotCount = max(p.LotCount, p.OpenLots) + 1
				p.OpenLots++
				c.Pos.Order = append(c.Pos.Order, "bond")
			}
		}
	case "generationLots":
		return pack(a, "generationLots", c.ClaimLots), nil
	case "credit":
		credit := c.ClaimCredit
		if credit == nil {
			credit = new(big.Int)
		}
		return pack(a, "credit", credit), nil
	case "mature":
		if c.Terms != nil {
			for _, lot := range c.ClaimLots {
				if c.Terms.Unanchored[lot.String()] != 0 {
					return nil, &rpcError{Code: 3, Message: "execution reverted: TermAnchorPending"}
				}
			}
		}
		if write {
			c.ClaimLots = nil
			c.ClaimCredit = big.NewInt(100)
		}
	case "claim":
		amount, recipient := in[0].(*big.Int), in[1].(ethcommon.Address)
		if c.ClaimCredit == nil || amount.Sign() <= 0 || amount.Cmp(c.ClaimCredit) > 0 {
			return nil, &rpcError{Code: 3, Message: "execution reverted"}
		}
		if write {
			c.ClaimCredit.Sub(c.ClaimCredit, amount)
			topic := ethcrypto.Keccak256Hash([]byte("CreditClaimed(address,address,uint256)"))
			c.Logs = append(c.Logs, map[string]any{"address": c.Custody, "topics": []ethcommon.Hash{
				topic, ethcommon.BytesToHash(from[:]), ethcommon.BytesToHash(recipient[:]),
			}, "data": hexutil.Bytes(amount.FillBytes(make([]byte, 32)))})
		}
	}
	return nil, nil
}

func (c *Chain) posOf(id uint64) *Position {
	if c.Pos == nil {
		return nil
	}
	return c.Pos.Positions[id]
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
		return pack(a, method, vrclient.ModuleView{Module: c.Module, Health: c.Health, Meta: vrclient.ModuleMeta{ModuleTag: c.Tag, LiabilityHolder: c.Custody}}), nil
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
		if c.FailActivations {
			return nil, &rpcError{Code: -32603, Message: "activation schedule unavailable"}
		}
		return pack(a, method, uint32(0)), nil
	case "recordCursor":
		return pack(a, method, c.RecordCursor), nil
	case "queue", "execute", "cancel":
		return c.governance(from, method, in, write)
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
