package vrfake

import (
	"bytes"
	"math/big"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/vrclient"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The Foundation side of the model: the FoundationMultisig at Governor (EIP-712 approvals by three of five signers, a sequential nonce,
// an approved call that reverts reverts the execution), and VR's queue, cancel and execute with the delays measured on the model's
// clock (Progress, UcTime). A ModuleAction executes into the PoA model with its guards; a refused action is an ActionRefused log and no
// transition (the change is still Active), as in PoaElection. Other kinds become Scheduled; the boundary and the roots are not modelled.
// Queue refusals use the code of the failing check where the model knows it and RANGE (8) otherwise.

// SetSigners sets the multisig's signers (sorted ascending).
func (c *Chain) SetSigners(addrs [5]ethcommon.Address) {
	c.Mu.Lock()
	defer c.Mu.Unlock()
	s := addrs
	for i := range s {
		for j := i + 1; j < len(s); j++ {
			if bytes.Compare(s[j][:], s[i][:]) < 0 {
				s[i], s[j] = s[j], s[i]
			}
		}
	}
	c.Signers = s
}

func (c *Chain) isSigner(a ethcommon.Address) bool {
	for _, s := range c.Signers {
		if s == a {
			return true
		}
	}
	return false
}

func (c *Chain) multisig(from ethcommon.Address, data []byte, write bool) ([]byte, *rpcError) {
	m, err := vrclient.MultisigABI.MethodById(data[:4])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	in, err := m.Inputs.Unpack(data[4:])
	if err != nil {
		return nil, &rpcError{Code: 3, Message: "execution reverted"}
	}
	a := vrclient.MultisigABI
	switch m.Name {
	case "nonce":
		return pack(a, m.Name, c.MsigNonce), nil
	case "signers":
		return pack(a, m.Name, c.Signers), nil
	case "nextSigners":
		return pack(a, m.Name, [5]ethcommon.Address{}), nil
	case "signersPending":
		return pack(a, m.Name, false), nil
	case "nextNotBeforeProgress", "nextNotBeforeTime":
		return pack(a, m.Name, uint64(0)), nil
	case "isSigner":
		return pack(a, m.Name, c.isSigner(in[0].(ethcommon.Address))), nil
	case "callDigest":
		d, _ := vrclient.CallDigest(c.ChainID, c.Governor, in[0].(ethcommon.Address), in[1].([]byte), in[2].(uint64))
		return pack(a, m.Name, d), nil
	case "execute":
		target, payload, sigs := in[0].(ethcommon.Address), in[1].([]byte), in[2].([][]byte)
		if target == (ethcommon.Address{}) {
			return nil, revert(a, "CallFailed")
		}
		digest, _ := vrclient.CallDigest(c.ChainID, c.Governor, target, payload, c.MsigNonce)
		if len(sigs) < vrclient.MultisigThreshold {
			return nil, revert(a, "BadSignatures")
		}
		var last ethcommon.Address
		for _, sg := range sigs {
			who, err := vrclient.RecoverSigner(digest, sg)
			if err != nil || bytes.Compare(who[:], last[:]) <= 0 || !c.isSigner(who) {
				return nil, revert(a, "BadSignatures")
			}
			last = who
		}
		var snapshot *Chain
		if write {
			snapshot = c.snapshotGov()
			c.MsigNonce++
		}
		_, rerr := c.exec(c.Governor, target, payload, write)
		if rerr != nil {
			if snapshot != nil {
				c.restoreGov(snapshot)
			}
			return nil, revert(a, "CallFailed")
		}
		return nil, nil
	}
	return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + m.Name + " not modelled)"}
}

// snapshotGov and restoreGov undo a failed approved call (the contract's call reverts as a whole).
func (c *Chain) snapshotGov() *Chain {
	cp := &Chain{MsigNonce: c.MsigNonce, NextChangeID: c.NextChangeID, Pending: append([]uint64(nil), c.Pending...),
		Changes: map[uint64]vrclient.ChangeView{}, Poa: map[uint64][2]uint64{}, Logs: append([]map[string]any(nil), c.Logs...)}
	for k, v := range c.Changes {
		cp.Changes[k] = v
	}
	for k, v := range c.Poa {
		cp.Poa[k] = v
	}
	return cp
}

func (c *Chain) restoreGov(s *Chain) {
	c.MsigNonce, c.NextChangeID, c.Pending, c.Changes, c.Poa, c.Logs = s.MsigNonce, s.NextChangeID, s.Pending, s.Changes, s.Poa, s.Logs
}

func (c *Chain) logAt(addr ethcommon.Address, abiEvent string, topics []ethcommon.Hash, data []byte) {
	var id ethcommon.Hash
	if abiEvent == "ActionRefused" {
		id = vrclient.PoaABI.Events[abiEvent].ID
	} else {
		id = vrclient.VRABI.Events[abiEvent].ID
	}
	c.Logs = append(c.Logs, map[string]any{"address": addr, "topics": append([]ethcommon.Hash{id}, topics...), "data": hexutil.Bytes(data)})
}

func queueCode(err error) uint8 {
	switch {
	case err == nil:
		return 0
	case errIs(err, vrschema.ErrUnknownKind):
		return 1
	case errIs(err, vrschema.ErrOversize):
		return 3
	case errIs(err, vrschema.ErrLength):
		return 4
	}
	return 8
}

func errIs(err, target error) bool {
	for e := err; e != nil; {
		if e == target {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

func (c *Chain) governance(from ethcommon.Address, method string, in []any, write bool) ([]byte, *rpcError) {
	a := vrclient.VRABI
	switch method {
	case "queue":
		if from != c.Governor {
			return nil, revert(a, "NotGovernor")
		}
		kind, payload := in[0].(uint8), in[1].([]byte)
		env := vrschema.QueueEnv{KnownRootEpoch: c.Config.KnownRootEpoch, UCTime: c.UcTime, Pending: len(c.Pending), Committee: c.Committee,
			MaxGas: c.Config.MaxGas, SystemGas: c.Config.SystemGas}
		for _, id := range c.Pending {
			if c.Changes[id].Kind == vrclient.KindForceRemove {
				env.PendingForce++
			}
		}
		if err := vrschema.QueueCheck(kind, payload, env); err != nil {
			code := queueCode(err)
			switch err.Error() {
			case "TooManyPending":
				code = 2
			case "NotInCommittee":
				code = 16
			case "TooManyForceRemoves":
				code = 17
			}
			return nil, revert(a, "QueueRefused", code)
		}
		id := c.NextChangeID
		if write {
			c.NextChangeID++
			ch := vrclient.ChangeView{Kind: kind, State: vrclient.ChangeQueued, NotBeforeProgress: c.Progress + c.Config.DelayRounds,
				NotBeforeTime: c.UcTime + c.Config.DelaySeconds, PayloadHash: ethcrypto.Keccak256Hash(payload), Payload: append([]byte(nil), payload...)}
			c.Changes[id] = ch
			c.Pending = append(c.Pending, id)
			ev := vrclient.VRABI.Events["ChangeQueued"]
			d, err := ev.Inputs.NonIndexed().Pack(ch.PayloadHash, ch.NotBeforeProgress, ch.NotBeforeTime)
			if err != nil {
				panic(err)
			}
			c.logAt(c.Registry, "ChangeQueued", []ethcommon.Hash{idTopic(id), ethcommon.BigToHash(big.NewInt(int64(kind)))}, d)
		}
		return pack(a, method, id), nil
	case "cancel":
		if from != c.Governor {
			return nil, revert(a, "NotGovernor")
		}
		id := in[0].(uint64)
		ch := c.Changes[id]
		if ch.State != vrclient.ChangeQueued && ch.State != vrclient.ChangeScheduled {
			return nil, revert(a, "NotCancellable")
		}
		if write {
			ch.State = vrclient.ChangeCancelled
			c.Changes[id] = ch
			c.dropPending(id)
			c.logAt(c.Registry, "ChangeCancelled", []ethcommon.Hash{idTopic(id)}, nil)
		}
		return nil, nil
	case "execute":
		id := in[0].(uint64)
		ch := c.Changes[id]
		if ch.State != vrclient.ChangeQueued {
			return nil, revert(a, "PreconditionFailed")
		}
		if c.Progress < ch.NotBeforeProgress || c.UcTime < ch.NotBeforeTime {
			return nil, revert(a, "DelayNotElapsed")
		}
		if !write {
			return nil, nil
		}
		if ch.Kind != vrclient.KindModuleAction {
			ch.State, ch.ScheduledAt = vrclient.ChangeScheduled, c.Progress
			c.Changes[id] = ch
			ev := vrclient.VRABI.Events["ChangeScheduled"]
			d, _ := ev.Inputs.NonIndexed().Pack(c.Progress)
			c.logAt(c.Registry, "ChangeScheduled", []ethcommon.Hash{idTopic(id)}, d)
			return nil, nil
		}
		ma, _ := vrclient.DecodeModuleAction(ch.Payload)
		if ma.Module != c.Module {
			ch.State, ch.RejectReason = vrclient.ChangeRejected, 20
		} else {
			c.govern(ma.Action, ma.ID)
			ch.State = vrclient.ChangeActive
		}
		c.Changes[id] = ch
		c.dropPending(id)
		ev := vrclient.VRABI.Events["ModuleActionExecuted"]
		d, _ := ev.Inputs.NonIndexed().Pack(ch.State)
		c.logAt(c.Registry, "ModuleActionExecuted", []ethcommon.Hash{idTopic(id)}, d)
		return nil, nil
	}
	return nil, &rpcError{Code: 3, Message: "execution reverted (vrfake: " + method + " not modelled)"}
}

func (c *Chain) dropPending(id uint64) {
	out := c.Pending[:0]
	for _, p := range c.Pending {
		if p != id {
			out = append(out, p)
		}
	}
	c.Pending = out
}

// govern is PoaElection.onGovernance (the guards of design 3.7.1; a refusal is an ActionRefused log, not a revert).
func (c *Chain) govern(action, id uint64) {
	s := uint8(c.Poa[id][0])
	set := func(to uint8) { c.Poa[id] = [2]uint64{uint64(to), c.Progress} }
	refuse := func(reason uint8) {
		d, _ := vrclient.PoaABI.Events["ActionRefused"].Inputs.NonIndexed().Pack(new(big.Int).SetUint64(action), new(big.Int).SetUint64(id), reason)
		c.logAt(c.Module, "ActionRefused", nil, d)
	}
	switch action {
	case vrclient.ActionAdmit:
		if s != vrclient.PoaApplied {
			refuse(1)
			return
		}
		set(vrclient.PoaAdmitted)
	case vrclient.ActionRemove:
		if s == vrclient.PoaNone || s == vrclient.PoaExited {
			refuse(1)
			return
		}
		set(vrclient.PoaRemoving)
	case vrclient.ActionConfirmExit:
		if s != vrclient.PoaExitRequested {
			refuse(1)
			return
		}
		set(vrclient.PoaRemoving)
	default:
		refuse(2)
	}
}
