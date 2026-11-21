package nb2ref

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/stretchr/testify/require"
)

var recoveryFixtureEmitter = [20]byte{0xa1, 0x08}

type recoveryOpening struct {
	frame RecoveryFrame
	tail  [32]byte
}

// recoveryWallet obtains openings from the evidence, never passes uncommitted
// semantic data, and can rebuild its side of the sparse set from the transcript.
type recoveryWallet struct {
	e     *RecoveryEvidence
	stack map[[32]byte]recoveryOpening
	seen  RecoverySeen
	ids   [][32]byte
}

func (w *recoveryWallet) input(s RecoveryState) (RecoveryInput, [32]byte, error) {
	var in RecoveryInput
	var sid [32]byte
	window := func(start, end uint64) error {
		if start >= end {
			return ErrRecoveryWitness
		}
		x, err := w.e.Window(start, end)
		if err == nil {
			in.Windows = append(in.Windows, x)
		}
		return err
	}
	f := s.Frame
	raw := w.e.raw
	switch s.Phase {
	case RecoveryDiscover:
		start := f.Start
		if start == 2 && s.Stack == ([32]byte{}) {
			start = 0
		}
		// Save the opening from the authenticated token header.
		sc := scanner{b: raw[f.Start:f.End]}
		if err := recoveryTokenPrefix(&sc); err != nil {
			return in, sid, err
		}
		f.Mint = f.Start + uint64(sc.pos)
		_, j, end, err := recoveryMintPrefix(&sc, f.Start, f.End)
		if err != nil {
			// Still submit the malformed header to both verifiers.
			return in, sid, window(start, min(f.End, start+256))
		}
		f.Just, f.JustEnd = j, end
		w.stack[f.push(s.Stack)] = recoveryOpening{f, s.Stack}
		return in, sid, window(start, min(f.End, j+32))
	case RecoveryPrepare:
		if err := window(f.Mint, f.Just); err != nil {
			return in, sid, err
		}
		return in, sid, window(f.JustEnd, min(f.End, f.JustEnd+256))
	case RecoveryHashMint:
		return in, sid, window(s.Pos, min(s.MintEnd, s.Pos+RecoveryHashBytes))
	case RecoveryMint:
		sc := scanner{b: raw[s.MintEnd:f.End], native: true}
		if _, err := sc.item(0); err != nil {
			return in, sid, err
		}
		if _, _, err := sc.head(); err != nil {
			return in, sid, err
		}
		end := s.MintEnd + uint64(sc.pos)
		if s.SplitProof == 0 {
			if err := window(f.Mint, end); err != nil {
				return in, sid, err
			}
		} else {
			if err := window(f.Mint, f.Just); err != nil {
				return in, sid, err
			}
			if err := window(s.SplitProof, end); err != nil {
				return in, sid, err
			}
		}
		mint, _, err := recoveryMint(in, f, false)
		if err != nil {
			return in, sid, err
		}
		id := TokenID(mint.Salt, mint.Network)
		key, err := MinterKey(id)
		if err != nil {
			return in, sid, err
		}
		sid = StateID(sigPred(key), MintSourceHash(id))
	case RecoveryTransfer:
		sc := scanner{b: raw[s.Pos:f.End], native: true}
		end := f.End
		if _, err := sc.item(0); err == nil {
			end = s.Pos + uint64(sc.pos)
		}
		if err := window(s.Pos, end); err != nil {
			return in, sid, err
		}
		sid = StateID(SignaturePredicate(s.Owner[:]), s.State)
	case RecoveryUnwind:
		f := w.stack[s.Stack]
		in.Frame, in.Tail = f.frame, f.tail
		return in, sid, window(s.Pos, f.frame.JustEnd)
	default:
		return in, sid, ErrRecoveryState
	}
	in.Seen = w.seen.Witness(sid)
	return in, sid, nil
}

func recoveryScenario(t *testing.T, transfers, depth int, rotated bool, quorum ...int) (*World, []byte, int) {
	t.Helper()
	w, err := NewWorld(4, 2, 1)
	require.NoError(t, err)
	if len(quorum) != 0 {
		recoveryFourMemberWorld(t, w, quorum[0])
	}
	owner := Key("axis-b")
	dep, err := w.MakeDeposit(big.NewInt(100), owner, ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 2})
	require.NoError(t, err)
	d := w.RootDraft(dep, []*secp256k1.PrivateKey{owner})
	d.Cert = make(map[int]CertOpts)
	for i := range transfers {
		key := Key(fmt.Sprintf("axis-b-owner-%d", i%4))
		d.Transfer(sigPred(key), key)
		opts := CertOpts{IRTime: DevTime + 10000}
		if rotated && i >= transfers/2 {
			opts.Committee = w.Roots[1]
			opts.Seal = &SealOpts{Network: DevNetwork, Epoch: 2, RootRound: RotationRound + uint64(i) + 1}
		}
		d.Cert[i+1] = opts
	}
	amount := int64(100)
	for i := range depth {
		if d.Cert == nil {
			d.Cert = make(map[int]CertOpts)
		}
		d.Cert[len(d.Transfers)+1] = CertOpts{IRTime: DevTime + 10000}
		owner := Key(fmt.Sprintf("axis-b-child-%d", i))
		_, kids, err := w.Split(d, []SplitOut{
			{Amount: big.NewInt(amount - 1), Owner: owner}, {Amount: big.NewInt(1), Owner: Key("axis-b-sibling")},
		}, SplitOpts{})
		require.NoError(t, err)
		d = kids[0]
		amount--
	}
	if d.Cert == nil {
		d.Cert = make(map[int]CertOpts)
	}
	d.Return(w.ReturnTo(big.NewInt(amount), Recipient20("axis-b-payout"), 42))
	if rotated {
		d.Cert[len(d.Transfers)] = CertOpts{IRTime: DevTime + 10000, Committee: w.Roots[1], Seal: &SealOpts{Network: DevNetwork, Epoch: 2, RootRound: RotationRound + 600}}
	}
	part, err := w.Finalize(d)
	require.NoError(t, err)
	return w, Evidence(part.Bytes()), len(part.mintRaw)
}

func recoveryFourMemberWorld(t *testing.T, w *World, signers int) {
	t.Helper()
	var err error
	w.Roots[0], err = NewCommittee("root-1", 4)
	require.NoError(t, err)
	w.Roots[1], err = NewCommittee("root-2", 4)
	require.NoError(t, err)
	w.Entries[0], err = w.Roots[0].Genesis(DevNetwork, 1, 1)
	require.NoError(t, err)
	w.Entries[1], err = w.Roots[0].Successor(w.Entries[0], w.Roots[1], RotationRound)
	require.NoError(t, err)
	bundle, err := TrustBundle(w.Entries...)
	require.NoError(t, err)
	id, err := w.Entries[0].EntryID()
	require.NoError(t, err)
	w.Trust, err = LoadTrustInput(bundle, id)
	require.NoError(t, err)
	w.Cfg.RootGenesis = id
	w.Cfg.Ty = DeriveType(w.Cfg.Network, id, w.Cfg.ExecutionGenesis, w.Cfg.ChainID)
	w.Cfg.Aid = DeriveCoin(w.Cfg.Network, id, w.Cfg.ExecutionGenesis, w.Cfg.ChainID)
	w.Gamma = w.Cfg.Bytes()
	w.Agg.Committee = w.Roots[0]
	for _, committee := range w.Roots {
		committee.Signers = signers
	}
}

func TestRecoveryQuorumTrimming(t *testing.T) {
	var full []byte
	for _, signers := range []int{4, 3} {
		name := fmt.Sprintf("quorum-%d", signers)
		t.Run(name, func(t *testing.T) {
			w, raw, _ := recoveryScenario(t, 64, 4, true, signers)
			want, err := VerifyReturn(w.Gamma, raw, w.Trust, w.Params)
			require.NoError(t, err)
			calls, got, err := walkRecovery(t, w, raw, true)
			require.NoError(t, err)
			require.Equal(t, want.ABI(), got.ABI())
			if signers == 4 {
				full = want.ABI()
			} else {
				// Trimming was applied before signing nested mints. Confirm
				// the authenticated payout fields agree on both encodings.
				require.Equal(t, full, want.ABI())
			}
			t.Logf("signers=%d evidence=%d calls=%d", signers, len(raw), len(calls))
			exportRecovery(t, name, w, raw, calls, want)
		})
	}
}

type recoveryCall struct {
	prior    RecoveryState
	in       RecoveryInput
	receipt  *DepositProof
	expected RecoveryState
	verdict  *Verdict
	err      error
}

// walkRecovery carries only the immediately preceding certified receipt. At
// restart it rebuilds wallets' openings and reopens the JSON-serialized state.
func walkRecovery(t *testing.T, w *World, raw []byte, restart bool) ([]recoveryCall, *Verdict, error) {
	t.Helper()
	e, err := NewRecoveryEvidence(raw)
	require.NoError(t, err)
	v, err := NewRecovery(w.Gamma, w.Trust, w.Params, recoveryFixtureEmitter, e.Root(), e.Length())
	require.NoError(t, err)
	wallet := recoveryWallet{e: e, stack: make(map[[32]byte]recoveryOpening)}
	s := RecoveryState{Phase: RecoveryDiscover, Frame: RecoveryFrame{Start: 2, End: e.Length()}}
	var transcript []recoveryCall
	var receipt *DepositProof
	var restarted bool
	for len(transcript) < 10000 {
		in, sid, err := wallet.input(s)
		if err != nil {
			return transcript, nil, err
		}
		var next RecoveryState
		var verdict *Verdict
		if len(transcript) == 0 {
			next, verdict, err = v.Start(in)
		} else {
			next, verdict, err = v.Advance(s, receipt, in)
		}
		transcript = append(transcript, recoveryCall{s, in, receipt, next, verdict, err})
		if err != nil || verdict != nil {
			return transcript, verdict, err
		}
		if s.Phase == RecoveryMint || s.Phase == RecoveryTransfer {
			wallet.seen.Insert(sid)
			wallet.ids = append(wallet.ids, sid)
		}
		s = next
		receipt, err = w.ReceiptProof(v.ProgressLog(s), ReceiptOpts{Type: 2, TxIndex: 3, FillerLogs: 2, Rotated: len(transcript)%3 == 0})
		require.NoError(t, err)
		if restart && !restarted && len(wallet.ids) == 4 {
			start := time.Now()
			journal, err := json.Marshal(s)
			require.NoError(t, err)
			s = RecoveryState{}
			require.NoError(t, json.Unmarshal(journal, &s))
			wallet.seen = RecoverySeen{}
			for _, key := range wallet.ids {
				wallet.seen.Insert(key)
			}
			wallet.stack = make(map[[32]byte]recoveryOpening)
			for _, old := range transcript {
				if old.prior.Phase == RecoveryDiscover {
					_, _, err = wallet.input(old.prior)
					require.NoError(t, err)
				}
			}
			wallet.e, err = NewRecoveryEvidence(raw)
			require.NoError(t, err)
			v, err = NewRecovery(w.Gamma, w.Trust, w.Params, recoveryFixtureEmitter, e.Root(), e.Length())
			require.NoError(t, err)
			restarted = true
			t.Logf("restart: %d-byte state, %d consumed source IDs, %s", len(journal), len(wallet.ids), time.Since(start))
		}
	}
	t.Fatal("recovery did not finish")
	return nil, nil, nil
}

func TestRecoveryDifferential(t *testing.T) {
	for _, tc := range []struct {
		name             string
		transfers, depth int
		rotated          bool
	}{
		{"short", 2, 0, false},
		{"epoch-rotation", 12, 1, true},
		{"deep-split", 0, 20, true},
		{"ordinary-envelope-exceeded", 600, 0, true},
		{"oversized-child-mint", 600, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w, evidence, mintSize := recoveryScenario(t, tc.transfers, tc.depth, tc.rotated)
			expected, err := VerifyReturn(w.Gamma, evidence, w.Trust, w.Params)
			require.NoError(t, err)
			steps, actual, err := walkRecovery(t, w, evidence, true)
			require.NoError(t, err)
			require.Equal(t, expected.ABI(), actual.ABI())
			if tc.transfers == 600 {
				require.Greater(t, len(evidence), 512<<10)
				if tc.depth != 0 {
					require.Greater(t, mintSize, 512<<10)
				}
			}
			t.Logf("evidence=%d signed-terminal-mint=%d calls=%d", len(evidence), mintSize, len(steps))
			exportRecovery(t, tc.name, w, evidence, steps, expected)
		})
	}
}

func TestRecoveryRejectsInvalidLineage(t *testing.T) {
	t.Run("repeated-source", func(t *testing.T) {
		w, err := NewWorld(4, 2, 1)
		require.NoError(t, err)
		ev, err := repeatedSID(w)
		require.NoError(t, err)
		_, err = VerifyReturn(w.Gamma, ev[1], w.Trust, w.Params)
		require.ErrorIs(t, err, ErrRepeatedSID)
		steps, actual, err := walkRecovery(t, w, ev[1], false)
		require.ErrorIs(t, err, ErrRepeatedSID)
		require.Nil(t, actual)
		exportRecovery(t, "repeated-source", w, ev[1], steps, nil)
	})
	t.Run("malformed-nested-length", func(t *testing.T) {
		w, evidence, _ := recoveryScenario(t, 3, 1, false)
		part, err := decodeEvidence(evidence)
		require.NoError(t, err)
		broken := bytes.Clone(part.Mint.Justification)
		broken[3] = 0x83 // incorrectly claims a third item in the split justification
		i := bytes.Index(evidence, part.Mint.Justification)
		require.Greater(t, i, 0)
		copy(evidence[i:], broken)
		_, err = VerifyReturn(w.Gamma, evidence, w.Trust, w.Params)
		require.ErrorIs(t, err, ErrSplitJustif)
		steps, actual, err := walkRecovery(t, w, evidence, false)
		require.ErrorIs(t, err, ErrSplitJustif)
		require.Nil(t, actual)
		exportRecovery(t, "malformed-nested-length", w, evidence, steps, nil)
	})
	t.Run("incomplete", func(t *testing.T) {
		w, evidence, _ := recoveryScenario(t, 3, 1, false)
		evidence = evidence[:len(evidence)-1]
		_, err := VerifyReturn(w.Gamma, evidence, w.Trust, w.Params)
		require.Error(t, err)
		steps, actual, err := walkRecovery(t, w, evidence, false)
		require.Error(t, err)
		require.Nil(t, actual)
		require.NotEmpty(t, steps)
		exportRecovery(t, "incomplete", w, evidence, steps, nil)
	})
}

func TestRecoveryRejectsForeignOrAlteredProgress(t *testing.T) {
	w, evidence, _ := recoveryScenario(t, 3, 1, true)
	e, err := NewRecoveryEvidence(evidence)
	require.NoError(t, err)
	v, err := NewRecovery(w.Gamma, w.Trust, w.Params, recoveryFixtureEmitter, e.Root(), e.Length())
	require.NoError(t, err)
	wallet := recoveryWallet{e: e, stack: make(map[[32]byte]recoveryOpening)}
	in, _, err := wallet.input(RecoveryState{Phase: RecoveryDiscover, Frame: RecoveryFrame{Start: 2, End: e.Length()}})
	require.NoError(t, err)
	s, _, err := v.Start(in)
	require.NoError(t, err)
	in, _, err = wallet.input(s)
	require.NoError(t, err)
	receipt, err := w.ReceiptProof(v.ProgressLog(s), ReceiptOpts{Type: 2, TxIndex: 3})
	require.NoError(t, err)
	tampered := s
	tampered.Pos++
	_, _, err = v.Advance(tampered, receipt, in)
	require.ErrorIs(t, err, ErrRecoveryState)
	foreign, err := w.ReceiptProof(v.ProgressLog(s), ReceiptOpts{MutLog: func(l *RawLog) { l.Address[0] ^= 1 }})
	require.NoError(t, err)
	_, _, err = v.Advance(s, foreign, in)
	require.ErrorIs(t, err, ErrLogEmitter)
	foreign, err = w.ReceiptProof(v.ProgressLog(s), ReceiptOpts{MutLog: func(l *RawLog) { l.Topics[1][0] ^= 1 }})
	require.NoError(t, err)
	_, _, err = v.Advance(s, foreign, in)
	require.ErrorIs(t, err, ErrRecoveryState)
	in.Windows[0].Data[0] ^= 1
	_, _, err = v.Advance(s, receipt, in)
	require.ErrorIs(t, err, ErrRecoveryWitness)
}

const recoveryTestABI = `[
{"name":"start","type":"function","inputs":[{"name":"gamma","type":"bytes"},{"name":"root","type":"bytes32"},{"name":"length","type":"uint64"},{"name":"input","type":"tuple","components":INPUT}]},
{"name":"resume","type":"function","inputs":[{"name":"gamma","type":"bytes"},{"name":"root","type":"bytes32"},{"name":"length","type":"uint64"},{"name":"prior","type":"tuple","components":STATE},{"name":"receipt","type":"bytes"},{"name":"input","type":"tuple","components":INPUT}]}
]`
const recoveryTestFrame = `[{"name":"start","type":"uint64"},{"name":"end","type":"uint64"},{"name":"mint","type":"uint64"},{"name":"just","type":"uint64"},{"name":"justEnd","type":"uint64"}]`
const recoveryTestInput = `[{"name":"windows","type":"tuple[]","components":[{"name":"start","type":"uint64"},{"name":"data","type":"bytes"},{"name":"paths","type":"bytes32[][]"}]},{"name":"frame","type":"tuple","components":FRAME},{"name":"tail","type":"bytes32"},{"name":"seenBitmap","type":"uint256"},{"name":"siblings","type":"bytes32[]"}]`
const recoveryTestState = `[{"name":"phase","type":"uint8"},{"name":"frame","type":"tuple","components":FRAME},{"name":"stack","type":"bytes32"},{"name":"seen","type":"bytes32"},{"name":"pos","type":"uint64"},{"name":"mintEnd","type":"uint64"},{"name":"left","type":"uint64"},{"name":"splitProof","type":"uint64"},{"name":"hash","type":"bytes32"},{"name":"owner","type":"bytes32"},{"name":"ownerTail","type":"bytes1"},{"name":"state","type":"bytes32"},{"name":"id","type":"bytes32"},{"name":"amount","type":"uint256"},{"name":"parentID","type":"bytes32"},{"name":"parentAmount","type":"uint256"},{"name":"parentManifest","type":"bytes32"}]`

type recoveryABIState struct {
	Phase                          uint8
	Frame                          RecoveryFrame
	Stack, Seen                    [32]byte
	Pos, MintEnd, Left, SplitProof uint64
	Hash, Owner                    [32]byte
	OwnerTail                      [1]byte
	State, Id                      [32]byte
	Amount                         *big.Int
	ParentID                       [32]byte `abi:"parentID"`
	ParentAmount                   *big.Int
	ParentManifest                 [32]byte
}

func recoveryTrustFixture(t *testing.T, w *World) []byte {
	t.Helper()
	trust := struct {
		Network      uint16   `json:"network"`
		Epochs       []uint64 `json:"epochs"`
		Starts       []uint64 `json:"starts"`
		Ends         []uint64 `json:"ends"`
		Totals       []uint64 `json:"totals"`
		MemberEpochs []uint64 `json:"memberEpochs"`
		MemberIDs    []string `json:"memberIds"`
		MemberKeys   []string `json:"memberKeys"`
	}{Network: w.Cfg.Network}
	for i, entry := range w.Entries {
		var end, total uint64
		if i+1 < len(w.Entries) {
			end = w.Entries[i+1].EpochStart
		}
		trust.Epochs = append(trust.Epochs, entry.Epoch)
		trust.Starts = append(trust.Starts, entry.EpochStart)
		trust.Ends = append(trust.Ends, end)
		for _, m := range entry.RootNodes {
			trust.MemberEpochs = append(trust.MemberEpochs, entry.Epoch)
			trust.MemberIDs = append(trust.MemberIDs, fmt.Sprintf("0x%x", m.NodeID))
			trust.MemberKeys = append(trust.MemberKeys, fmt.Sprintf("0x%x", m.SigKey))
			total += m.Stake
		}
		trust.Totals = append(trust.Totals, total)
	}
	j, err := json.Marshal(trust)
	require.NoError(t, err)
	return j
}

func exportRecovery(t *testing.T, name string, w *World, ev []byte, transcript []recoveryCall, verdict *Verdict) {
	t.Helper()
	dir := os.Getenv("NB2_RECOVERY_FIXTURES")
	if dir == "" {
		return
	}
	require.NoError(t, os.MkdirAll(dir, 0700))
	sig := recoveryTestABI
	for _, sub := range [][2]string{{"INPUT", recoveryTestInput}, {"STATE", recoveryTestState}, {"FRAME", recoveryTestFrame}} {
		sig = string(bytes.ReplaceAll([]byte(sig), []byte(sub[0]), []byte(sub[1])))
	}
	a, err := abi.JSON(bytes.NewBufferString(sig))
	require.NoError(t, err)
	e, err := NewRecoveryEvidence(ev)
	require.NoError(t, err)
	v, err := NewRecovery(w.Gamma, w.Trust, w.Params, recoveryFixtureEmitter, e.Root(), e.Length())
	require.NoError(t, err)
	out, err := os.Create(filepath.Join(dir, name+".bin"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, out.Close()) })
	put := func(b []byte) {
		t.Helper()
		_, err := out.Write(binary.BigEndian.AppendUint32(nil, uint32(len(b))))
		require.NoError(t, err)
		_, err = out.Write(b)
		require.NoError(t, err)
	}
	put(recoveryTrustFixture(t, w))
	put(w.Gamma)
	put(ev)
	if verdict == nil {
		put(nil)
	} else {
		put(verdict.ABI())
	}
	for _, call := range transcript {
		in := struct {
			Windows    []RecoveryWindow
			Frame      RecoveryFrame
			Tail       [32]byte
			SeenBitmap *big.Int
			Siblings   [][32]byte
		}{call.in.Windows, call.in.Frame, call.in.Tail, new(big.Int).SetBytes(call.in.Seen.Bitmap[:]), call.in.Seen.Siblings}
		var data, wire []byte
		if call.receipt == nil {
			data, err = a.Pack("start", w.Gamma, e.Root(), e.Length(), in)
		} else {
			s := call.prior
			opened := recoveryABIState{uint8(s.Phase), s.Frame, s.Stack, s.Seen, s.Pos, s.MintEnd, s.Left, s.SplitProof,
				s.Hash, [32]byte(s.Owner[:32]), [1]byte{s.Owner[32]}, s.State, s.ID, new(big.Int).SetBytes(s.Amount[:]),
				s.ParentID, new(big.Int).SetBytes(s.ParentAmount[:]), s.ParentManifest}
			wire = call.receipt.Bytes()
			data, err = a.Pack("resume", w.Gamma, e.Root(), e.Length(), opened, wire, in)
		}
		require.NoError(t, err)
		put(data)
		if call.err != nil {
			put(nil)
		} else if call.verdict != nil {
			put(call.verdict.ABI())
		} else {
			h := call.expected.Digest(v.Session())
			put(h[:])
		}
		t.Logf("trace phase=%d calldata=%d receipt=%d", call.prior.Phase, len(data), len(wire))
	}
}
