package nb2ref

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

func flatCertifiedEvent(t *testing.T, w *World, v *FlatVerifier, e FlatEvent, opts ReceiptOpts) []byte {
	t.Helper()
	proof, err := w.ReceiptProof(expectedLog(e, v.deployment.Recovery), opts)
	require.NoError(t, err)
	return proof.Bytes()
}

func flatGaps(t *testing.T, k uint64, eta [32]byte) ([32]byte, []byte, [][32]byte) {
	t.Helper()
	var ids [][32]byte
	for i := range k {
		id := HE([]byte("flat-gap/neighbor"), flatU64(i))
		require.NotEqual(t, eta, id)
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return bytes.Compare(ids[i][:], ids[j][:]) < 0 })
	tree, ok := BuildGapTree(ids)
	require.True(t, ok)
	proof, ok := tree.Prove(eta)
	require.True(t, ok)
	return tree.Root(), proof, ids
}

type flatCustodyFixture struct {
	Deposits, Segment, Population             uint64
	Liability, VaultBalance, RecipientBalance string
	Head, PreviousHead                        string
	Current, Previous                         []string
	Events                                    []Event
}

func flatCustodyState(v *FlatVault, recipient [20]byte) flatCustodyFixture {
	n, c, m, q, h, p := v.State()
	current, previous := v.LiveIDs()
	ids := func(src [][32]byte) []string {
		out := make([]string, 0, len(src))
		for _, id := range src {
			out = append(out, hex.EncodeToString(id[:]))
		}
		return out
	}
	return flatCustodyFixture{n, c, m, q.String(), v.Balance(v.model.Cfg.Vault).String(), v.Balance(recipient).String(),
		hex.EncodeToString(h[:]), hex.EncodeToString(p[:]), ids(current), ids(previous), v.Logs()}
}

func flatExportCold(t *testing.T, name string, wire []byte, meta any) {
	t.Helper()
	dir := os.Getenv("NB2_FLAT_VECTOR_OUT")
	if dir == "" {
		return
	}
	dir = filepath.Join(dir, "cold", name)
	require.NoError(t, os.MkdirAll(dir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "calldata.bin"), wire, 0644))
	j, err := json.MarshalIndent(meta, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "outcome.json"), append(j, '\n'), 0644))
}

func TestFlatGapAndSettlementMatrix(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	key := Key("flat-root")
	levels := flatFixtureLineage(t, w, v, 0, 0, false)
	rootReason, err := DecodeReceiptBacking(levels[0].token.Mint.Justification)
	require.NoError(t, err)
	rho := Rho(v.domain, rootReason.R)
	evidence, records := flatFixtureEncode(t, levels)
	_, completion := flatFixtureRun(t, w, v, evidence, records, 2)
	header := mustFlatEvidence(t, evidence).Header()
	vd := completion.Verdict
	start := vd.MinSegment
	require.NotZero(t, start)
	root, proof, ids := flatGaps(t, v.cfg.K, vd.Eta)
	require.Equal(t, root, expectedGapRoot(ids))
	heads := make([][32]byte, start+4)
	heads[0] = expectedGenesisHead(v.domain, v.cfg.K)
	for i := 1; i < len(heads); i++ {
		heads[i] = expectedArchiveStep(v.domain, uint64(i-1), heads[i-1], root)
	}
	h0, h1 := heads[start], heads[start+1]
	receipt := flatCertifiedEvent(t, w, v, completion, ReceiptOpts{Type: 2})
	prefix, err := (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt, StartHead: &h0, Proofs: [][]byte{proof}}).Calldata(FlatAdvanceGaps, v.cfg.K)
	require.NoError(t, err)
	actualGap, err := v.AdvanceFlatGaps(prefix)
	require.NoError(t, err)
	gap := FlatEvent{Kind: FlatGapEvent, Session: completion.Session, Seq: completion.Seq + 1,
		Verdict: vd, NextSegment: start + 1, Head: h1}
	require.Equal(t, gap, actualGap)
	gapReceipt := flatCertifiedEvent(t, w, v, gap, ReceiptOpts{Type: 2, Rotated: true})

	for _, startGap := range []bool{false, true} {
		for _, suffix := range []bool{false, true} {
			for _, previous := range []bool{false, true} {
				t.Run(fmt.Sprintf("gap=%t/suffix=%t/previous=%t", startGap, suffix, previous), func(t *testing.T) {
					vault, err := NewFlatVault(v, w.Env())
					require.NoError(t, err)
					require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), rho))
					e := start
					packet := FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}
					if startGap {
						packet.Kind, packet.Receipt = FlatGapEvent, gapReceipt
						e++
					}
					if suffix {
						packet.Proofs = [][]byte{proof}
						if !startGap {
							packet.StartHead = &h0
						}
						e++
					}
					c := e
					if previous {
						c++
					}
					vault.model.SetState(1, c, 0, big.NewInt(100), heads[c], heads[c-1], nil, ids)
					data, err := packet.Calldata(FlatRedeemRecovered, v.cfg.K)
					require.NoError(t, err)
					before := vault.Logs()
					initial := flatCustodyState(vault, vd.Recipient)
					require.Equal(t, heads[c], expectedArchiveStep(v.domain, c-1, heads[c-1], expectedGapRoot(ids)))
					after := expectedSettlement(initial, vd, int(v.cfg.K))
					_, err = vault.RedeemRecovered(data, RecipientPropagatesReentry)
					require.ErrorIs(t, err, ErrPayoutFailed)
					require.Equal(t, before, vault.Logs())
					require.Equal(t, int64(100), vault.Balance(v.cfg.Vault).Int64())
					got, err := vault.RedeemRecovered(data, RecipientReentersRedeem)
					require.NoError(t, err)
					require.ErrorIs(t, got.Inner, ErrReentrancy)
					require.Equal(t, int64(100), vault.Balance(vd.Recipient).Int64())
					n, cOut, pop, q, head, prev := vault.State()
					require.Equal(t, uint64(1), n)
					require.Equal(t, c, cOut)
					require.Equal(t, uint64(1), pop)
					require.Zero(t, q.Sign())
					require.Equal(t, heads[c], head)
					require.Equal(t, heads[c-1], prev)
					_, err = vault.RedeemRecovered(data, RecipientAccepts)
					require.ErrorIs(t, err, ErrAlreadyPaid)
					require.Len(t, vault.Logs(), len(before)+1)
					require.Equal(t, after, flatCustodyState(vault, vd.Recipient))
					flatExportCold(t, fmt.Sprintf("settle-kind%d-suffix%t-prev%t", packet.Kind, suffix, previous), data, struct {
						Before, After                         flatCustodyFixture
						FailedPayout, CaughtInnerCall, Replay string
					}{initial, after, "PayoutFailed", "Reentrancy", "AlreadyPaid"})
				})
			}
		}
	}
	t.Run("advance-bounds", func(t *testing.T) {
		for _, event := range []FlatEvent{completion, gap} {
			for _, count := range []int{0, 1, 1024, 1025} {
				p := FlatGapPacket{Header: header, Kind: event.Kind, Receipt: flatCertifiedEvent(t, w, v, event, ReceiptOpts{})}
				if count > 0 && event.Kind == FlatCompleteEvent {
					p.StartHead = &h0
				}
				for range count {
					p.Proofs = append(p.Proofs, proof)
				}
				wire, err := p.Calldata(FlatAdvanceGaps, v.cfg.K)
				if count == 0 || count > 1024 {
					require.ErrorIs(t, err, ErrFlatPacket)
					wire := uncheckedColdWire(t, FlatAdvanceGaps, p)
					_, err := v.AdvanceFlatGaps(wire)
					require.ErrorIs(t, err, ErrFlatPacket)
					retry := p
					retry.Proofs = [][]byte{proof}
					if event.Kind == FlatCompleteEvent {
						retry.StartHead = &h0
					}
					retryWire, err := retry.Calldata(FlatAdvanceGaps, v.cfg.K)
					require.NoError(t, err)
					flatRecordRefusal(t, fmt.Sprintf("advance-kind%d-count%d", event.Kind, count),
						wire, "BadPacket", p.Receipt, retryWire, nil)
					continue
				}
				require.NoError(t, err)
				got, err := v.AdvanceFlatGaps(wire)
				require.NoError(t, err)
				index, head := start, h0
				if event.Kind == FlatGapEvent {
					index, head = start+1, h1
				}
				for i := range count {
					head = expectedArchiveStep(v.domain, index+uint64(i), head, root)
				}
				want := FlatEvent{Kind: FlatGapEvent, Session: event.Session, Seq: event.Seq + 1,
					Verdict: event.Verdict, NextSegment: index + uint64(count), Head: head}
				require.Equal(t, want, got)
				log := expectedLog(want, v.deployment.Recovery)
				flatExportCold(t, fmt.Sprintf("advance-kind%d-count%d", event.Kind, count), wire, struct {
					Topics  []string
					Data    string
					Receipt string
				}{[]string{hex.EncodeToString(log.Topics[0][:]), hex.EncodeToString(log.Topics[1][:])},
					hex.EncodeToString(log.Data), hex.EncodeToString(flatCertifiedEvent(t, w, v, want, ReceiptOpts{}))})
			}
		}
	})
	t.Run("zero-gap-wrong-head-and-skipped-signed-start", func(t *testing.T) {
		vault, err := NewFlatVault(v, w.Env())
		require.NoError(t, err)
		require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), rho))
		vault.model.SetState(1, start+2, 0, big.NewInt(100), heads[start+2], h1, nil, ids)
		forged := gap
		forged.Head[0] ^= 1
		data, err := (FlatGapPacket{Header: header, Kind: FlatGapEvent, Receipt: flatCertifiedEvent(t, w, v, forged, ReceiptOpts{})}).Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		before := flatCustodyState(vault, vd.Recipient)
		_, err = vault.RedeemRecovered(data, RecipientAccepts)
		require.ErrorIs(t, err, ErrChainMismatch)
		retry, err := (FlatGapPacket{Header: header, Kind: FlatGapEvent, Receipt: gapReceipt}).Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		flatRecordRefusal(t, "zero-suffix-gap-wrong-head", data, "ChainMismatch", gapReceipt, retry, &before)
		data, err = (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}).Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		_, err = vault.RedeemRecovered(data, RecipientAccepts)
		require.ErrorIs(t, err, ErrStaleEndpoint)
		require.Len(t, vault.Logs(), 1)
	})
	for _, ordinaryFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("race/ordinary-first=%t", ordinaryFirst), func(t *testing.T) {
			vault, err := NewFlatVault(v, w.Env())
			require.NoError(t, err)
			require.NoError(t, vault.Deposit(big.NewInt(100), FirstOwner(key), rho))
			vault.model.SetState(1, start, 0, big.NewInt(100), h0, [32]byte{}, nil, ids)
			wire, err := (FlatGapPacket{Header: header, Kind: FlatCompleteEvent, Receipt: receipt}).Calldata(FlatRedeemRecovered, v.cfg.K)
			require.NoError(t, err)
			ordinary := func() error { _, e := vault.Redeem(evidence, vd.Eta, start, nil, RecipientAccepts); return e }
			recovered := func() error { _, e := vault.RedeemRecovered(wire, RecipientAccepts); return e }
			first, second := recovered, ordinary
			if ordinaryFirst {
				first, second = ordinary, recovered
			}
			require.NoError(t, first())
			require.ErrorIs(t, second(), ErrAlreadyPaid)
			require.Equal(t, int64(100), vault.Balance(vd.Recipient).Int64())
		})
	}
}

func TestFlatSettlementBoundsAndSealRollback(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	key := Key("flat-root")
	levels := flatFixtureLineage(t, w, v, 0, 0, false)
	j, err := DecodeReceiptBacking(levels[0].token.Mint.Justification)
	require.NoError(t, err)
	raw, records := flatFixtureEncode(t, levels)
	_, complete := flatFixtureRun(t, w, v, raw, records, 2)
	h := mustFlatEvidence(t, raw).Header()
	eta, a := complete.Verdict.Eta, complete.Verdict.MinSegment
	segRoot, proof, ids := flatGaps(t, v.cfg.K, eta)
	head := expectedGenesisHead(v.domain, v.cfg.K)
	var previousHead [32]byte
	for i := uint64(0); i < a; i++ {
		previousHead, head = head, expectedArchiveStep(v.domain, i, head, segRoot)
	}
	receipt := flatCertifiedEvent(t, w, v, complete, ReceiptOpts{})
	newVault := func() *FlatVault {
		s, err := NewFlatVault(v, w.Env())
		require.NoError(t, err)
		require.NoError(t, s.Deposit(big.NewInt(100), FirstOwner(key), Rho(v.domain, j.R)))
		return s
	}
	t.Run("settlement-1024-and-1025", func(t *testing.T) {
		p := FlatGapPacket{Header: h, Kind: FlatCompleteEvent, Receipt: receipt, StartHead: &head}
		want := head
		var previous [32]byte
		for i := range uint64(1024) {
			previous, want = want, expectedArchiveStep(v.domain, a+i, want, segRoot)
			p.Proofs = append(p.Proofs, proof)
		}
		s := newVault()
		s.model.SetState(1, a+1024, 0, big.NewInt(100), want, previous, nil, ids)
		wire, err := p.Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		before := flatCustodyState(s, complete.Verdict.Recipient)
		failure := p
		failure.Proofs = append(append([][]byte(nil), p.Proofs...), proof)
		rejected := uncheckedColdWire(t, FlatRedeemRecovered, failure)
		_, err = s.RedeemRecovered(rejected, RecipientAccepts)
		require.ErrorIs(t, err, ErrFlatPacket)
		flatRecordRefusal(t, "settle-count1025", rejected, "BadPacket", receipt, wire, &before)
		_, err = s.RedeemRecovered(wire, RecipientAccepts)
		require.NoError(t, err)
		after := expectedSettlement(before, complete.Verdict, int(v.cfg.K))
		require.Equal(t, after, flatCustodyState(s, complete.Verdict.Recipient))
		flatExportCold(t, "settle-count1024", wire, struct{ Before, After flatCustodyFixture }{
			before, after})
		p.Proofs = append(p.Proofs, proof)
		_, err = p.Calldata(FlatRedeemRecovered, v.cfg.K)
		require.ErrorIs(t, err, ErrFlatPacket)
	})
	t.Run("failed-payout-rolls-back-seal", func(t *testing.T) {
		s := newVault()
		s.model.SetState(1, a, v.cfg.K-1, big.NewInt(100), head, previousHead, ids[:len(ids)-1], ids)
		p := FlatGapPacket{Header: h, Kind: FlatCompleteEvent, Receipt: receipt}
		wire, err := p.Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		before := flatCustodyState(s, complete.Verdict.Recipient)
		_, err = s.RedeemRecovered(wire, RecipientReverts)
		require.ErrorIs(t, err, ErrPayoutFailed)
		require.Equal(t, before, flatCustodyState(s, complete.Verdict.Recipient))
		_, err = s.RedeemRecovered(wire, RecipientAccepts)
		require.NoError(t, err)
		after := expectedSettlement(before, complete.Verdict, int(v.cfg.K))
		require.Equal(t, after, flatCustodyState(s, complete.Verdict.Recipient))
		require.Equal(t, a+1, after.Segment)
		require.Zero(t, after.Population)
		require.Len(t, after.Previous, int(v.cfg.K))
		require.Len(t, s.Logs(), len(before.Events)+2)
		_, err = s.RedeemRecovered(wire, RecipientAccepts)
		require.ErrorIs(t, err, ErrAlreadyPaid)
		flatExportCold(t, "settle-seal-rollback-and-retry", wire, struct {
			Before, After        flatCustodyFixture
			FirstFailure, Replay string
		}{before, after, "PayoutFailed", "AlreadyPaid"})
	})
	t.Run("insufficient-backing-and-failed-seal", func(t *testing.T) {
		s := newVault()
		max := *complete.Verdict
		max.MinSegment = MaxSegment
		e := complete
		e.Verdict = &max
		p := FlatGapPacket{Header: h, Kind: FlatCompleteEvent, Receipt: flatCertifiedEvent(t, w, v, e, ReceiptOpts{})}
		wire, err := p.Calldata(FlatRedeemRecovered, v.cfg.K)
		require.NoError(t, err)
		for _, tc := range []struct {
			q    int64
			want error
		}{{99, ErrLiabilityUnderflow}, {100, ErrSegmentCounterExhausted}} {
			s.model.SetState(1, MaxSegment, v.cfg.K-1, big.NewInt(tc.q), head, [32]byte{}, ids[:len(ids)-1], nil)
			before := flatCustodyState(s, complete.Verdict.Recipient)
			_, err = s.RedeemRecovered(wire, RecipientAccepts)
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, flatCustodyState(s, complete.Verdict.Recipient))
		}
	})
}

// Build the negative calldata directly so the public decoder, rather than
// the test-side packet encoder, is the admission boundary under test.
func uncheckedColdWire(t *testing.T, entry FlatEntry, p FlatGapPacket) []byte {
	t.Helper()
	raw := append(p.Header.appendTo(nil), byte(p.Kind))
	raw = flatBlob(raw, p.Receipt)
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(p.Proofs)))
	if p.StartHead != nil {
		raw = append(raw, p.StartHead[:]...)
	}
	for _, proof := range p.Proofs {
		raw = append(raw, proof...)
	}
	wire, err := entry.Calldata(raw)
	require.NoError(t, err)
	return wire
}

func TestFlatDepositRejectsNonCurveFirstOwnerWithoutEffects(t *testing.T) {
	w, v, _ := flatFixtureVerifier(t)
	vault, err := NewFlatVault(v, w.Env())
	require.NoError(t, err)
	owner := FirstOwner(Key("funded-valid-owner"))
	require.NoError(t, vault.Deposit(big.NewInt(3), owner, [32]byte{1}))
	point := append(bytes.Clone(FirstOwnerPrefix), 2)
	point = append(point, bytes.Repeat([]byte{0xff}, 32)...)
	require.Len(t, point, FirstOwnerBytes)
	_, err = ParseKey(point[9:])
	require.Error(t, err)
	before := flatCustodyState(vault, [20]byte{})
	require.ErrorIs(t, vault.Deposit(big.NewInt(7), point, [32]byte{2}), ErrBadFirstOwner)
	require.Equal(t, before, flatCustodyState(vault, [20]byte{}))
	vault.model.entered = true
	require.ErrorIs(t, vault.Deposit(big.NewInt(7), point, [32]byte{2}), ErrReentrancy)
	require.Equal(t, before, flatCustodyState(vault, [20]byte{}))
}
