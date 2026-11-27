package nb2ref

import (
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/require"
)

func TestFlatLineageSemanticRefusals(t *testing.T) {
	for _, bad := range []struct {
		name   string
		change func(*testing.T, *World, *FlatVerifier, *Draft)
		want   error
	}{
		{"wrong-root-secret", func(t *testing.T, w *World, v *FlatVerifier, d *Draft) {
			j, err := DecodeReceiptBacking(d.Mint.Justification)
			require.NoError(t, err)
			j.R[0] ^= 1
			d.Mint.Justification = j.Bytes()
		}, ErrSecretOpening},
		{"wrong-root-owner", func(t *testing.T, w *World, v *FlatVerifier, d *Draft) {
			key := Key("alternate-root-owner")
			d.Mint.Recipient, d.Owners[0] = sigPred(key), key
		}, ErrMintOwner},
		{"wrong-root-amount", func(t *testing.T, w *World, v *FlatVerifier, d *Draft) {
			d.Mint.Data = ValueData(w.Cfg.Aid, big.NewInt(99))
		}, ErrMintData},
		{"continuing-transfer-data", func(t *testing.T, w *World, v *FlatVerifier, d *Draft) {
			key := Key("flat-continued")
			d.Transfer(sigPred(key), key)
			d.Transfers[0].Data = []byte{1}
		}, ErrTransferData},
		{"expired-transfer", func(t *testing.T, w *World, v *FlatVerifier, d *Draft) {
			key := Key("flat-expired")
			d.Transfer(sigPred(key), key)
			d.Transfers[0].Deadline = Deadline{Set: true, At: DevTime + 10}
		}, ErrDeadlineExpired},
	} {
		t.Run(bad.name, func(t *testing.T) {
			w, v, _ := flatFixtureVerifier(t)
			d, _ := flatFixtureRoot(t, w, v, 100, Key("flat-root"))
			bad.change(t, w, v, d)
			tok := flatFixtureReturn(t, w, v, d, 7)
			raw, records := flatFixtureEncode(t, []flatFixtureLevel{{nil, tok}})
			_, err := v.VerifyFlatReturn(raw)
			require.ErrorIs(t, err, bad.want)
			packet := newFlatFixtureWallet(mustFlatEvidence(t, raw)).packet(t, nil, nil, records)
			wire, err := packet.Calldata()
			require.NoError(t, err)
			out, err := v.RunFlat(wire)
			require.Nil(t, out)
			require.ErrorIs(t, err, ErrFlatStep)
			require.ErrorIs(t, err, bad.want)
			flatRecordRefusal(t, bad.name, wire, "BadStep", nil, nil, nil)
			flatExportRefusedEvidence(t, bad.name, raw)
		})
	}
}

func flatExportRefusedEvidence(t *testing.T, name string, raw []byte) {
	t.Helper()
	if dir := os.Getenv("NB2_FLAT_VECTOR_OUT"); dir != "" {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "refusals", name, "evidence.bin"), raw, 0644))
	}
}

func TestFlatChildRequiresItsVerifiedParent(t *testing.T) {
	for _, change := range []string{"wrong-link", "recursive-reason", "wrong-amount", "wrong-deadline", "missing-parent", "wrong-sum", "repeated-mint-sid"} {
		t.Run(change, func(t *testing.T) {
			w, v, _ := flatFixtureVerifier(t)
			d, _ := flatFixtureRoot(t, w, v, 100, Key("flat-root"))
			var parent *Token
			var child *Draft
			var alloc []byte
			var expected error
			switch change {
			case "wrong-sum", "repeated-mint-sid":
				// A correctly signed singleton manifest whose sum is wrong,
				// or a child whose signed salt recreates the parent's mint SID.
				owner := Key("flat-singleton-child")
				pid := TokenID(d.Mint.Salt, d.Mint.Network)
				salt, amount := d.Mint.Salt, int64(100)
				if change == "wrong-sum" {
					salt[0] ^= 1
					amount = 99
					expected = ErrSplitSum
				} else {
					expected = ErrRepeatedSID
				}
				m := MintTx{Network: w.Cfg.Network, Recipient: sigPred(owner), Salt: salt, Type: w.Cfg.Ty, Data: ValueData(w.Cfg.Aid, big.NewInt(amount))}
				id := TokenID(salt, m.Network)
				tree, err := BuildSumTree([]SumLeaf{{Key: id, Data: FlatOutput(pid, &m), Value: big.NewInt(amount)}})
				require.NoError(t, err)
				manifest := SplitManifest{tree.Root()}
				data := manifest.Bytes()
				d.Transfers = append(d.Transfers, TransferTx{Recipient: BurnPredicate(HU(data)), Data: data, Mask: HU([]byte("singleton-split"))})
				parent, err = w.Finalize(d)
				require.NoError(t, err)
				burn := parent.Proofs[0].CD
				link := FlatParentLink(v.domain, pid, StateID(burn.Source, burn.SourceHash), burn.TxHash, manifest.Root, u256u(100))
				m.Justification = FlatChildReason(link)
				child = &Draft{Mint: m, Owners: []*secp256k1.PrivateKey{owner}}
				alloc = SumProof{}.Bytes()
			default:
				p, kids, proofs := flatFixtureSplit(t, w, v, d, 60, 40)
				parent, child, alloc = p, kids[0], proofs[0]
				switch change {
				case "wrong-link":
					child.Mint.Justification[len(child.Mint.Justification)-1] ^= 1
					expected = ErrSplitJustif
				case "recursive-reason":
					child.Mint.Justification = SplitJustificationBytes(parent.Bytes(), SumProof{})
					expected = ErrInputTooLarge
				case "wrong-amount":
					child.Mint.Data = ValueData(w.Cfg.Aid, big.NewInt(61))
					expected = ErrSplitProof
				case "wrong-deadline":
					child.Mint.Deadline = Deadline{Set: true, At: DevTime + 20_000}
					expected = ErrSplitProof
				case "missing-parent":
					expected = ErrTruncated
				}
			}
			last := flatFixtureReturn(t, w, v, child, 7)
			raw, records := flatFixtureEncode(t, []flatFixtureLevel{{nil, parent}, {alloc, last}})
			if change == "missing-parent" {
				// Preserve the declared two-level prelude, but truncate after
				// the first level so the completion cannot credit the prefix.
				raw = raw[:records[2].start]
				records = records[:2]
			}
			_, err := v.VerifyFlatReturn(raw)
			require.ErrorIs(t, err, expected)
			if change == "missing-parent" {
				trace, got := flatFixtureRun(t, w, v, raw, records, 2)
				require.Equal(t, FlatProgressEvent, got.Kind)
				require.Len(t, trace, 1)
				return
			}
			wallet := newFlatFixtureWallet(mustFlatEvidence(t, raw))
			model := newExpectedLineage(v, raw)
			startPacket := wallet.packet(t, nil, nil, records[:1])
			start, err := startPacket.Calldata()
			require.NoError(t, err)
			frame, progress, _ := flatFixtureFrame(t, w, v, model, startPacket, start, records[:1], ReceiptOpts{})
			prior := frame.ResultReceipt
			packet := wallet.packet(t, progress, prior, records[1:])
			data, err := packet.Calldata()
			require.NoError(t, err)
			// The invalid child cannot be repaired under this commitment. The
			// preceding split can still be certified from the original input.
			wallet = newFlatFixtureWallet(mustFlatEvidence(t, raw))
			wallet.packet(t, nil, nil, records[:1])
			retry, err := wallet.packet(t, progress, prior, records[1:2]).Calldata()
			require.NoError(t, err)
			_, err = v.RunFlat(retry)
			require.NoError(t, err)
			got, err := v.RunFlat(data)
			require.Nil(t, got)
			require.ErrorIs(t, err, ErrFlatStep, fmt.Sprintf("child mutation %s", change))
			if change != "repeated-mint-sid" {
				require.ErrorIs(t, err, expected)
			}
			flatRecordRefusal(t, change, data, "BadStep", prior, retry, nil)
			flatExportRefusedEvidence(t, change, raw)
		})
	}
}
