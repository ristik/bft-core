package vrhandoff_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The frozen handoff-protocol vectors (VT-16, testvectors/validator-registry), replayed through this package's root-side functions: the
// intent, the assembler order, the assembly, readiness, certificate and Freeze v5 encodings and signing targets, the HandoffView replay
// rule, the timeouts and residence waits, certificate admissibility and the proposer policy. The liveness-side quantities of the view
// traces (earliest commit, assembler window, completion) are the frozen timing model's, not root code, and are not replayed here.

type vector struct {
	Name   string          `json:"name"`
	Op     string          `json:"op"`
	Input  json.RawMessage `json:"input"`
	Expect json.RawMessage `json:"expect"`
}

func vectors(t *testing.T, file string) []vector {
	raw, err := os.ReadFile(filepath.Join("..", "testvectors", "validator-registry", file))
	require.NoError(t, err)
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	return f.Vectors
}

func hx(t *testing.T, s string) []byte {
	b, err := common.ParseHexOrString(s)
	require.NoError(t, err)
	return b
}

func decode(t *testing.T, raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) == 0 {
		return m
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	require.NoError(t, d.Decode(&m))
	return m
}

func num(t *testing.T, v any) uint64 {
	switch x := v.(type) {
	case json.Number:
		n, err := strconv.ParseUint(x.String(), 10, 64)
		require.NoError(t, err)
		return n
	case float64:
		return uint64(x)
	case string:
		n, err := strconv.ParseUint(x, 10, 64)
		require.NoError(t, err)
		return n
	}
	t.Fatalf("not a number: %v", v)
	return 0
}

func TestFrozenHandoffVectors(t *testing.T) {
	counts := map[string]int{}
	for _, v := range vectors(t, "encoding.json") {
		in, ex := decode(t, v.Input), decode(t, v.Expect)
		switch v.Op {
		case "handoff.intent":
			i, err := vrschema.DecodeIntent(hx(t, ex["bytes"].(string)))
			require.NoError(t, err, v.Name)
			d, err := i.Digest()
			require.NoError(t, err)
			require.Equal(t, hx(t, ex["intentDigest"].(string)), d[:], v.Name)
			require.Equal(t, num(t, in["anchorRound"]), vrhandoff.AnchorRound(vrhandoff.Source{CertRootRound: num(t, in["certRootRound"])}, num(t, in["attemptOpenRound"])))
			require.Equal(t, num(t, in["anchorRound"]), i.AnchorRound)
			require.Equal(t, num(t, ex["earliestActivation"]), vrhandoff.EarliestActivation(i))
			require.Equal(t, hx(t, in["candidate"].(string)), i.Candidate)
			_, err = vrhandoff.CandidateOf(i)
			require.NoError(t, err, "the intent carries an unsigned primary candidate v6")
		case "handoff.assemblerOrder":
			var ids []string
			for _, x := range in["incumbents"].([]any) {
				ids = append(ids, x.(string))
			}
			d := [32]byte(hx(t, in["intentDigest"].(string)))
			var want []string
			for _, x := range ex["order"].([]any) {
				want = append(want, x.(string))
			}
			require.Equal(t, want, vrhandoff.AssemblerOrder(d, ids), v.Name)
			require.Equal(t, ex["assemblerOfSlot7"], vrhandoff.Assembler(d, ids, 7))
		case "handoff.assembly":
			var a vrhandoff.Assembly
			require.NoError(t, types.Cbor.Unmarshal(hx(t, ex["bytes"].(string)), &a))
			require.Equal(t, hx(t, in["candidate"].(string)), a.Candidate)
			require.Equal(t, num(t, in["slot"]), a.Slot)
			msg, err := a.SignedBytes()
			require.NoError(t, err)
			require.Equal(t, hx(t, ex["signedBytes"].(string)), msg, v.Name)
			require.NoError(t, vrschema.Verify(hx(t, in["signerKey"].(string)), a.Sig, msg))
			again, err := types.Cbor.Marshal(a)
			require.NoError(t, err)
			require.Equal(t, hx(t, ex["bytes"].(string)), again)
		case "handoff.readiness":
			if b, ok := ex["bytes"].(string); ok {
				r, err := vrschema.DecodeReadiness(hx(t, b))
				require.NoError(t, err, v.Name)
				env, err := r.EnvelopeBytes()
				require.NoError(t, err)
				require.Equal(t, hx(t, ex["envelopeBytes"].(string)), env, v.Name)
				require.NoError(t, vrschema.Verify(hx(t, in["signerKey"].(string)), r.EnvelopeSig, env))
			} else {
				_, err := vrschema.DecodeReadiness(hx(t, in["bytes"].(string)))
				require.Error(t, err, v.Name)
			}
		case "handoff.certificate":
			b, ok := ex["bytes"].(string)
			if !ok {
				continue
			}
			c, err := vrschema.DecodeViewCertificate(hx(t, b))
			require.NoError(t, err, v.Name)
			var succ []string
			for _, x := range in["successors"].([]any) {
				succ = append(succ, x.(string))
			}
			require.NoError(t, c.CheckShape(succ, c.Readiness[0].BodyID), v.Name)
		case "handoff.freezeV5":
			if b, ok := ex["bytes"].(string); ok {
				fz, err := vrschema.DecodeFreezeV5(hx(t, b))
				require.NoError(t, err, v.Name)
				w := sha256.Sum256(fz.Witness)
				require.Equal(t, hx(t, ex["witnessHash"].(string)), w[:])
			} else if b, ok := in["bytes"].(string); ok {
				_, err := vrschema.DecodeFreezeV5(hx(t, b))
				require.Error(t, err, v.Name)
			} else {
				continue
			}
		default:
			continue
		}
		counts[v.Op]++
	}
	for _, v := range vectors(t, "statemachine.json") {
		in, ex := decode(t, v.Input), decode(t, v.Expect)
		switch v.Op {
		case "view.replay":
			var r vrschema.HandoffViewReplay
			raw, _ := json.Marshal(in["replay"])
			require.NoError(t, json.Unmarshal(raw, &r))
			err := vrhandoff.VerifyHandoffView(r, num(t, in["view"]), num(t, in["blockUcTime"]))
			require.Equal(t, ex["valid"], err == nil, v.Name)
			if err != nil {
				require.Equal(t, ex["error"], err.Error(), v.Name)
			}
		case "view.certificateAdmissible":
			require.Equal(t, ex["admissible"], vrhandoff.CertificateAdmissible(num(t, in["certView"]), num(t, in["committedView"]), in["freezeCommitted"].(bool)), v.Name)
		case "view.leaderPolicy":
			require.Equal(t, ex["choice"], vrhandoff.LeaderChoice(in["certComplete"].(bool), in["gatesHold"].(bool), in["viewDue"].(bool), in["rejectionDue"].(bool),
				in["quiet"].(bool)), v.Name)
		case "view.trace":
			var tr vrschema.ViewTrace
			raw, _ := json.Marshal(in["trace"])
			require.NoError(t, json.Unmarshal(raw, &tr))
			j := ex["judgment"].(map[string]any)
			if tr.TOverride != 0 {
				require.Equal(t, num(t, j["residenceWaitMs"]), vrschema.ResidenceWaitMillis(tr.TOverride), v.Name)
				break
			}
			secs, never := vrhandoff.ViewTimeoutSeconds(tr.Level, tr.View, tr.Assemblers)
			require.Equal(t, num(t, j["tSeconds"]), secs, v.Name)
			require.Equal(t, j["never"], never, v.Name)
			wait, finite := vradmit.ResidenceWaitMillis(tr.Level, tr.View, tr.Assemblers)
			require.Equal(t, !never, finite)
			require.Equal(t, num(t, j["residenceWaitMs"]), wait, v.Name)
			err := vrhandoff.VerifyHandoffView(vrschema.HandoffViewReplay{IntentDerivable: true, CommittedView: tr.View, BackoffAgrees: true, OpenUCTime: tr.OpenUCTime,
				Level: tr.Level, N: tr.Assemblers, InBlock: 1}, tr.View+1, tr.ProposalUC)
			require.Equal(t, j["replayValid"], err == nil, v.Name)
		default:
			continue
		}
		counts[v.Op]++
	}
	for _, v := range vectors(t, "arithmetic.json") {
		in, ex := decode(t, v.Input), decode(t, v.Expect)
		switch v.Op {
		case "arith.viewTimeout":
			secs, never := vrhandoff.ViewTimeoutSeconds(uint8(num(t, in["level"])), num(t, in["view"]), uint32(num(t, in["n"])))
			require.Equal(t, ex["never"], never, v.Name)
			if !never {
				require.Equal(t, num(t, ex["seconds"]), secs, v.Name)
			}
		case "arith.deadline":
			at, never := vrhandoff.Deadline(num(t, in["open"]), uint8(num(t, in["level"])), num(t, in["view"]), uint32(num(t, in["n"])))
			require.Equal(t, ex["never"], never, v.Name)
			if !never {
				require.Equal(t, num(t, ex["at"]), at, v.Name)
			}
		default:
			continue
		}
		counts[v.Op]++
	}
	total := 0
	for op, n := range counts {
		t.Logf("%-28s %d", op, n)
		total += n
	}
	t.Logf("replayed %d frozen vectors", total)
	require.Equal(t, map[string]int{"handoff.intent": 1, "handoff.assemblerOrder": 1, "handoff.assembly": 1, "handoff.readiness": 2, "handoff.certificate": 1,
		"handoff.freezeV5": 2, "view.replay": 8, "view.certificateAdmissible": 5, "view.leaderPolicy": 5, "view.trace": 14, "arith.viewTimeout": 11,
		"arith.deadline": 5}, counts)
}
