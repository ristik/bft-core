package q3compat

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/q3format"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

type stubService struct {
	r   ServiceReport
	err error
}

func (s stubService) Report(context.Context) (ServiceReport, error) { return s.r, s.err }

type stubExec struct {
	r   ExecutionReport
	err error
}

func (s stubExec) Report(context.Context) (ExecutionReport, error) { return s.r, s.err }

var pinned = ExecutionRequirement{GenesisHash: fb(0x31), CodeHash: fb(0x32), TransitionCodec: 1}

func goodExec() ExecutionReport {
	return ExecutionReport{Version: 1, Protocols: []string{"q3/1"}, RegistryLayout: 2, GenesisHash: fb(0x31), CodeHash: fb(0x32),
		ConfigRevisions: []uint64{1}, TransitionCodec: []uint64{1}}
}

func goodService(rc q3format.ReceiptContext) ServiceReport {
	return ServiceReport{Network: rc.Network, Genesis: rc.Genesis, Protocols: []string{"q3/0", "q3/1"}, Staged: rc.CandidateDigest}
}

func goodEntity(rc q3format.ReceiptContext, id string) Entity {
	return Entity{NodeID: id, BFT: stubService{r: goodService(rc)}, Authority: stubService{r: goodService(rc)}, Execution: stubExec{r: goodExec()}}
}

func TestAttest(t *testing.T) {
	b, signers := testBody(t)
	rc := q3format.ContextFor(b, 3, fill(0x44))
	r, err := goodEntity(rc, "n1").Attest(context.Background(), rc, b.Config, pinned, signers["n1"])
	require.NoError(t, err, "acceptance control")
	require.Equal(t, "n1", r.NodeID)

	service := func(mut func(*ServiceReport)) Service {
		s := goodService(rc)
		mut(&s)
		return stubService{r: s}
	}
	exec := func(mut func(*ExecutionReport)) Execution {
		x := goodExec()
		mut(&x)
		return stubExec{r: x}
	}
	svcMutations := map[string]func(*ServiceReport){
		"other network":    func(s *ServiceReport) { s.Network++ },
		"other genesis":    func(s *ServiceReport) { s.Genesis = fill(0x55) },
		"staged elsewhere": func(s *ServiceReport) { s.Staged = fill(0x56) },
		"nothing staged":   func(s *ServiceReport) { s.Staged = [32]byte{} },
	}
	type tc struct {
		name string
		e    Entity
		want []error
	}
	var cases []tc
	for name, mut := range svcMutations {
		e1, e2 := goodEntity(rc, "n1"), goodEntity(rc, "n1")
		e1.BFT, e2.Authority = service(mut), service(mut)
		cases = append(cases, tc{"bft " + name, e1, []error{ErrNotReady, ErrComponent}}, tc{"authority " + name, e2, []error{ErrNotReady, ErrComponent}})
	}
	for name, role := range map[string]func(*Entity, Service){"bft": func(e *Entity, s Service) { e.BFT = s }, "authority": func(e *Entity, s Service) { e.Authority = s }} {
		e := goodEntity(rc, "n1")
		role(&e, service(func(s *ServiceReport) { s.Protocols = []string{"q3/0"} }))
		cases = append(cases, tc{name + " old protocol", e, []error{ErrNotReady, ErrProtocol}})
		e = goodEntity(rc, "n1")
		role(&e, stubService{err: errors.New("down")})
		cases = append(cases, tc{name + " unreachable", e, []error{ErrNotReady, ErrProbe}})
		e = goodEntity(rc, "n1")
		role(&e, nil)
		cases = append(cases, tc{name + " absent", e, []error{ErrNotReady, ErrProbe}})
	}
	for name, mut := range map[string]struct {
		f    func(*ExecutionReport)
		want error
	}{
		"layout 1":        {func(x *ExecutionReport) { x.RegistryLayout = 1 }, ErrExecutionLayout},
		"unsupported":     {func(x *ExecutionReport) { x.Protocols = []string{"q3/0"} }, ErrExecutionProtocol},
		"old report":      {func(x *ExecutionReport) { x.Version = 0 }, ErrExecutionVersion},
		"no config codec": {func(x *ExecutionReport) { x.ConfigRevisions = nil }, ErrExecutionCodec},
		"no transition":   {func(x *ExecutionReport) { x.TransitionCodec = []uint64{2} }, ErrExecutionCodec},
		"other genesis":   {func(x *ExecutionReport) { x.GenesisHash = fb(0x77) }, ErrExecutionIdentity},
		"other code":      {func(x *ExecutionReport) { x.CodeHash = fb(0x78) }, ErrExecutionIdentity},
	} {
		e := goodEntity(rc, "n1")
		e.Execution = exec(mut.f)
		cases = append(cases, tc{"execution " + name, e, []error{ErrNotReady, mut.want}})
	}
	e := goodEntity(rc, "n1")
	e.Execution = stubExec{err: errors.New("down")}
	cases = append(cases, tc{"execution unreachable", e, []error{ErrNotReady, ErrProbe}})
	e = goodEntity(rc, "n1")
	e.Execution = nil
	cases = append(cases, tc{"execution absent", e, []error{ErrNotReady, ErrProbe}})

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := c.e.Attest(context.Background(), rc, b.Config, pinned, signers["n1"])
			for _, w := range c.want {
				require.ErrorIs(t, err, w)
			}
			require.Equal(t, q3format.Receipt{}, r, "a refused entity signs nothing")
		})
	}
}

func TestAttestChecksTheTupleItSigns(t *testing.T) {
	b, signers := testBody(t)
	rc := q3format.ContextFor(b, 3, fill(0x44))
	e := goodEntity(rc, "n1")

	invalid := b.Config
	invalid.SigningScheme = 1
	_, err := e.Attest(context.Background(), rc, invalid, pinned, signers["n1"])
	require.ErrorIs(t, err, q3format.ErrConfig)

	for name, mut := range map[string]func(*q3format.ReceiptContext){
		"other network": func(c *q3format.ReceiptContext) { c.Network++ },
		"other genesis": func(c *q3format.ReceiptContext) { c.Genesis = fill(0x66) },
		"other tuple":   func(c *q3format.ReceiptContext) { c.Config = fill(0x67) },
	} {
		other := rc
		mut(&other)
		_, err := e.Attest(context.Background(), other, b.Config, pinned, signers["n1"])
		require.ErrorIs(t, err, ErrComponent, name)
	}
}

func TestExecutionRequirementNeedsLocalPins(t *testing.T) {
	cfg := q3format.Q3Config(testNetwork, fill(9))
	require.NoError(t, pinned.Check(goodExec(), cfg), "acceptance control")
	empty := goodExec()
	empty.GenesisHash, empty.CodeHash = nil, nil
	require.ErrorIs(t, ExecutionRequirement{TransitionCodec: 1}.Check(empty, cfg), ErrExecutionIdentity, "no pins against a report without identity")
	for name, w := range map[string]ExecutionRequirement{
		"no genesis pin": {CodeHash: fb(0x32), TransitionCodec: 1},
		"no code pin":    {GenesisHash: fb(0x31), TransitionCodec: 1},
	} {
		r := goodExec()
		r.GenesisHash, r.CodeHash = nil, nil // an empty report must not match an empty pin
		require.ErrorIs(t, w.Check(r, cfg), ErrExecutionIdentity, name)
		require.ErrorIs(t, w.Check(goodExec(), cfg), ErrExecutionIdentity, name+" with a full report")
	}
}

func TestRequireReadiness(t *testing.T) {
	b, signers := testBody(t)
	rc := q3format.ContextFor(b, 3, fill(0x44))
	sign := func(c q3format.ReceiptContext, ids ...string) (out []q3format.Receipt) {
		for _, id := range ids {
			r, err := q3format.SignReceipt(c, id, abcrypto.Signer(signers[id]))
			require.NoError(t, err)
			out = append(out, r)
		}
		return
	}
	all := sign(rc, "n1", "n2", "n3", "n4")
	require.NoError(t, RequireReadiness(b, rc, all), "acceptance control")

	elsewhere := rc
	elsewhere.Attempt++
	otherCandidate := rc
	otherCandidate.CandidateDigest = fill(0x45)
	stranger, _ := newSigner(t)
	forged, err := q3format.SignReceipt(rc, "n2", stranger)
	require.NoError(t, err)

	for _, c := range []struct {
		name string
		rc   q3format.ReceiptContext
		rs   []q3format.Receipt
		want error
	}{
		{"heavy member missing", rc, all[1:], q3format.ErrReceiptMissing},
		{"light member missing", rc, all[:3], q3format.ErrReceiptMissing},
		{"a quorum is not enough", rc, sign(rc, "n1", "n2"), q3format.ErrReceiptMissing},
		{"no receipts", rc, nil, q3format.ErrReceiptMissing},
		{"duplicate", rc, append(append([]q3format.Receipt{}, all...), all[0]), q3format.ErrReceiptDuplicate},
		{"unknown signer", rc, append(append([]q3format.Receipt{}, all...), q3format.Receipt{NodeID: "zz"}), q3format.ErrReceiptUnknown},
		{"wrong key", rc, []q3format.Receipt{all[0], forged, all[2], all[3]}, q3format.ErrReceiptSignature},
		{"replayed from another attempt", rc, sign(elsewhere, "n1", "n2", "n3", "n4"), q3format.ErrReceiptSignature},
		{"replayed from another candidate", rc, sign(otherCandidate, "n1", "n2", "n3", "n4"), q3format.ErrReceiptSignature},
		{"context of another candidate", otherCandidate, all, q3format.ErrReceiptSignature},
		{"context of another body", func() q3format.ReceiptContext { c := rc; c.BodyID = fill(0x46); return c }(), all, q3format.ErrReceiptContext},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := RequireReadiness(b, c.rc, c.rs)
			require.ErrorIs(t, err, ErrReadinessRefused)
			require.ErrorIs(t, err, c.want)
		})
	}
}
