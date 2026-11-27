package vradmit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// CertificateInput is what Freeze validity (design section 5.3.5) checks a view certificate against: the intent re-derived from committed
// history and the VR proof at P (its digest), the committed current view, the incumbents (node id and root key, in any order: the
// assembler order is derived), the candidate the certificate must carry, the successor identities in identity order, the V3 body and
// attempt the receipts are bound to, and the signing bytes of the successor trust base derived from the intent.
type CertificateInput struct {
	Certificate    vrschema.ViewCertificate
	IntentDigest   [32]byte
	CommittedView  uint64
	Incumbents     map[string][]byte
	CandidateBytes []byte
	Successors     []evmassign.Identity
	Body           q3format.BodyV3
	Attempt        uint64
	TrustBaseBytes []byte
}

// ErrCertificateShape reports a certificate that does not name the intent, the candidate or the successors.
var ErrCertificateShape = errors.New("vradmit: view certificate")

// VerifyCertificate is design section 5.3.5 items 2 to 4: the assembly is signed by assembler(order, view) with view <= the committed
// current view, it carries exactly the candidate, and the certificate holds exactly one readiness per successor member, each for that
// exact (intentDigest, view, candidateDigest, bodyID), with a valid receipt, a trust-base signature over the derived successor trust base
// and a valid envelope, all by the member's root key. Any complete certificate is valid, including a late one for an earlier view.
func VerifyCertificate(in CertificateInput) error {
	c := in.Certificate
	a := c.Assembly
	if !bytes.Equal(a.IntentDigest, in.IntentDigest[:]) || a.Slot > in.CommittedView {
		return fmt.Errorf("%w: assembly of another intent or of an uncommitted view %d", ErrCertificateShape, a.Slot)
	}
	if !bytes.Equal(a.Candidate, in.CandidateBytes) {
		return fmt.Errorf("%w: the assembly carries another candidate", ErrCertificateShape)
	}
	if len(in.Incumbents) == 0 {
		return fmt.Errorf("%w: no incumbents", ErrCertificateShape)
	}
	ids := make([]string, 0, len(in.Incumbents))
	for id := range in.Incumbents {
		ids = append(ids, id)
	}
	assembler := vrschema.Assembler(vrschema.AssemblerOrder(in.IntentDigest, ids), a.Slot)
	msg, err := a.SignedBytes()
	if err != nil {
		return err
	}
	if err := vrschema.Verify(in.Incumbents[assembler], a.Sig, msg); err != nil {
		return fmt.Errorf("%w: the assembly is not signed by view %d's assembler %s: %w", ErrCertificateShape, a.Slot, assembler, err)
	}
	names := make([]string, len(in.Successors))
	for i, s := range in.Successors {
		names[i] = s.RootNodeID
	}
	bodyID := in.Body.Identity()
	if err := c.CheckShape(names, bodyID[:]); err != nil {
		return err
	}
	cd := sha256.Sum256(a.Candidate)
	receipts := make([]q3format.Receipt, len(c.Readiness))
	for i, r := range c.Readiness {
		key := in.Successors[i].RootKey
		env, err := r.EnvelopeBytes()
		if err != nil {
			return err
		}
		if err := vrschema.Verify(key, r.EnvelopeSig, env); err != nil {
			return fmt.Errorf("%w: readiness %d envelope: %w", ErrCertificateShape, i, err)
		}
		if err := vrschema.Verify(key, r.TrustBaseSig, in.TrustBaseBytes); err != nil {
			return fmt.Errorf("%w: readiness %d trust-base signature: %w", ErrCertificateShape, i, err)
		}
		if err := verifyOwnCommitments(r.Commitments, in.Successors[i]); err != nil {
			return fmt.Errorf("%w: readiness %d: %w", ErrCertificateShape, i, err)
		}
		if receipts[i], err = vrschema.ReadinessReceipt(r.Receipt, names[i]); err != nil {
			return err
		}
	}
	return q3format.VerifyReceipts(in.Body, q3format.ContextFor(in.Body, in.Attempt, cd), receipts)
}

// verifyOwnCommitments requires every commitment of a member's readiness to be by that member's exact binding.
func verifyOwnCommitments(cs []vrschema.SupportCommitment, m evmassign.Identity) error {
	for _, c := range cs {
		if err := VerifyCommitment(c, m); err != nil {
			return err
		}
	}
	return nil
}
