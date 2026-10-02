package cmd

import (
	"errors"
	"fmt"
)

// refusalError is a refusal whose message text is fixed (operator scripts may match it) while errors.Is reaches the typed
// sentinel and any cause behind it. A nil cause is dropped, which fmt's %w would render as "%!w(<nil>)".
type refusalError struct {
	msg  string
	errs []error
}

func (e *refusalError) Error() string { return e.msg }

func (e *refusalError) Unwrap() []error { return e.errs }

// ErrTrustBodyIDMismatch is a restore whose --trust-body-id does not equal the BodyID of the verified current history after
// catch-up (or whose BodyID could not be read), an operator pin error, distinct from a failure to obtain the history.
var ErrTrustBodyIDMismatch = &refusalError{msg: "restore trust BodyID differs from verified current history"}

// trustBodyIDMismatch is ErrTrustBodyIDMismatch carrying the BodyID lookup cause, if any, with the historical message text.
func trustBodyIDMismatch(cause error) error {
	e := &refusalError{msg: fmt.Sprintf("%s: %v", ErrTrustBodyIDMismatch.msg, cause), errs: []error{ErrTrustBodyIDMismatch}}
	if cause != nil {
		e.errs = append(e.errs, cause)
	}
	return e
}

// ErrHandoffTerminalCertificate is a verified handoff whose terminal shard certificate is absent or inconsistent with the
// frozen parent the handoff proof names.
var ErrHandoffTerminalCertificate = errors.New("verified handoff lacks the terminal shard certificate")

// ErrGenesisLocalKey is ErrJoinerLocalKey for a node named by the genesis configuration: the configuration names the node's
// local key-configuration signing key rather than a signing authority's key.
var ErrGenesisLocalKey = &refusalError{
	msg: "the shard configuration names this node's local signing key from the key configuration, not a signing authority's key; " +
		"generate the configuration from `signing-authority node-info`",
	errs: []error{ErrJoinerLocalKey},
}
