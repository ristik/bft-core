package service

import (
	"errors"

	"github.com/unicitynetwork/bft-core/signingauthority"
)

/*
The refusal vocabulary crosses the wire by name.

A caller of the authority in one process gets a sentinel error, and a caller across this transport
must get the same one: the round's abstention reason, and an operator reading it, should not depend
on where the authority runs. So a refusal travels as the name the contract gives it, and is mapped
back on the other side. A name this table does not know stays a plain error carrying that name,
never a nil error and never silently one of the known ones.
*/
var refusalsByName = map[string]error{
	signingauthority.ErrContextMismatch.Error():     signingauthority.ErrContextMismatch,
	signingauthority.ErrUnauthenticated.Error():     signingauthority.ErrUnauthenticated,
	signingauthority.ErrProposalMismatch.Error():    signingauthority.ErrProposalMismatch,
	signingauthority.ErrRequestTooLarge.Error():     signingauthority.ErrRequestTooLarge,
	signingauthority.ErrUnsupportedVersion.Error():  signingauthority.ErrUnsupportedVersion,
	signingauthority.ErrKeyLost.Error():             signingauthority.ErrKeyLost,
	signingauthority.ErrFenced.Error():              signingauthority.ErrFenced,
	signingauthority.ErrStale.Error():               signingauthority.ErrStale,
	signingauthority.ErrConflict.Error():            signingauthority.ErrConflict,
	signingauthority.ErrNoReservation.Error():       signingauthority.ErrNoReservation,
	signingauthority.ErrResponseNotRetained.Error(): signingauthority.ErrResponseNotRetained,
	signingauthority.ErrStateUntrusted.Error():      signingauthority.ErrStateUntrusted,
	errFrameTooLarge.Error():                        errFrameTooLarge,
	errWrongEndpoint.Error():                        errWrongEndpoint,
	errOperatorUnauthenticated.Error():              errOperatorUnauthenticated,
	errMalformed.Error():                            errMalformed,
	errInternal.Error():                             errInternal,
}

// errInternal is a failure inside the authority process that is not one of the contract's decisions:
// a context deadline, an encoding failure, a bug. It is reported under its own name rather than
// borrowed from the vocabulary above, because a shard node must not read "the authority refused this
// work" where the truth is "something went wrong in there". Detail stays in the authority's log.
var errInternal = errors.New("signing-authority-internal-error")

/*
refusalName is what the server puts on the wire for an error.

It reports the NAME of a known refusal and nothing else. An error the table does not know becomes
signing-authority-internal-error rather than being passed through: an unknown failure inside the
authority process is not a decision a shard node should act on as though it were one, and an error
string from in there is the wrong thing to hand a remote caller.
*/
func refusalName(err error) string {
	for name, sentinel := range refusalsByName {
		if errors.Is(err, sentinel) {
			return name
		}
	}
	return errInternal.Error()
}

// refusalError maps a name from the wire back to the error a local caller would have seen.
func refusalError(name string) error {
	if err, ok := refusalsByName[name]; ok {
		return err
	}
	return errors.New(name)
}
