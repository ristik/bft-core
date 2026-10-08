package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	basehex "github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// maxPosControlRequest bounds the request body: a control item and its witness (an EVM storage-proof witness is at most 1 MiB).
const maxPosControlRequest = 2 << 20

type rootPosControlOperator interface {
	SubmitPosControl(context.Context, rctypes.PosControl, []byte) error
}

// rootPosControlRequest is a Retirement or RejectResult control (its canonical item) and the witness the control commits to by hash.
type rootPosControlRequest struct {
	Control basehex.Bytes `json:"control"`
	Witness basehex.Bytes `json:"witness"`
}

// rootPosControlHandler lets a local operator offer this validator's root node a Retirement or RejectResult control. The node signs it as
// a submission of this validator, sends it to the other root nodes and keeps the witness for them to pull; the leader orders it if the
// root state accepts it.
func rootPosControlHandler(operator rootPosControlOperator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var request rootPosControlRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPosControlRequest)).Decode(&request) != nil || len(request.Witness) == 0 {
			http.Error(w, "invalid control submission", http.StatusBadRequest)
			return
		}
		var control rctypes.PosControl
		if err := control.UnmarshalCBOR(request.Control); err != nil {
			http.Error(w, "invalid control: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := operator.SubmitPosControl(r.Context(), control, request.Witness); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, consensus.ErrPosSubmission) {
				status = http.StatusUnprocessableEntity
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
