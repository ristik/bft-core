package service

import (
	"context"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

// answerWith serves one fixed status payload on a unix socket, whatever is asked: an authority built before or after the epochs were
// added to the status, as seen by a client of the other build.
func answerWith(t *testing.T, payload []byte) Dialer {
	t.Helper()
	path := filepath.Join(socketDir(t), "fixed.sock")
	l, err := net.Listen("unix", path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				var req wireRequest
				if readFrame(conn, &req) != nil {
					return
				}
				_ = writeFrame(conn, wireResponse{Version: protocolVersion, Payload: payload})
			}()
		}
	}()
	return UnixDialer(path)
}

// oldStatus is the status layout of an authority built before the root and shard epochs were added (statusPayloadV1 is its decoder's
// name for it); it is spelled out here so the test does not depend on the decoder's own type.
type oldStatus struct {
	_                struct{} `cbor:",toarray"`
	Generation       uint64
	ReservedRound    uint64
	HasReservation   bool
	ResponseRetained bool
	Faulted          bool
	KeyLost          bool
}

func TestStatusFromAnAuthorityBuiltBeforeTheEpochsReadsWithZeroEpochs(t *testing.T) {
	old, err := types.Cbor.Marshal(oldStatus{Generation: 7, ReservedRound: 12, HasReservation: true, Faulted: true})
	require.NoError(t, err)
	credential, err := NewCredential()
	require.NoError(t, err)
	dial := answerWith(t, old)

	operator, err := NewOperatorClient(ClientConfig{Dial: dial, Credential: credential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = operator.Close() })
	client, err := NewClient(ClientConfig{Dial: dial, Credential: credential, Timeout: 10 * time.Second})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	for name, read := range map[string]func() (uint64, uint64, uint64, uint64, bool, bool, error){
		"the operator's status": func() (uint64, uint64, uint64, uint64, bool, bool, error) {
			s, err := operator.Status(context.Background())
			return s.Generation, s.ReservedRound, s.RootEpoch, s.ShardEpoch, s.HasReservation, s.Faulted, err
		},
		"the shard node's restore status": func() (uint64, uint64, uint64, uint64, bool, bool, error) {
			s, err := client.RestoreStatus(context.Background())
			return s.Generation, s.ReservedRound, s.RootEpoch, s.ShardEpoch, s.HasReservation, s.Faulted, err
		},
	} {
		generation, round, rootEpoch, shardEpoch, reserved, faulted, err := read()
		require.NoError(t, err, name)
		require.EqualValues(t, 7, generation, name)
		require.EqualValues(t, 12, round, name)
		require.True(t, reserved, name)
		require.True(t, faulted, name)
		require.Zero(t, rootEpoch, "%s: the epochs an old authority never sent read as zero (root epochs start at 1: zero means not reported)", name)
		require.Zero(t, shardEpoch, name)
	}
}

// Only the two layouts the client knows are accepted: any other length (a future layout, damage, a different message) is refused.
// Every array is built from correctly typed fields in the status order, so length is the only thing a refused one gets wrong: the
// same builder's six- and eight-field arrays decode.
func TestStatusDecoderRefusesEveryUnknownLayout(t *testing.T) {
	current, err := types.Cbor.Marshal(statusPayload{Generation: 1, RootEpoch: 2, ShardEpoch: 3})
	require.NoError(t, err)
	decoded, err := decodeStatus(current)
	require.NoError(t, err)
	require.EqualValues(t, 2, decoded.RootEpoch)
	require.EqualValues(t, 3, decoded.ShardEpoch)

	fields := []any{uint64(7), uint64(12), true, false, true, false, uint64(2), uint64(3), uint64(4), uint64(5), uint64(6)}
	for n := 0; n <= len(fields); n++ {
		raw, err := types.Cbor.Marshal(fields[:n])
		require.NoError(t, err)
		_, err = decodeStatus(raw)
		if n == 6 || n == 8 {
			require.NoError(t, err, "%d fields: a known layout", n)
			continue
		}
		var typeErr *cbor.UnmarshalTypeError
		require.ErrorAs(t, err, &typeErr, "%d fields: an unknown layout", n)
	}
	bare, err := types.Cbor.Marshal(uint64(7))
	require.NoError(t, err)
	_, err = decodeStatus(bare)
	var typeErr *cbor.UnmarshalTypeError
	require.ErrorAs(t, err, &typeErr, "a bare integer")
	_, err = decodeStatus(append(append([]byte{}, current...), 0x00))
	var extra *cbor.ExtraneousDataError
	require.ErrorAs(t, err, &extra, "trailing bytes after a status")
	_, err = decodeStatus(nil)
	require.ErrorIs(t, err, io.EOF, "no status")
}

// The other direction cannot be supported: a build that predates the epochs decodes a status with toarray, which refuses an array of
// a different length. This pins that fact (and so the upgrade order: clients before authorities) rather than leaving it implicit.
func TestAnOldClientCannotReadANewStatus(t *testing.T) {
	current, err := types.Cbor.Marshal(statusPayload{Generation: 1, RootEpoch: 2, ShardEpoch: 3})
	require.NoError(t, err)
	var legacy oldStatus
	var typeErr *cbor.UnmarshalTypeError
	require.ErrorAs(t, types.Cbor.Unmarshal(current, &legacy), &typeErr, "a six-field decoder refuses the eight-field status with a typed error")
}

// Asking for the status over either channel is read-only: the authority holds exactly what it held, with a session, a reservation or
// neither, however often it is asked.
func TestStatusOverTheWireIsReadOnly(t *testing.T) {
	f := newFixture(t)
	client := f.admit(t)
	before := f.authority.Status()
	enrollment := f.authority.Enrollment()
	for i := 0; i < 20; i++ {
		viaOperator, err := f.operator.Status(context.Background())
		require.NoError(t, err)
		require.Equal(t, before, viaOperator)
		viaClient, err := client.RestoreStatus(context.Background())
		require.NoError(t, err)
		require.Equal(t, before, viaClient)
	}
	require.Equal(t, before, f.authority.Status(), "the status calls changed what the authority holds")
	require.Equal(t, enrollment, f.authority.Enrollment())
	require.False(t, f.authority.Status().HasReservation, "a status call must not reserve anything")
}
