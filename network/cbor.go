package network

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/unicitynetwork/bft-go-base/types"
)

func serializeMsg(msg any) ([]byte, error) {
	data, err := types.Cbor.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshaling %T as CBOR: %w", msg, err)
	}
	return frameMsg(data), nil
}

func deserializeMsg(r io.Reader, msg any) error {
	src := bufio.NewReader(r)
	// read data length
	length64, err := binary.ReadUvarint(src)
	if err != nil {
		return fmt.Errorf("reading data length: %w", err)
	}
	if length64 == 0 {
		return fmt.Errorf("unexpected data length zero")
	}

	lengthInt64 := int64(length64) /* #nosec G115 its unlikely that value of length64 exceeds int64 max value */
	if err := types.Cbor.Decode(io.LimitReader(src, lengthInt64), msg); err != nil {
		return fmt.Errorf("decoding message data: %w", err)
	}

	return nil
}

// frameMsg prefixes the CBOR payload with its unsigned-varint length.
func frameMsg(data []byte) []byte {
	buf := make([]byte, binary.MaxVarintLen64, binary.MaxVarintLen64+len(data))
	n := binary.PutUvarint(buf, uint64(len(data)))
	return append(buf[:n], data...)
}

// deserializeMsgLimited reads one frame whose CBOR payload must not exceed maxLen bytes.
// The declared length is checked before any allocation and the payload must be consumed
// exactly by the decoder (no trailing bytes).
func deserializeMsgLimited(src *bufio.Reader, msg any, maxLen uint64) error {
	length, err := readFrameLength(src, maxLen)
	if err != nil {
		return err
	}
	return readFramePayload(src, msg, length)
}

// readFrameLength reads and bounds a frame's declared payload length.
func readFrameLength(src *bufio.Reader, maxLen uint64) (uint64, error) {
	length, err := binary.ReadUvarint(src)
	if err != nil {
		return 0, fmt.Errorf("reading data length: %w", err)
	}
	if length == 0 {
		return 0, fmt.Errorf("unexpected data length zero")
	}
	if length > maxLen {
		return 0, fmt.Errorf("data length %d exceeds the limit %d", length, maxLen)
	}
	return length, nil
}

// readFramePayload reads exactly length payload bytes and decodes them. The buffer grows with the bytes actually received (#1032): a
// declared length alone allocates nothing beyond the first chunk, however large it is.
func readFramePayload(src *bufio.Reader, msg any, length uint64) error {
	var buf bytes.Buffer
	buf.Grow(int(min(length, frameReadChunk)))   /* #nosec G115 length is bounded by the frame limit */
	n, err := io.CopyN(&buf, src, int64(length)) /* #nosec G115 length is bounded by the frame limit */
	if err != nil {
		return fmt.Errorf("reading message data (%d of %d bytes): %w", n, length, err)
	}
	if err := types.Cbor.Unmarshal(buf.Bytes(), msg); err != nil {
		return fmt.Errorf("decoding message data: %w", err)
	}
	return nil
}

// frameReadChunk is the initial allocation of a frame read; the buffer grows only as payload arrives.
const frameReadChunk = 64 << 10
