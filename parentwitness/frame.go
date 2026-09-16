package parentwitness

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

func writeFrame(w io.Writer, body []byte, max int) error {
	if len(body) == 0 || len(body) > max {
		return fmt.Errorf("%w: frame is %d bytes", ErrBounds, len(body))
	}
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], uint64(len(body)))
	if err := writeExact(w, prefix[:n]); err != nil {
		return err
	}
	return writeExact(w, body)
}

func readFrame(r *bufio.Reader, max int) ([]byte, error) {
	n, err := readUvarintExact(r)
	if err != nil {
		return nil, fmt.Errorf("%w: frame length: %v", ErrWire, err)
	}
	if n == 0 || n > uint64(max) {
		return nil, fmt.Errorf("%w: declared frame is %d bytes", ErrBounds, n)
	}
	body := make([]byte, int(n))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: frame body: %v", ErrWire, err)
	}
	return body, nil
}

func writeExact(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

// readUvarintExact avoids bufio.Reader.ReadByte: that method may fill its buffer from the
// underlying stream and consume response body bytes before the declared length is admitted.
func readUvarintExact(r io.Reader) (uint64, error) {
	var x uint64
	for i := 0; i < binary.MaxVarintLen64; i++ {
		var one [1]byte
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return 0, err
		}
		b := one[0]
		if i == binary.MaxVarintLen64-1 && b > 1 {
			return 0, errors.New("varint overflows uint64")
		}
		if b < 0x80 {
			return x | uint64(b)<<uint(7*i), nil
		}
		x |= uint64(b&0x7f) << uint(7*i)
	}
	return 0, errors.New("varint overflows uint64")
}

func WriteRequestFrame(w io.Writer, r Request) error {
	b, err := EncodeRequest(r)
	if err != nil {
		return err
	}
	return writeFrame(w, b, MaxRequestBytes)
}
func ReadRequestFrame(r *bufio.Reader) (Request, error) {
	b, err := readFrame(r, MaxRequestBytes)
	if err != nil {
		return Request{}, err
	}
	return DecodeRequest(b)
}
func WriteResponseFrame(w io.Writer, r Response) error {
	b, err := EncodeResponse(r)
	if err != nil {
		return err
	}
	return writeFrame(w, b, MaxResponseBytes)
}
func ReadVerifiedResponseFrame(r *bufio.Reader, t Target) (VerifiedResponse, error) {
	b, err := readFrame(r, MaxResponseBytes)
	if err != nil {
		return VerifiedResponse{}, err
	}
	return VerifyResponse(t, b)
}
