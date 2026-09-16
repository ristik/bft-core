package parentwitness

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

var ErrDownloadedBytes = errors.New("parent witness: downloaded byte budget exhausted")

// downloadedReader accounts bytes as they are read from a response stream. It deliberately
// limits each underlying Read so partial bodies and malformed frames cannot bypass the budget.
type downloadedReader struct {
	r         io.Reader
	left      int64
	used      *int64
	exhausted bool
}

func (r *downloadedReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		r.exhausted = true
		return 0, ErrDownloadedBytes
	}
	if int64(len(p)) > r.left {
		p = p[:int(r.left)]
	}
	n, err := r.r.Read(p)
	r.left -= int64(n)
	*r.used += int64(n)
	if err != nil {
		return n, err
	}
	return n, nil
}

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

// readFrame requires the raw stream reader. A caller must not wrap it in a buffering reader whose
// private buffer could prefetch body bytes before this function admits the declared length.
func readFrame(r io.Reader, max int) ([]byte, error) {
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

func readFrameBudgeted(r io.Reader, max int, used *int64, budget int64) ([]byte, error) {
	if used == nil || budget <= 0 {
		return nil, fmt.Errorf("%w: invalid download budget", ErrBounds)
	}
	br := &downloadedReader{r: r, left: budget - *used, used: used}
	body, err := readFrame(br, max)
	if err != nil {
		if br.exhausted || errors.Is(err, ErrDownloadedBytes) {
			return nil, ErrDownloadedBytes
		}
		return nil, err
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
func ReadRequestFrame(r io.Reader) (Request, error) {
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
func ReadVerifiedResponseFrame(r io.Reader, t Target) (VerifiedResponse, error) {
	b, err := readFrame(r, MaxResponseBytes)
	if err != nil {
		return VerifiedResponse{}, err
	}
	return VerifyResponse(t, b)
}

func readVerifiedResponseFrameBudgeted(r io.Reader, t Target, used *int64, budget int64) (VerifiedResponse, error) {
	b, err := readFrameBudgeted(r, MaxResponseBytes, used, budget)
	if err != nil {
		return VerifiedResponse{}, err
	}
	return VerifyResponse(t, b)
}
