package archive

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// astra's review of #1070: GetExact with a wrong digest read and hashed every stored representation's chunks before comparing digests, so a
// public reader could make the replica read large records for the price of a small refusal. The digest is now checked against the
// self-authenticated manifest first. The proof that the chunks are not read is a damaged chunk: a wrong digest is still Unavailable (not
// Corrupt), and only the right digest reads the chunk and finds the damage.
func TestGetExactRejectsAWrongDigestWithoutReadingTheChunks(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	require.NoError(t, err)
	q, rec := fixture()
	rec.Body = bytes.Repeat([]byte{7}, 1<<20)
	require.NoError(t, s.Put(q, rec))
	digest, err := ManifestDigest(q, rec)
	require.NoError(t, err)
	got, err := s.GetExact(q, digest)
	require.NoError(t, err)
	require.Equal(t, rec.Body, got.Body)

	loc, err := location(q, recordV2(rec))
	require.NoError(t, err)
	// damage the chunk bytes of the stored record, in whichever layout it was written (#1059 packs a record into one file)
	if packed := packedPath(dir, loc); fileExists(packed) {
		b, err := os.ReadFile(packed)
		require.NoError(t, err)
		b[len(b)-1] ^= 0xff
		require.NoError(t, os.WriteFile(packed, b, 0o600))
	} else {
		chunk := filepath.Join(dir, loc, fileName("body"))
		require.NoError(t, os.WriteFile(chunk, bytes.Repeat([]byte{8}, 1<<20), 0o600))
	}

	for i := 0; i < 2; i++ {
		_, err = s.GetExact(q, [32]byte{9})
		require.ErrorIs(t, err, ErrUnavailable, "a wrong digest is refused from the manifest: the 1 MiB chunk is not read")
	}
	_, err = s.GetExact(q, digest)
	require.ErrorIs(t, err, ErrCorrupt, "the right digest reads the chunks, and checks them")
}
