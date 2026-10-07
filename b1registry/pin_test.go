package b1registry

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestArtifactFileIdentity(t *testing.T) {
	_, err := Runtime()
	require.NoError(t, err)
	original := artifact
	defer func() { artifact = original }()
	// A semantically identical JSON file is still not the immutable source artifact.
	artifact = append(append([]byte(nil), artifact...), '\n')
	_, err = Runtime()
	require.ErrorIs(t, err, ErrArtifact)
}
