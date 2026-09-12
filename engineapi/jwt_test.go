package engineapi

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseSecret_AcceptsWithAndWithoutPrefix(t *testing.T) {
	hex64 := repeat("ab", 32)
	s1, err := ParseSecret(hex64)
	require.NoError(t, err)
	s2, err := ParseSecret("0x" + hex64)
	require.NoError(t, err)
	require.Equal(t, s1, s2)
}

func TestParseSecret_RejectsWrongLength(t *testing.T) {
	_, err := ParseSecret("abcd")
	require.Error(t, err)
}

func TestToken_HasThreeSegmentsAndValidClaims(t *testing.T) {
	secret, err := ParseSecret(repeat("cd", 32))
	require.NoError(t, err)

	now := time.Unix(1787146522, 0)
	tok, err := secret.Token(now)
	require.NoError(t, err)

	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)

	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header jwtHeader
	require.NoError(t, json.Unmarshal(headerJSON, &header))
	require.Equal(t, "HS256", header.Alg)
	require.Equal(t, "JWT", header.Typ)

	claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims jwtClaims
	require.NoError(t, json.Unmarshal(claimsJSON, &claims))
	require.Equal(t, now.Unix(), claims.IAT)
}

func TestToken_DifferentSecretsProduceDifferentSignatures(t *testing.T) {
	s1, err := ParseSecret(repeat("11", 32))
	require.NoError(t, err)
	s2, err := ParseSecret(repeat("22", 32))
	require.NoError(t, err)

	now := time.Unix(1000, 0)
	t1, err := s1.Token(now)
	require.NoError(t, err)
	t2, err := s2.Token(now)
	require.NoError(t, err)
	require.NotEqual(t, t1, t2)
}
