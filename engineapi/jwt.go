package engineapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Engine API authentication (execution-apis/src/engine/authentication.md):
// every call carries a bearer JWT, HS256-signed with a 32-byte shared
// secret, whose only required claim is "iat" — issued-at, which the server
// requires be within 60 seconds of its own clock. Hand-rolled rather than a
// JWT library: one claim, one algorithm, not worth a dependency.

// Secret is the 32-byte shared secret read from a jwt.hex file — the
// convention reth (and every other post-merge client) uses: a single line
// of 64 hex characters, optionally 0x-prefixed.
type Secret [32]byte

func ParseSecret(hexStr string) (Secret, error) {
	hexStr = strings.TrimSpace(hexStr)
	hexStr = strings.TrimPrefix(hexStr, "0x")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return Secret{}, fmt.Errorf("engineapi: decoding JWT secret: %w", err)
	}
	if len(b) != 32 {
		return Secret{}, fmt.Errorf("engineapi: JWT secret must be 32 bytes, got %d", len(b))
	}
	var s Secret
	copy(s[:], b)
	return s, nil
}

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	IAT int64 `json:"iat"`
}

// Token mints a fresh bearer token. Engine API tokens are single-use in
// practice — the 60-second freshness window means a client either signs one
// per call or accepts a short reuse window; this signs one per call, which
// costs nothing (HMAC-SHA256 over ~40 bytes) and avoids ever having to
// reason about how close to the edge of the window a reused token is.
func (s Secret) Token(now time.Time) (string, error) {
	header, err := json.Marshal(jwtHeader{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("engineapi: encoding JWT header: %w", err)
	}
	claims, err := json.Marshal(jwtClaims{IAT: now.Unix()})
	if err != nil {
		return "", fmt.Errorf("engineapi: encoding JWT claims: %w", err)
	}

	signingInput := b64(header) + "." + b64(claims)
	mac := hmac.New(sha256.New, s[:])
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func b64(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}
