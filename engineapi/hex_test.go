package engineapi

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQuantity_RoundTrip(t *testing.T) {
	cases := []struct {
		val  uint64
		want string
	}{
		{0, `"0x0"`},
		{5, `"0x5"`},
		{256, `"0x100"`},
		{1787146522, `"0x6a85b11a"`},
	}
	for _, c := range cases {
		b, err := json.Marshal(quantity(c.val))
		require.NoError(t, err)
		require.Equal(t, c.want, string(b))

		var q quantity
		require.NoError(t, json.Unmarshal(b, &q))
		require.Equal(t, c.val, uint64(q))
	}
}

func TestQuantity_RejectsLeadingZero(t *testing.T) {
	var q quantity
	err := json.Unmarshal([]byte(`"0x0f"`), &q)
	require.Error(t, err)
}

func TestData_RoundTrip(t *testing.T) {
	orig := data{0xDE, 0xAD, 0xBE, 0xEF}
	b, err := json.Marshal(orig)
	require.NoError(t, err)
	require.Equal(t, `"0xdeadbeef"`, string(b))

	var d data
	require.NoError(t, json.Unmarshal(b, &d))
	require.Equal(t, orig, d)
}

func TestData_EmptyRoundTrip(t *testing.T) {
	b, err := json.Marshal(data{})
	require.NoError(t, err)
	require.Equal(t, `"0x"`, string(b))
}

func TestData_RejectsOddLength(t *testing.T) {
	var d data
	err := json.Unmarshal([]byte(`"0xabc"`), &d)
	require.Error(t, err)
}

func TestData32_EnforcesLength(t *testing.T) {
	var d data32
	err := json.Unmarshal([]byte(`"0xdead"`), &d)
	require.Error(t, err)

	valid := `"0x` + repeat("ab", 32) + `"` // 32 bytes
	require.NoError(t, json.Unmarshal([]byte(valid), &d))
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}
