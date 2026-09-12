package rootinput

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestDerive_NilTrustBaseIsARefusal(t *testing.T) {
	f := newFixture(t)
	uc, tr := f.successful(t)
	c := f.context()
	c.TrustBases = stubTrustBases{}
	_, err := Derive(context.Background(), c, uc, tr)
	require.ErrorIs(t, err, ErrUnauthenticated)
}
