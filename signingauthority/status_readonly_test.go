package signingauthority

import (
	"context"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// countingSigner counts every signature the authority's key produces.
type countingSigner struct {
	abcrypto.Signer
	signatures atomic.Int64
}

func (c *countingSigner) SignBytes(data []byte) ([]byte, error) {
	c.signatures.Add(1)
	return c.Signer.SignBytes(data)
}

func (c *countingSigner) SignHash(data []byte) ([]byte, error) {
	c.signatures.Add(1)
	return c.Signer.SignHash(data)
}

// the authority's whole mutable state, compared by value.
type authoritySnapshot struct {
	generation   uint64
	state        health
	rec          record
	scopeVersion uint64
	enroll       Enrollment
}

func snapshot(a *Authority) authoritySnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return authoritySnapshot{generation: a.generation, state: a.state, rec: a.rec, scopeVersion: a.scopeVersion, enroll: a.enroll}
}

// Reading the status is read-only: it signs nothing and changes no state, whatever the authority holds (a reservation with a retained
// response, a latched fault) and however often, and from however many goroutines, it is asked.
func TestStatusIsReadOnly(t *testing.T) {
	setups := map[string]func(*testing.T, *fixture) (*Authority, Session){
		"an idle authority": func(t *testing.T, f *fixture) (*Authority, Session) { return f.session(t) },
		"a held reservation": func(t *testing.T, f *fixture) (*Authority, Session) {
			a, s := f.session(t)
			_, err := a.Reserve(context.Background(), s, f.assignment(t, 5, 11))
			require.NoError(t, err)
			return a, s
		},
		"a signed, retained response": func(t *testing.T, f *fixture) (*Authority, Session) {
			a, s := f.session(t)
			_, err := a.Reserve(context.Background(), s, f.assignment(t, 5, 11))
			require.NoError(t, err)
			require.NoError(t, a.Sign(s))
			require.NoError(t, a.RetainResponse(s))
			return a, s
		},
		"a latched fault": func(t *testing.T, f *fixture) (*Authority, Session) {
			a, s := f.session(t)
			a.MarkUntrusted("an operator saw something this authority cannot see")
			return a, s
		},
	}
	for name, setup := range setups {
		t.Run(name, func(t *testing.T) {
			a, _ := setup(t, newFixture(t, 1))
			counter := &countingSigner{Signer: a.signer}
			a.mu.Lock()
			a.signer = counter
			a.mu.Unlock()
			before := snapshot(a)
			want := a.Status()

			var wg sync.WaitGroup
			for i := 0; i < 8; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < 50; j++ {
						got := a.Status()
						if got != want {
							t.Errorf("status changed while only being read: %+v != %+v", got, want)
							return
						}
					}
				}()
			}
			wg.Wait()

			require.Zero(t, counter.signatures.Load(), "reading the status signed something")
			require.True(t, reflect.DeepEqual(before, snapshot(a)), "reading the status changed the authority's state")
			require.Equal(t, want, a.Status())
		})
	}
}
