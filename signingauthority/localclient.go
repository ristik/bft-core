package signingauthority

import "context"

/*
LocalClient binds one session to one in-process authority.

The four client operations of this contract each take a session, because the authority serves one
admitted client at a time and fences the rest. Nothing downstream of the session holder should have
to carry that token around, and once the authority is in its own process the shard node does not
hold a session at all: it holds a credential its operator provisioned, and the session lives with
the authority. This type is the in-process counterpart, for a single-process deployment and for
tests: whoever is entitled to the session binds it once, and hands on a client that cannot name a
different one.

It is not a way to obtain a session. Session replacement remains ReplaceSession on the authority
itself, which is the operator control plane.
*/
type LocalClient struct {
	authority *Authority
	session   Session
}

// NewLocalClient binds a session to an authority. The caller must already hold the session.
func NewLocalClient(authority *Authority, session Session) *LocalClient {
	return &LocalClient{authority: authority, session: session}
}

func (c *LocalClient) Reserve(ctx context.Context, req Request) (*Authorization, error) {
	return c.authority.Reserve(ctx, c.session, req)
}

func (c *LocalClient) Sign(context.Context) error { return c.authority.Sign(c.session) }

func (c *LocalClient) RetainResponse(context.Context) error {
	return c.authority.RetainResponse(c.session)
}

func (c *LocalClient) Release(_ context.Context, round uint64, digest [32]byte) ([]byte, error) {
	return c.authority.Release(c.session, round, digest)
}
