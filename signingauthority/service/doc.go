/*
Package service puts the signing authority in its own process.

The F6c profile (docs/design/f6c-signing-state-contract.md §3) selects an independent key-owning
authority, and says what "independent" has to mean: the authority host is outside the shard node's
backup, restore, snapshot, key-export and process-cloning domains, and a same-directory sidecar does
not satisfy it merely by having a different PID. The authority package alone cannot provide that,
because an in-process authority shares the shard's lifetime, its memory and its credentials. This
package is the boundary across which the two can be separated: a transport carrying exactly the four
client operations, and two credential spaces on two endpoints.

What crosses the wire is an operation, never bytes to sign. A client may reserve a structured
request, sign what was reserved, retain the response and release it. There is no message that
carries a signing request of any other shape, no message that reads or writes a key, and no message
on the client endpoint that replaces a session.

Two endpoints, two credentials:

  - The client endpoint serves the shard node. It accepts the current client credential and nothing
    else, and an operation from any other credential is signing-session-fenced, which is the same
    answer the authority gives an old generation in one process.
  - The operator endpoint serves the operator. It has its own credential, provisioned when the
    server is built, and it is the only place session replacement, status and enrollment live.

The shard node never holds a signingauthority.Session. Replacement mints the session inside the
authority process and returns a bearer credential the server maps to it, so the token that cannot be
minted stays where the key is, and a fenced shard process cannot unfence itself: the credential it
holds is the thing that was invalidated.

What this package does not do. It does not authenticate hosts, encrypt the wire or survive a hostile
operating system: it is a local transport for a private profile, and a Unix domain socket in a
directory only the two parties can enter is the isolation it assumes. It does not activate anything
either. Nothing selects an authority for a deployed shard node here, no command runs a server, and
the restored non-voting gate is untouched.
*/
package service
