# Root and shard-node RPC: what is exposed, and how to keep it private (#533)

The root node's `--rpc-server-address` (and the shard node's) serve operator endpoints that have **no authentication of their own**. The supported
posture is: bind to loopback or to an isolated operator network, never publish the port, never proxy it. The node logs a `WARN` at start when the
address is not loopback (`the root RPC address is not loopback and has no operator authentication ...`). Authenticating the endpoints is not
implemented (owner decision for now: documentation and the warning only).

## How to keep it private

1. **Bind to loopback**: `--rpc-server-address 127.0.0.1:PORT`. Operators then reach it over SSH (`ssh -L`) or from the host.
2. **Containers**: the testnet binds `127.0.0.1` (root 8002, shard 9101) and the root and shard node of each validator entity share one network namespace
   (`deploy/testnet`: a holder container per entity), so nothing else on the Docker network can reach either listener, guarded or not; operators exec into the
   entity (`docker compose exec`). The start-up WARN must therefore NOT appear there: if it does, the binding is wrong. Prometheus reads the two metrics documents
   through a relay in the namespace that serves only those exact GET paths. (A package that binds `0.0.0.0` on a shared network would expose every endpoint
   below, the unguarded writes included, to anything on that network.)
3. **Firewall**: if the port must be reachable by other machines of the operator set (cross-host root clusters), allow only their addresses
   (security group / `iptables`), and put them on a private network, not the public one.
4. **No reverse proxy in front of it, and never behind the public JSON-RPC gateway.** The handoff and Q3 operator endpoints decide "local" from the
   TCP peer address being loopback (`localOperatorRequest`): a proxy on the same host makes every remote request arrive from `127.0.0.1` and
   defeats that check. If an authenticating proxy is unavoidable, it must authenticate every request itself and expose only the read-only
   endpoints below, never the write endpoints.

## What each endpoint can do if a stranger reaches it

Root (`cli/ubft/cmd/root_node.go`). "Loopback peer" = the endpoint refuses a request whose TCP peer is not loopback and needs
`Content-Type: application/json` without an `Origin` header (blocks browser CSRF); it is a safeguard against a *network* caller, not
authentication.

| Endpoint | Guard | Effect if exposed (and the guard does not hold) |
|---|---|---|
| `PUT /api/v1/trustbases` | **none** | Stores a trust base. The store accepts only one that extends the previous epoch's (`quorumweight.VerifyTrustBase`: signed by the previous quorum), for an epoch not yet stored, so a stranger cannot install a forged trust base; they can pre-store a *valid* one early (it is what the committee will install anyway) and probe the store. Not a grant of authority, but it is a write: keep it private. |
| `PUT /api/v1/configurations` | none; under profile 2 it refuses every write (403) | Without profile 2 (legacy lab setups only): adds a shard configuration to this node. Not used by the testnet or the lanes. |
| `GET /api/v1/trustbases`, `GET /api/v1/roundInfo`, `/api/v1/metrics` | none | Read-only: trust bases (public), the node's round/state summary, Prometheus metrics (operational detail: peer ids, round timings). |
| `POST /api/v1/handoff/plan` | loopback peer | Asks this validator to build, **sign** (the plan and its abort domain, with its own key) and submit a handoff plan. A plan carries the operators' endorsements/receipts and is verified by consensus: without them it is refused. A caller can cause signatures over a plan this validator derives from its own state, load and refused-plan noise, not an unauthorised handoff. |
| `POST /api/v1/handoff/intent`, `/endorse`, `/evm-assignment/context` | loopback peer | Register a plan another validator built, submit an endorsement, build the EVM assignment context. Verified against the root's own state and signatures; useless without valid operator signatures. |
| `POST /api/v1/handoff/q3-candidate` | loopback peer | Returns the V3 candidate this validator derives from its committed state. Registers nothing. |
| `POST /api/v1/handoff/q3-stage` | loopback peer | Stages a candidate that is consistent with the root's own state (**no signatures are checked at staging**). Staging sets the grant of the records feed for the staged successor: a caller can give feed read access to any peer id, or replace a real joiner's grant until it is staged again (#527). The feed serves certified, non-secret data. An abandoned candidate keeps its grant until the next stage or install. |
| `POST /api/v1/handoff/abort`, `/abort/status` | loopback peer | `SubmitHandoffAbort` makes **this validator sign an abort approval** for the pending handoff with its own key (`handoff_operator.go`) and feed it to the approval handler. A caller that gets past the guard on enough validators to reach the abort quorum **aborts the attempt** (not only delays it); it cannot make a handoff commit. |
| `POST /api/v1/q3/status`, `/activation`, `/bundle`, `/history`, `/signers` | loopback peer | Read-only views of the verified Q3 history and the latest certificate signers. |
| `POST /api/v1/pos/control` (only with `--proof-of-stake`) | loopback peer | Offers a Retirement or RejectResult control for ordering; the root checks it against its own state like any other control. |

Shard node (`--rpc-server-address`): `GET /api/v1/health` and `/api/v1/metrics` are read-only; `GET /api/v1/operator/status` is the archive/operator
status. The Q3 lane endpoints (`POST /api/v1/q3/stage`, `/q3/status`) are **loopback-guarded like the root's** (`shardQ3Staging.register` wraps both in `q3Endpoint`,
which starts with `localOperatorRequest`; `TestShardQ3EndpointsRefuseANonLoopbackPeer`). Staging checks the candidate against the node's verified history and its
own identity (no signatures): a caller that passes the guard can make the node stage a *valid* candidate early or refuse one with a consistency error (the lanes'
stage refusals come from here); it cannot activate anything (activation needs the committed record and the verified bundle). The health and metrics
endpoints are the unguarded ones. The proxy caveat above applies here too.

The effects of the plan, abort and pos-control rows are from reading the handlers, not from tests.

## What is NOT exposed by these endpoints

No key material is disclosed through either RPC and nothing arbitrary can be signed: the signing authority has its own operator socket and credential
(`signing-authority`), unrelated to these ports. But the guarded root endpoints do make the validator **sign fixed message types over its own committed state**:
`handoff/plan` (the plan and its abort domain), `handoff/endorse` (an endorsement of a Prepare-bound state) and `handoff/abort` (an abort approval). That is why
the loopback check must not be defeated by a proxy: whoever passes it can have this validator sign those messages. The remaining risks are availability,
early/probing writes of *valid* data, and disclosure of operational metadata.

## If authentication is added later (#533 option)

All write endpoints (`PUT /trustbases` and the loopback-guarded handoff and Q3 endpoints of both nodes) would take the same operator
credential check together; until then this page and the start-up warning are the control.
