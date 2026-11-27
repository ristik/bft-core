# Event catalogue

Status: VT-12 (bft-core#1152). Every lifecycle log line below carries the structured key `event=<dotted.name>`. The names are a compatibility
promise: they are never renamed or reused, only added. The human message may be reworded; scripts and log alerts match `event=`, never the
message. `TestEventCatalogue` (monitoring package) fails on a renamed or removed name, on a name missing from this table, and on a log line that
lost its `event` attribute. The messages are pinned too, because the lane scripts still grep some of them (for example `handoff activated`,
`root handoff outcome`, `retirement requested`).

The `event` attribute is always the LAST attribute of its line, so the lane scripts' greps that expect `msg=... key=value` to be adjacent keep matching.

Lines are logged with `--log-format json` or `text`; with text the key reads `event=vr.member.ready`, with JSON `"event":"vr.member.ready"`.
Severity is the level the line is logged at.

| event | level | process | message | what happened |
|---|---|---|---|---|
| `vr.identity.none` | info | exporter | validator state changed | the watched operator has no VR identity |
| `vr.identity.applied` | info | exporter | validator state changed | applied: the identity is in PoA state Applied |
| `vr.identity.admitted` | info | exporter | validator state changed | admitted by governance |
| `vr.identity.joining` | info | exporter | validator state changed | elected: Joining, it will be in the next committee |
| `vr.identity.active` | info | exporter | validator state changed | active: in the committee |
| `vr.identity.exit_requested` | info | exporter | validator state changed | exit requested |
| `vr.identity.removing` | info | exporter | validator state changed | removal in progress |
| `vr.identity.leaving` | info | exporter | validator state changed | leaving at the next boundary |
| `vr.identity.exited` | info | exporter | validator state changed | exited |
| `vr.identity.parked` | warn | exporter | validator state changed | parked: not electable |
| `vr.module.health_changed` | info/warn | exporter | VR module health changed | the election module's health changed (warn when not Healthy) |
| `vr.intent.derived` | info | root | VR handoff: intent | admitted or elected: a handoff intent exists |
| `vr.intent.died` | info | root | VR handoff: the intent died | the intent was superseded or expired |
| `vr.member.possession` | info | root | VR handoff member: possession proof | this member sent its possession proof |
| `vr.member.ready` | info | root | VR handoff member: readiness | ready: this member signed its readiness |
| `vr.member.staged` | info | root | VR handoff member: candidate staged | staged: the successor candidate is staged for the switch |
| `vr.upgrade.required` | warn | root | VR handoff member: UpgradeRequired | the schedule holds a rule this binary lacks; the node signs no readiness |
| `activation.latched` | info | root | (VT-07, #1228) | an activation rule was latched at the commit into its epoch (attributes `rule`, `epoch`, `digest`) |
| `activation.active` | info | root | (VT-07, #1228) | an activation rule is active from its epoch |
| `upgrade.required` | warn | root | (VT-07, #1228) | the schedule holds a rule this binary lacks (`state=pending` ahead of the epoch, `effective` once committed); the VT-07 form of `vr.upgrade.required`, with the rule attributes |
| `vr.handoff.assembled` | info | root | VR handoff: assembled | the view's assembly was made |
| `vr.handoff.certified` | info | root | VR handoff: a complete verified certificate is held (I-RET) | a complete readiness certificate is held |
| `vr.handoff.ordering` | info | root | VR handoff: ordering the | the leader orders a handoff step (Prepare, Freeze, H) |
| `vr.handoff.refused` | warn | root | VR handoff: the leader leaves out a refused | the leader's own executor refuses its handoff record (kind `prepare` or `freeze`) the way every root would, for this handoff identity: it proposes an ordinary block instead and does not order that step again; logged once per identity and kind. A refused Prepare or Freeze leaves the election result to expire through RejectResult (#1306). A refusal that can clear by itself (VR input or a witness this root lacks, a pending acknowledgement, the shard acknowledgement gate, the activation gates) and every Commit, Abort or V3 refusal are not remembered: the record is left out of that round and tried again the next, logged once as `root handoff: the leader leaves out a <kind> its own executor refuses for now` (warn; error for a `commit`: an endorsed Freeze does not lapse, the EVM stays frozen until an old-set Abort) |
| `vr.handoff.shard_staged` | info | root | VR handoff: the paired shard node holds the staged successor | the paired shard node holds the successor |
| `vr.output.published` | info | root | VR output published: source recorded | VR's open output was published; its source is recorded |
| `vr.recovery.ordered` | info | root | VR recovery: the leader orders the Prepare of the exact recovery | the leader orders the exact recovery |
| `vr.recovery.followed` | info | root | VR recovery: the leader follows the exact recovery | a leader follows the recovery in progress |
| `vr.recovery.dropped` | info | root | VR recovery: the request is dropped | a recovery request was dropped |
| `root.handoff.outcome` | info | root | root handoff outcome | the handoff committed, aborted or lapsed (attribute `phase`) |
| `root.epoch.switch` | info | root | switching epoch in process at the committed activation | joined: the root began its in-process switch into the successor epoch (logged before the installation, which can still fail: see `root.epoch.switch_failed`) |
| `root.epoch.switch_failed` | error | root | in-process epoch switch failed | the switch failed; signing stays fenced and the process exits to its recovery |
| `shard.handoff.activated` | info | shard | handoff activated | active: the shard node activated the successor assignment |
| `exit.retirement.requested` | info | root | retirement requested | exit: a retirement request was discovered |
| `exit.retirement.proof_ready` | info | root | retirement proof ready | the retirement proof was collected |
| `exit.retirement.complete` | info | root | retirement request complete | the generation is retired in the registry |
| `root.round.timeout` | info | root | local timeout | a late round: the local round timer fired |
| `root.vote.missed` | warn | root | this root ended rounds without a vote | a committee member ended three rounds in a row without a vote |
| `root.recovery.triggered` | warn | root | failure to process QC triggers recovery | behind: a QC the local state does not match |
| `shard.certification.stalled` | warn | shard | certification work has not progressed | behind: submitted work is not being certified |
| `node.peers.low` | warn | root, shard | connected peers are below the committee | fewer peers connected than expected for 30 s |
| `node.peers.recovered` | info | root, shard | connected peers are back to the committee | the peers are back |
| `node.disk.low` | warn | root, shard | disk space is low | free space below 10 percent (logged when a scrape sees it) |
| `node.disk.recovered` | info | root, shard | disk space recovered | free space is back above 10 percent |

The validator lifecycle, in order: `vr.identity.applied` (applied), `vr.identity.admitted`, `vr.intent.derived` (elected), `vr.member.possession`,
`vr.member.ready` (ready), `vr.member.staged`, `root.epoch.switch` (joined), `shard.handoff.activated` and `vr.identity.active` (active),
`vr.identity.exit_requested`, `exit.retirement.*` and `vr.identity.exited` (exit), `vr.identity.parked` (parked).
