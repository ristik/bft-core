"""The automatic RejectResult of an abandoned election result on a running package (bft-core #857, contracts#73; briefs/73-reject-result-design.md,
test 9). Opt-in: it waits out the reservation lifetime (about 9 minutes at the runner's ~2 progress rounds per second).

Stage `pos-reject`, right after `pos-election`. Precondition: the election holds a reserved result R that nobody publishes (pos-election reserves it and makes
no handoff). With the counters deliberately unlike (the election's attempt for R and the root's next attempt are compared and must differ), the stage:

1. records R's reservation progress s, the root's next attempt and the custody and registry cursors, and checks R stays Reserved while the registry's progress
   is below s + 1024 (sampled once on the way: no premature rejection);
2. waits, with no operator step, for the roots to order the rejection: R becomes Closed (ResultState 5) in the election and custody's session of R is no
   longer open; the registry's record count and custody's cursor have moved on (the SessionClosed was imported and applied); the root's next attempt moved
   past the rejection's (the control state is aborted at the attempt the rejection named);
3. checks the old material is dead: finalizing R and submitting proofs for R revert (NotReserved);
4. waits for the elections to resume: a new result R2 is reserved (its cadence anchor is R's attempt, long past).

The healthy, timely handoff runs alongside in the stages that follow (pos-proposal onwards, on R2): expiry does not replace the normal Ack path.
The early closure of a result proven lost needs an equivocation submitted to Evidence, which this package cannot produce; that branch is covered by the
real-witness tests of #858 (TestRealRejectLossBranch), not here.

The module only uses what `Rehearsal` already provides (call, view, view_text, expect, wait, say, exec_in, cast_run, evidence, REGISTRY).
"""
import json
import sys
import time

import handoff_ops
import operator_rpc

LIFETIME = 1024   # storage.ResultReservationLifetimeProgress
STALL = 180       # seconds without registry progress that count as a stopped chain
ZERO = '0x' + '00' * 32


def words(raw):
    return [int(raw[2 + 64 * i:2 + 64 * (i + 1)], 16) for i in range((len(raw) - 2) // 64)]


def pos_reject(self):
    deployment = json.loads((self.gen / 'network' / 'pos-deployment.json').read_text())
    custody, election = deployment['custody'], deployment['election']
    result = self.view_text(election, 'openResult()(bytes32)').strip()
    self.expect(result != ZERO, 'the election holds a reserved result (run pos-election first)')

    def result_words():
        return words(self.call('eth_call', [{'to': election, 'data': self.cast_run('calldata', 'result(bytes32)', result)}, 'latest']))

    def session_state():
        return words(self.call('eth_call', [{'to': custody, 'data': self.cast_run('calldata', 'session(bytes32)', result)}, 'latest']))[0]

    def published():
        raw = self.call('eth_call', [{'to': election, 'data': self.cast_run('calldata', 'publication(bytes32)', result)}, 'latest'])
        return words(raw)[10]

    root_rpc = operator_rpc.common_urls(handoff_ops.load_compose(self.gen))[0]
    def root_attempt():
        self.exec_in('root1', 'ubft', 'root', 'handoff', 'evm-context', '--root-rpc', root_rpc, '--out', '/tmp/reject-context.json')
        return json.loads(self.exec_in('root1', 'cat', '/tmp/reject-context.json'))['attempt']

    def progress():
        return self.view(self.REGISTRY, 'progress()(uint64)')[0]

    state, _, election_attempt, reserved_at = result_words()[:4]
    self.expect(state == 1, 'R is Reserved', str(state))
    self.expect(published() == 0, 'R is not published (nobody runs the handoff for it)')
    attempt_before = root_attempt()
    self.say(f'  R {result}: reserved at progress {reserved_at}, election attempt {election_attempt}, root next attempt {attempt_before}')
    self.expect(election_attempt != attempt_before, 'the counters are unlike (the old rule compared them and refused for good)',
                f'election {election_attempt}, root {attempt_before}')
    records0 = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
    cursor0 = self.view(custody, 'recordCursor()(uint64)')[0]

    # 1 no premature rejection: sampled once while the reservation is younger than its lifetime
    halfway = self.wait('the registry reaches half the lifetime', lambda: (lambda p: p if p >= reserved_at + LIFETIME // 2 else None)(progress()), 900)
    self.expect(halfway < reserved_at + LIFETIME and result_words()[0] == 1, 'R is still Reserved before its lifetime', f'progress {halfway}')

    # 2 the roots reject it by themselves
    started = time.monotonic()
    seen = {'progress': None, 'since': started}
    def closed():
        p = progress()
        self.say(f'  progress {p} (due at {reserved_at + LIFETIME}), R state {result_words()[0]}')
        if p != seen['progress']:
            seen['progress'], seen['since'] = p, time.monotonic()
        # a chain that stops certifying never applies the rejection: say so at once (#863 halted the roots right after the due point)
        if time.monotonic() - seen['since'] >= STALL:
            self.expect(False, 'the registry progress keeps rising while the rejection is awaited', f'stuck at {p} for {STALL} s or more')
        return result_words()[0] != 1 or None
    self.wait('the roots order the rejection and the EVM applies it', closed, 1800)
    at = progress()
    final = result_words()[0]
    self.say(f'  R resolved at progress {at}, {time.monotonic() - started:.0f} s after the wait started')
    self.expect(final == 5, 'R is Closed (resolved by a SessionClosed, the only rejection path)', str(final))
    self.expect(at >= reserved_at + LIFETIME, 'no earlier than its lifetime (it was not lost)', f'resolved at {at}, due at {reserved_at + LIFETIME}')
    self.expect(session_state() != 1, "custody's session of R is no longer open", str(session_state()))
    records1 = self.view(self.REGISTRY, 'recordCount()(uint64)')[0]
    cursor1 = self.view(custody, 'recordCursor()(uint64)')[0]
    self.expect(records1 > records0 and cursor1 > cursor0 and cursor1 == records1, 'the record was imported and custody applied it',
                f'records {records0}->{records1}, cursor {cursor0}->{cursor1}')
    attempt_after = root_attempt()
    self.expect(attempt_after == attempt_before + 1, "the root's next attempt moved past the rejection's (aborted at the attempt it named)",
                f'{attempt_before} -> {attempt_after}')

    # 3 the old material is dead
    for name, signature, args in (('finalize', 'finalizeCandidate(bytes32)', [result]),):
        ip = sys.modules[type(self).__module__].PROXY_IPS[0] + '10'
        status, text = self.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'to': election, 'data': self.cast_run('calldata', signature, *args)}, 'latest']}, ip)
        selector = self.cast_run('sig', 'NotReserved()')
        error = json.loads(text).get('error', {}) if status == 200 else {}
        self.expect(str(error.get('data', '')).startswith(selector), f'{name} of the rejected result reverts NotReserved', text[:200])

    # 4 the elections resume
    def resumed():
        out = self.view_text(election, 'openResult()(bytes32)').strip()
        return out if out not in (ZERO, result) else None
    fresh = self.wait('the election reserves a new result', resumed, 900)
    self.say(f'  elections resumed: R2 {fresh}')
    (self.evidence / 'pos-reject.json').write_text(json.dumps({'result': result, 'reservedAt': reserved_at, 'electionAttempt': election_attempt,
        'rootAttemptBefore': attempt_before, 'rootAttemptAfter': attempt_after, 'resolvedAtProgress': at, 'records': [records0, records1],
        'cursor': [cursor0, cursor1], 'next': fresh}, indent=2) + '\n')
