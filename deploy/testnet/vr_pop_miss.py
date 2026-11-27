#!/usr/bin/env python3
"""vr-pop-miss (bft-core#1319, astra option (a)): an incumbent that stops answering its handoff PoP is parked by a certified miss.

On a Compose VR/P85 generation with five genesis validators (run it after vr-pos-publish):

1. the last validator's root node stops: its pod, execution client, authority and shard node keep running, so its P85 possession proof
   still makes the next output Published, but its root never sends the VR handoff possession proof;
2. the next election names all five; every member sends its P85 proof and the output is Published; the roots commit the intent's PoP
   request (control op 6) with a cutoff POP_WINDOW in root progress after it;
3. at the cutoff the four live roots each state the stopped member's miss (root log "PoP misses stated at the request's cutoff");
4. the output expires with no handoff; the roots reject it with the miss certificate (four of five, the ordinary quorum by weight of the
   whole predecessor committee): the SealRegistry holds OutputRejected (Expired), PoPMissed (kind 9, the stopped member's bit) and
   SessionClosed, and ElectionPolicy parks the stopped incumbent for 2 x LIFETIME from that record, and nobody else;
5. the next election names the four others (the floor of four with an eligible replacement set), they publish it and the roots activate the
   next root epoch, while the parked incumbent stays bonded, indexed and not retiring.

The stopped root stays down until the generation's teardown.
"""
import json
import re
import time

import vr_recover
import vr_reject

LIFETIME, PARK_PERIOD = vr_reject.LIFETIME, vr_reject.PARK_PERIOD
POP_WINDOW = LIFETIME // 4   # vrschema.PoPWindow
REC_POP_MISSED, REC_SESSION_CLOSED = 9, 1
OUT_RESERVED, OUT_PUBLISHED, OUT_CLOSED = vr_reject.OUT_RESERVED, vr_reject.OUT_PUBLISHED, vr_reject.OUT_CLOSED
SAY_EVERY = vr_reject.SAY_EVERY


def find_miss(record_at, at, rid):
    """The PoPMissed record right after the OutputRejected at index `at` of `rid`, decoded: (index, deadline, bitmap, progress), or None."""
    rec = record_at(at + 1)
    if rec['kind'] != REC_POP_MISSED or len(rec['data']) != 3 or rec['data'][0] != int(rid, 16):
        return None
    return {'index': at + 1, 'deadline': rec['data'][1], 'bitmap': rec['data'][2], 'progress': rec['progress']}


def stated(log):
    """The miss statements a root logged: [(deadline, missing ids)]."""
    out = []
    for line in log.splitlines():
        if "PoP misses stated at the request's cutoff" not in line:
            continue
        dl = re.search(r'deadline\W+(\d+)', line)
        ms = re.search(r'missing\W+\[([\d ]*)\]', line)
        out.append((int(dl.group(1)) if dl else None, [int(x) for x in ms.group(1).split()] if ms else None))
    return out


def vr_pop_miss(r):
    if (r.manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('vr-pop-miss needs a VR/P85 Compose generation')
    incumbents = r.members()
    r.expect(len(incumbents) >= 5, 'vr-pop-miss has at least five genesis validators (the floor of four after one is parked)', str(incumbents))
    rec = vr_recover.Recovery(r, 1)
    rec.since = vr_recover.utc()
    ev = r.evidence / 'pop-miss'
    ev.mkdir(parents=True, exist_ok=True)
    gen, dep = r.gen, rec.deployment
    vr_addr, election = dep['registry'], dep['election']
    ids = {m: vr_recover.genesis_identity(gen, m)[0] for m in incumbents}
    x = incumbents[-1]
    xid = ids[x]
    live = [m for m in incumbents if m != x]
    times = {'start': rec.since}

    def output(rid):
        return vr_reject.decode_output(r.call('eth_call', [{'to': vr_addr, 'data': r.cast_run('calldata', 'output(bytes32)', rid)}, 'latest']))

    def open_result():
        rid = r.view_text(election, 'openResult()(bytes32)').strip()
        return rid if int(rid, 16) else None

    def progress():
        return r.view(r.REGISTRY, 'progress()(uint64)')[0]

    def epoch_now():
        return rec.root_view(live[0])['activeEpoch']

    # 1. the withholding incumbent: its root node stops, nothing else of it
    rec.dc('stop', f'root{x}')
    times['stopped'] = vr_recover.utc()
    epoch = epoch_now()
    r.say(f'  validator {x} (identity {xid}): root stopped at root epoch {epoch}; its pod, ureth, authority and shard node keep running')

    # 2. the next result names all five (a result reserved before the stop is handed off first)
    def publish(rid):
        def probe():
            cur = output(rid)
            if cur['state'] != OUT_RESERVED:
                return cur['state']
            for m in incumbents:
                done = rec.cli(m, rec.home(m, 'recover-participant'), 'validator', 'pos-publish', '--participate', '--result', rid,
                               '--proof-member', str(ids[m]), mounts=[(vr_recover.authority_dir(gen, rec.compose, m), '/home/authority')], check=False)
                r.say(f'  member {ids[m]}: exit {done.returncode}: ' + r.scrub(' | '.join((done.stdout + done.stderr).strip().splitlines()[-2:])[-240:]))
            return None
        return r.wait(f'every elected member proves possession and {rid[:18]} is published', probe, 1800, every=20)

    deadline = time.monotonic() + 5400
    while True:
        rid = r.wait('an election result is open', open_result, 3600, every=15)
        first = output(rid)['state']
        if first == OUT_RESERVED:
            state = publish(rid)
            o = output(rid)
            if xid in o['members']:
                break
        r.expect(time.monotonic() < deadline, 'a result naming the stopped incumbent is reserved within 90 minutes', str(epoch))
        r.say(f'  result {rid[:18]} (state {first}) was open before the stop or lacks the incumbent: handed off first (root epoch {epoch})')
        epoch = rec.participate_until(epoch)
    times['published'] = vr_recover.utc()
    r.say(f'  result {rid}: members {o["members"]}, state {state}, reserved at progress {o["reserved"]}, expires at {o["expires"]}')
    r.expect(state == OUT_PUBLISHED, 'the 5-member output is Published', str(state))
    r.expect(sorted(o['members']) == sorted(ids.values()), 'the output names every incumbent', str(o['members']))
    bit = o['members'].index(xid)

    # 3. the PoP request is committed and, at its cutoff, the live roots state the miss
    def requested():
        for m in live:
            log = rec.logs(f'root{m}')
            if 'proposing the PoP request' in log:
                return m
        return None
    proposer = r.wait('a root orders the PoP request of the intent', requested, 1200, every=15)
    times['requested'] = vr_recover.utc()
    r.say(f'  root{proposer} proposed the PoP request at progress about {progress()}')

    def statements():
        got = {m: stated(rec.logs(f'root{m}')) for m in live}
        return got if all(got.values()) else None
    st = r.wait('every live root states its misses at the cutoff', statements, (POP_WINDOW // 2) * 3 + 1800, every=60)
    times['stated'] = vr_recover.utc()
    r.say(f'  stated misses: {st}')
    r.expect(all(v[-1][1] == [xid] for v in st.values()), f'every live root stated exactly the stopped incumbent {xid}', str(st))
    cutoff = st[live[0]][-1][0]
    r.expect(cutoff is not None and cutoff <= o['expires'], 'the cutoff lies within the lifetime', f'{cutoff} <= {o["expires"]}')

    # 4. expiry, the certified rejection and the park
    last, premature = 0.0, []
    def expired():
        nonlocal last
        p, cur = progress(), output(rid)
        if cur['state'] != OUT_PUBLISHED and p < o['expires']:
            premature.append(f'state {cur["state"]} at progress {p} < {o["expires"]}')
            return 'premature'
        if time.monotonic() - last >= SAY_EVERY:
            last = time.monotonic()
            r.say(f'  progress {p} of {o["expires"]} (state {cur["state"]}, root epoch {epoch_now()})')
        return p if p >= o['expires'] else None
    at = r.wait('the output reaches its expiry with no handoff', expired, 4 * 3600, every=30)
    r.expect(not premature, 'no rejection before the expiry', '; '.join(premature))
    r.expect(epoch_now() == epoch, 'no handoff happened while the incumbent\'s PoP was missing', str(epoch_now()))
    r.wait('the roots reject the expired output (VR: Closed)', lambda: output(rid)['state'] == OUT_CLOSED or None, 2700, every=10)
    times['rejected'] = vr_recover.utc()
    logs = {}
    for m in incumbents:
        logs[m] = rec.logs(f'root{m}')
        r.keep_redacted(ev / f'root{m}.log', logs[m])
    ordered = [l for m in live for l in logs[m].splitlines() if 'a RejectResult is ordered in this proposal' in l]
    r.say('  ordered: ' + (r.scrub(ordered[-1][-300:]) if ordered else 'no log line'))

    def record_at(i):
        return vr_reject.decode_record(r.call('eth_call', [{'to': r.REGISTRY, 'data': r.cast_run('calldata', 'recordAt(uint64)', str(i))}, 'latest']))
    count = r.view(r.REGISTRY, 'recordCount()(uint64)')[0]
    rej = vr_reject.find_rejection(record_at, count, rid)
    r.expect(rej is not None, 'the SealRegistry holds the ordered OutputRejected of the result', str(count))
    r.expect(rej['reason'] == vr_reject.REJ_EXPIRED, 'the ordered rejection is Expired', str(rej))
    miss = find_miss(record_at, rej['index'], rid)
    r.say(f'  OutputRejected record {rej["index"]} (readyBitmap {rej["bitmap"]:#06x}); PoPMissed {miss}')
    r.expect(miss is not None, 'a PoPMissed record (kind 9) follows the OutputRejected', str(rej))
    r.expect(miss['bitmap'] == 1 << bit, f'the certified miss is exactly the stopped incumbent (bit {bit})', f'{miss["bitmap"]:#06x}')
    r.expect(miss['deadline'] == cutoff and miss['progress'] == rej['progress'], 'the record names the cutoff, at the rejection\'s anchor', str(miss))
    closed = record_at(rej['index'] + 2)
    r.expect(closed['kind'] == REC_SESSION_CLOSED and closed['data'][:1] == [int(rid, 16)], 'the SessionClosed follows', str(closed))
    parked = {i: r.view(election, 'parkedUntil(uint64)(uint64)', str(i))[0] for i in ids.values()}
    r.say(f'  parkedUntil: {parked}')
    r.expect(parked[xid] == miss['progress'] + PARK_PERIOD, 'the incumbent is parked for 2 x LIFETIME from the record', str(parked[xid]))
    r.expect(not any(v for i, v in parked.items() if i != xid), 'nobody else is parked', str(parked))

    # 5. the next election: the four others, and the handoff
    nrid = r.wait('the election reserves the next result', lambda: (lambda n: n if n and n != rid else None)(open_result()), 1800, every=15)
    frozen = vr_reject.frozen_ids(r.view_text(election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', nrid))
    r.say(f'  next result {nrid}: P85 froze {frozen}')
    others = sorted(i for i in ids.values() if i != xid)
    r.expect(sorted(frozen) == others, 'P85 froze the four others (the incumbent is parked)', str(frozen))
    target = rec.participate_until(epoch)
    times['activated'] = vr_recover.utc()
    no = output(nrid)
    r.expect(sorted(no['members']) == others, 'the next output names the four others', str(no['members']))
    r.expect(target > epoch, f'the handoff completed: root epoch {epoch} -> {target}', str(target))
    pos = rec.position(xid).splitlines()
    r.say(f'  parked incumbent position: open lots {pos[6]}, retirement requested {pos[8]}')
    r.expect(int(pos[6].split()[0]) > 0 and pos[8].strip() == 'false', 'the parked incumbent is still bonded and not retiring', str(pos))
    r.expect(r.view_text(election, 'isIndexed(uint64)(bool)', str(xid)).strip() == 'true', 'the parked incumbent is still in the live index')
    r.expect(r.view(election, 'parkedUntil(uint64)(uint64)', str(xid))[0] > progress(), 'the incumbent is still parked')
    (ev / 'result.json').write_text(json.dumps({'result': rid, 'members': o['members'], 'withholding': xid, 'reservedAt': o['reserved'],
        'expiresAt': o['expires'], 'expiredSeenAt': at, 'cutoff': cutoff, 'stated': {str(k): v for k, v in st.items()}, 'rejection': rej,
        'miss': miss, 'parkedUntil': {str(k): v for k, v in parked.items()}, 'next': nrid, 'nextMembers': no['members'],
        'rootEpoch': [epoch, target], 'times': times}, indent=1) + '\n')
