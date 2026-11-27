#!/usr/bin/env python3
"""vr-pop-miss (bft-core#1319, astra option (a)): an incumbent that stops answering its handoff PoP is parked by a certified miss, and the next
election proceeds with an eligible replacement at the four-member floor.

On a Compose VR/P85 generation with four genesis validators (run it after vr-pos-publish):

1. a fifth entity (joiner.py) joins fully: its pod, execution client, authority and root node run, it registers, bonds and is admitted
   (`ubft validator apply`), so its root sends its own handoff possession proof;
2. the last genesis validator's root node stops: its pod, execution client, authority and shard node keep running, so its P85 possession
   proof still makes the next output Published, but its root never sends the VR handoff possession proof;
3. the next election names all five; every member sends its P85 proof and the output is Published; the roots commit the intent's PoP
   request (control op 6) with a cutoff POP_WINDOW in root progress after it;
4. at the cutoff the three live genesis roots each state the stopped incumbent's miss (root log "PoP misses stated at the request's cutoff");
5. the output expires with no handoff; the roots reject it with the miss certificate (three of four, the ordinary quorum by weight of the whole
   predecessor committee): the SealRegistry holds OutputRejected (Expired), PoPMissed (kind 9, the stopped incumbent's bit) and SessionClosed;
   ElectionPolicy parks the stopped incumbent for 2 x LIFETIME from that record, and nobody else (the joiner proved, so #1303 spares it);
6. the next election names the three live incumbents and the joiner: the floor of four with an eligible replacement; they publish it and the
   roots activate the next root epoch, while the parked incumbent stays bonded, indexed and not retiring.

The joiner's shard node is not started: the new four-member EVM committee runs on three. The stopped root stays down until the teardown.
"""
import json
import re
import subprocess
import time

import handoff_ops
import joiner as joiner_lib
import pos_join
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
    r.expect(r.ubft is not None, 'vr-pop-miss has the pinned ubft (--ubft): it makes the joiner\'s keys and credentials')
    incumbents = r.members()
    r.expect(len(incumbents) == 4, 'vr-pop-miss runs on the four-validator VR generation (a joiner is the replacement)', str(incumbents))
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

    epoch = epoch_now()

    # 1. the joiner, as vr-reject makes it, but with its root node running: it sends its own handoff possession proof
    override_path = gen / handoff_ops.JOINER_OVERRIDE
    r.expect(not override_path.exists(), 'the generation has no joiner yet (run vr-pop-miss without vr-reject or vr-late-joiner)', str(override_path))
    certified = r.wait(f'a verified UC of root epoch {epoch} names the certified shard epoch', lambda: rec.newest_uc(live[0], epoch), 600, every=10)
    info = joiner_lib.prepare(gen, r.ubft)
    j, val = info['index'], gen / f'validator{info["index"]}'
    vrdep = json.loads((gen / 'network' / 'vr-deployment.json').read_text())
    wallet = pos_join.new_wallet(r)
    owner = wallet['address']
    auth = val / 'auth'
    (auth / 'pop').mkdir(mode=0o700, exist_ok=True)
    subprocess.run([str(r.ubft), 'signing-authority', 'credential', '--out', str(auth / 'pop' / 'pop.cred')], check=True, capture_output=True)
    trust = '/network/trust-base.json'
    if epoch > 1:
        (auth / 'current-trust.json').write_bytes(rec.fetch(f'root{live[0]}', 'q3', 'trust-base', '--root-rpc', rec.root_rpc, '--epoch', str(epoch)))
        trust = '/authority/current-trust.json'
    root_info = json.loads((val / 'root' / 'node-info.json').read_text())
    (auth / 'registration.json').write_text(json.dumps({'network': vrdep['networkWord'], 'chainId': r.manifest['chain_id'], 'registry': vr_addr,
        'authorized': [{'action': 'register', 'owner': owner, 'payee': owner, 'rootNodeId': root_info['nodeId'], 'rootKey': root_info['sigKey']}]}) + '\n')
    (auth / 'lifetime').write_text('fail-stop\n')
    override = json.loads(override_path.read_text())
    services = override['services']
    services[f'authority{j}']['entrypoint'] = vr_recover.authority_entrypoint(services[f'authority{j}']['entrypoint'], info['evm'], epoch,
        certified['shardEpoch'] + 1, trust, r.manifest['genesis_hash'])
    override_path.write_text(json.dumps(override, indent=1, sort_keys=True) + '\n')
    home = val / 'operator-home'
    home.mkdir(mode=0o700)
    for rel in ('root/keys.json', 'root/node-info.json', 'jwt/jwt.hex', 'ureth-key/p2p-secret'):
        (home / rel).parent.mkdir(mode=0o700, exist_ok=True)
        (home / rel).write_bytes((val / rel).read_bytes())
    (home / 'operator').mkdir(mode=0o700)
    (home / 'operator' / 'owner.key').write_text(wallet['private_key'] + '\n')
    (home / 'authority').mkdir(mode=0o700)
    (home / 'validator.json').write_text(json.dumps(vr_recover.operator_config(r.manifest, dep, owner, 0)) + '\n')
    vr_recover.chown(val)
    r.rescan()
    r.funder_send(owner, vr_reject.FUNDING)
    r.say(f'  joiner {j}: root {info["root"]}, EVM node {info["evm"]}, owner {owner}; root epoch {epoch}')
    rec.dc('up', '-d', '--no-deps', f'pod{j}', f'ureth{j}', f'authority{j}')
    r.wait('the joiner\'s authority answers', lambda: rec.auth_status(j), 120)
    if not (auth / 'node-info.json').exists():
        rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'node-info', *vr_recover.OPERATOR, '--out', '/authority/node-info.json')
    mounts = [(auth, '/home/authority')]

    def cli(*args, check=True):
        return rec.cli(live[0], home, *args, mounts=mounts, check=check)

    first = cli('validator', 'apply', '--wait', '5m', check=False)
    r.keep_redacted(ev / 'apply-1.log', first.stdout + first.stderr)
    ident = json.loads((home / 'validator.json').read_text()).get('id')
    r.expect(bool(ident), 'apply registered the joiner in VR', r.scrub((first.stdout + first.stderr).strip()[-300:]))
    (auth / 'pos-policy.json').write_text(json.dumps({'network': vrdep['networkWord'], 'chainId': r.manifest['chain_id'],
                                                     'election': election, 'ids': [ident]}) + '\n')
    vr_recover.chown(auth)
    rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'pos-policy', *vr_recover.OPERATOR, '--policy', '/authority/pos-policy.json')
    if first.returncode:
        r.expect('signing-pos-policy-refused' in first.stdout + first.stderr, 'the first apply stopped only for the PoS policy',
                 r.scrub((first.stdout + first.stderr).strip()[-300:]))
        second = cli('validator', 'apply', '--wait', '5m')
        r.keep_redacted(ev / 'apply-2.log', second.stdout + second.stderr)
    rec.dc('up', '-d', '--no-deps', f'root{j}')
    times['joined'] = vr_recover.utc()
    r.say(f'  joiner {j} is identity {ident}; its root node runs')

    members = {**ids, j: ident}

    def home_of(m):
        return home if m == j else rec.home(m, 'recover-participant')

    def mounts_of(m):
        return mounts if m == j else [(vr_recover.authority_dir(gen, rec.compose, m), '/home/authority')]

    def publish(rid, who):
        def probe():
            cur = output(rid)
            if cur['state'] != OUT_RESERVED:
                return cur['state']
            for m in who:
                done = rec.cli(live[0], home_of(m), 'validator', 'pos-publish', '--participate', '--result', rid, '--proof-member', str(members[m]),
                               mounts=mounts_of(m), check=False)
                r.say(f'  member {members[m]}: exit {done.returncode}: ' + r.scrub(' | '.join((done.stdout + done.stderr).strip().splitlines()[-2:])[-240:]))
            return None
        return r.wait(f'every elected member proves possession and {rid[:18]} is published', probe, 1800, every=20)

    # 2. the first result naming the joiner: before it is published (no intent yet, so no proof sent), the withholding incumbent's root
    # node stops, nothing else of it. A result reserved before the joiner's admission is handed off first, with every root running.
    deadline = time.monotonic() + 5400
    while True:
        rid = r.wait('an election result is open', open_result, 3600, every=15)
        o = output(rid)
        first_state = o['state']
        if first_state == OUT_RESERVED:
            frozen = vr_reject.frozen_ids(r.view_text(election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', rid))
            if ident in frozen and xid in frozen:
                rec.dc('stop', f'root{x}')
                times['stopped'] = vr_recover.utc()
                r.say(f'  validator {x} (identity {xid}): root stopped at root epoch {epoch} before {rid[:18]} is published; '
                      'its pod, ureth, authority and shard node keep running')
                state = publish(rid, list(members))
                o = output(rid)
                break
        r.expect(time.monotonic() < deadline, 'a result naming the joiner is reserved within 90 minutes', str(epoch))
        r.say(f'  result {rid[:18]} (state {first_state}) does not name the joiner: handed off first (root epoch {epoch})')
        epoch = rec.participate_until(epoch)
    times['published'] = vr_recover.utc()
    r.say(f'  result {rid}: members {o["members"]}, state {state}, reserved at progress {o["reserved"]}, expires at {o["expires"]}')
    r.expect(state == OUT_PUBLISHED, 'the 5-member output is Published', str(state))
    r.expect(sorted(o['members']) == sorted(members.values()), 'the output names every incumbent and the joiner', str(o['members']))
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
    for m in incumbents + [j]:
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
    parked = {i: r.view(election, 'parkedUntil(uint64)(uint64)', str(i))[0] for i in members.values()}
    r.say(f'  parkedUntil: {parked}')
    r.expect(parked[xid] == miss['progress'] + PARK_PERIOD, 'the incumbent is parked for 2 x LIFETIME from the record', str(parked[xid]))
    r.expect(not any(v for i, v in parked.items() if i != xid), 'nobody else is parked', str(parked))

    # 5. the next election: the four others, and the handoff
    nrid = r.wait('the election reserves the next result', lambda: (lambda n: n if n and n != rid else None)(open_result()), 1800, every=15)
    frozen = vr_reject.frozen_ids(r.view_text(election, 'frozenMembers(bytes32)((uint64,uint64,uint64,uint64,bytes32)[])', nrid))
    r.say(f'  next result {nrid}: P85 froze {frozen}')
    others = sorted([i for i in ids.values() if i != xid] + [ident])
    r.expect(sorted(frozen) == others, 'P85 froze the three live incumbents and the joiner (the incumbent is parked; the floor of four)', str(frozen))
    publish(nrid, [m for m in members if m != x])
    def activated():
        view = rec.root_view(live[0])
        switching = view.get('switch') and view['switch']['phase'] not in ('running', 'following')
        return view['activeEpoch'] if view['activeEpoch'] > epoch and not switching else None
    target = r.wait(f'the roots activate an epoch after {epoch}', activated, 3600, every=15)
    times['activated'] = vr_recover.utc()
    no = output(nrid)
    r.expect(sorted(no['members']) == others, 'the next output names the three live incumbents and the joiner', str(no['members']))
    r.expect(target > epoch, f'the handoff completed: root epoch {epoch} -> {target}', str(target))
    pos = rec.position(xid).splitlines()
    r.say(f'  parked incumbent position: open lots {pos[6]}, retirement requested {pos[8]}')
    r.expect(int(pos[6].split()[0]) > 0 and pos[8].strip() == 'false', 'the parked incumbent is still bonded and not retiring', str(pos))
    r.expect(r.view_text(election, 'isIndexed(uint64)(bool)', str(xid)).strip() == 'true', 'the parked incumbent is still in the live index')
    r.expect(r.view(election, 'parkedUntil(uint64)(uint64)', str(xid))[0] > progress(), 'the incumbent is still parked')
    (ev / 'result.json').write_text(json.dumps({'result': rid, 'members': o['members'], 'withholding': xid, 'joiner': ident, 'reservedAt': o['reserved'],
        'expiresAt': o['expires'], 'expiredSeenAt': at, 'cutoff': cutoff, 'stated': {str(k): v for k, v in st.items()}, 'rejection': rej,
        'miss': miss, 'parkedUntil': {str(k): v for k, v in parked.items()}, 'next': nrid, 'nextMembers': no['members'],
        'rootEpoch': [epoch, target], 'times': times}, indent=1) + '\n')
