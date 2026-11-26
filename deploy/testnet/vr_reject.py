#!/usr/bin/env python3
"""vr-reject (bft-core#1311): an elected joiner that never produces its handoff PoP; its output expires and the roots reject it themselves.

On the public candidate a joiner registered and bonded, was elected into a 5-member output and never started a node that could send its
handoff possession proof. The output stayed Published past its expiry, because no VR-mode root built RejectResult v2, and the root epochs froze.

This stage replays that on a Compose VR/P85 generation (run it after vr-pos-publish):

1. a fifth entity (joiner.py) with its own signing authority only: its pod, execution client and authority run, its root and shard node never
   start; a fresh owner wallet funded by the funder;
2. `ubft validator apply` (VR.register, custody bond, the delegation admission), as the validator container's `join` runs it;
3. the next election names the joiner: every member, the joiner included, sends its P85 possession proof (`validator pos-publish --participate`),
   so the output is Published, as on the candidate; the joiner requests its exit (`validator exit`, custody.requestRetirement) so that the
   next election excludes it;
4. no operator step: the output stays Published while VR's progress is below expiresAtProgress, then the roots order RejectResult v2
   (Expired): VR marks it Rejected, then Closed; every root that built it logged "election result due for rejection" (registry=true);
5. the next election names the incumbents only, they publish it, and the roots activate the next root epoch.

The joiner's authority, pod and execution client stay up until the end of the stage, then only its own services are removed.
"""
import json
import subprocess
import time

import handoff_ops
import joiner as joiner_lib
import pos_join
import vr_recover

LIFETIME = 16384   # vrschema.Lifetime: expiresAtProgress = reservedProgress + LIFETIME
OUT_RESERVED, OUT_PUBLISHED, OUT_REJECTED, OUT_CLOSED = 1, 2, 4, 7
ZERO = '0x' + '00' * 32
SAY_EVERY = 300    # seconds between progress lines while the output ages
FUNDING = 200 * 10 ** 18


def words(raw):
    return [int(raw[2 + 64 * i:2 + 64 * (i + 1)], 16) for i in range((len(raw) - 2) // 64)]


def decode_output(raw):
    """VR.output(resultId)'s tuple (vrschedule/rpc.go vrABI): state, attempt, reservedProgress, expiresAtProgress, ..., members[16]; member ids."""
    w = words(raw)
    t = w[0] // 32
    m = t + w[t + 16] // 32
    return {'state': w[t], 'attempt': w[t + 1], 'reserved': w[t + 2], 'expires': w[t + 3],
            'members': [w[m + 1 + k * 10] for k in range(w[m])]}


def vr_reject(r):
    if (r.manifest.get('pos') or {}).get('profile') != 'vr-pos16':
        raise ValueError('vr-reject needs a VR/P85 Compose generation')
    r.expect(r.ubft is not None, 'vr-reject has the pinned ubft (--ubft): it makes the joiner\'s keys and credentials')
    r.expect(not (r.gen / handoff_ops.JOINER_OVERRIDE).exists(), 'no other joiner in this generation (vr-reject writes its own joiner override; '
             'run it without vr-late-joiner)')
    rec = vr_recover.Recovery(r, 1)
    rec.since = vr_recover.utc()
    ev = r.evidence / 'reject'
    ev.mkdir(parents=True, exist_ok=True)
    gen, dep = r.gen, rec.deployment
    vr_addr, election = dep['registry'], dep['election']
    incumbents = r.members()
    ids = {m: vr_recover.genesis_identity(gen, m)[0] for m in incumbents}
    live = incumbents[0]
    times = {'start': rec.since}

    def output(rid):
        return decode_output(r.call('eth_call', [{'to': vr_addr, 'data': r.cast_run('calldata', 'output(bytes32)', rid)}, 'latest']))

    def open_result():
        rid = r.view_text(election, 'openResult()(bytes32)').strip()
        return rid if int(rid, 16) else None

    def progress():
        return r.view(r.REGISTRY, 'progress()(uint64)')[0]

    def epoch_now():
        return rec.root_view(live)['activeEpoch']

    epoch = epoch_now()

    # 1. the joiner: keys, an authority at the current scope, a funded owner wallet, an operator home
    certified = r.wait(f'a verified UC of root epoch {epoch} names the certified shard epoch', lambda: rec.newest_uc(live, epoch), 600, every=10)
    info = joiner_lib.prepare(gen, r.ubft)
    j, val = info['index'], gen / f'validator{info["index"]}'
    wallet = pos_join.new_wallet(r)
    owner = wallet['address']
    auth = val / 'auth'
    (auth / 'pop').mkdir(mode=0o700, exist_ok=True)
    subprocess.run([str(r.ubft), 'signing-authority', 'credential', '--out', str(auth / 'pop' / 'pop.cred')], check=True, capture_output=True)
    trust = '/network/trust-base.json'
    if epoch > 1:
        (auth / 'current-trust.json').write_bytes(rec.fetch(f'root{live}', 'q3', 'trust-base', '--root-rpc', rec.root_rpc, '--epoch', str(epoch)))
        trust = '/authority/current-trust.json'
    root_info = json.loads((val / 'root' / 'node-info.json').read_text())
    vrdep = json.loads((gen / 'network' / 'vr-deployment.json').read_text())
    (auth / 'registration.json').write_text(json.dumps({'network': vrdep['networkWord'], 'chainId': r.manifest['chain_id'], 'registry': vr_addr,
        'authorized': [{'action': 'register', 'owner': owner, 'payee': owner, 'rootNodeId': root_info['nodeId'], 'rootKey': root_info['sigKey']}]}) + '\n')
    (auth / 'lifetime').write_text('fail-stop\n')
    override_path = gen / handoff_ops.JOINER_OVERRIDE
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
    r.funder_send(owner, FUNDING)
    r.say(f'  joiner {j}: root {info["root"]}, EVM node {info["evm"]}, owner {owner}; root epoch {epoch}')

    # only the joiner's pod, execution client and authority: its root (the handoff PoP) and shard node never start
    rec.dc('up', '-d', '--no-deps', f'pod{j}', f'ureth{j}', f'authority{j}')
    r.wait('the joiner\'s authority answers', lambda: rec.auth_status(j), 120)
    rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'node-info', *vr_recover.OPERATOR, '--out', '/authority/node-info.json')
    mounts = [(auth, '/home/authority')]

    def cli(*args, check=True):
        return rec.cli(live, home, *args, mounts=mounts, check=check)

    def provision_policy(ident):
        (auth / 'pos-policy.json').write_text(json.dumps({'network': vrdep['networkWord'], 'chainId': r.manifest['chain_id'],
                                                         'election': election, 'ids': [ident]}) + '\n')
        vr_recover.chown(auth)
        rec.exec(f'authority{j}', 'ubft', 'signing-authority', 'pos-policy', *vr_recover.OPERATOR, '--policy', '/authority/pos-policy.json')

    # 2. apply: register, bond, admit (the container's join: a first apply refused for the PoS policy provisions it and applies again)
    first = cli('validator', 'apply', '--wait', '5m', check=False)
    r.keep_redacted(ev / 'apply-1.log', first.stdout + first.stderr)
    ident = json.loads((home / 'validator.json').read_text()).get('id')
    r.expect(bool(ident), 'apply registered the joiner in VR', r.scrub((first.stdout + first.stderr).strip()[-300:]))
    provision_policy(ident)
    if first.returncode:
        r.expect('signing-pos-policy-refused' in first.stdout + first.stderr, 'the first apply stopped only for the PoS policy',
                 r.scrub((first.stdout + first.stderr).strip()[-300:]))
        second = cli('validator', 'apply', '--wait', '5m')
        r.keep_redacted(ev / 'apply-2.log', second.stdout + second.stderr)
    times['applied'] = vr_recover.utc()
    r.say(f'  joiner {j} is identity {ident}')

    # 3. the next election names the joiner; outputs of the incumbents alone opened before the admission are handed off first
    def joiner_output():
        rid = open_result()
        if rid is None:
            return None
        o = output(rid)
        return (rid, o) if ident in o['members'] else 'incumbents'

    deadline = time.monotonic() + 5400
    while True:
        got = r.wait('an election result is open', lambda: joiner_output(), 3600, every=15)
        if got != 'incumbents':
            break
        r.expect(time.monotonic() < deadline, 'the joiner is elected within 90 minutes', str(epoch))
        r.say(f'  an output of the incumbents opened before the admission: handed off first (root epoch {epoch})')
        epoch = rec.participate_until(epoch)
    rid, o = got
    times['reserved'] = vr_recover.utc()
    r.say(f'  result {rid}: members {o["members"]}, reserved at progress {o["reserved"]}, expires at {o["expires"]}')
    r.expect(o['expires'] == o['reserved'] + LIFETIME, 'expiresAtProgress is reservedProgress + LIFETIME', str(o))
    members = {**ids, j: ident}

    def publish():
        cur = output(rid)
        if cur['state'] != OUT_RESERVED:
            return cur['state']
        for m, who in members.items():
            mount = mounts if m == j else [(vr_recover.authority_dir(gen, rec.compose, m), '/home/authority')]
            mhome = home if m == j else rec.home(m, 'recover-participant')
            done = rec.cli(live, mhome, 'validator', 'pos-publish', '--participate', '--result', rid, '--proof-member', str(who),
                           mounts=mount, check=False)
            r.say(f'  member {who}: exit {done.returncode}: ' + r.scrub(' | '.join((done.stdout + done.stderr).strip().splitlines()[-2:])[-240:]))
        return None
    state = r.wait('every member, the joiner included, proves possession and the output is published', publish, 1800, every=20)
    r.expect(state == OUT_PUBLISHED, 'the 5-member output is Published (as on the candidate)', str(state))
    times['published'] = vr_recover.utc()
    out = cli('validator', 'exit', '--wait', '5m')
    r.keep_redacted(ev / 'exit.log', out.stdout + out.stderr)
    r.expect('requestRetirement' in out.stdout + out.stderr, 'the joiner requested its exit (custody.requestRetirement)',
             r.scrub(out.stdout.strip()[-200:]))

    # 4. the output ages with no handoff (the joiner's root never sends its PoP), then the roots reject it themselves
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
    times['expired'] = vr_recover.utc()
    r.expect(not premature, 'no rejection before the expiry', '; '.join(premature))
    r.expect(epoch_now() == epoch, 'no handoff happened while the joiner\'s PoP was missing', str(epoch_now()))
    seen = {}
    def rejected():
        cur = output(rid)
        seen.setdefault(cur['state'], progress())
        return cur['state'] if cur['state'] in (OUT_REJECTED, OUT_CLOSED) else None
    r.wait('the roots reject the expired output (VR: Rejected, then Closed)', rejected, 1800, every=10)
    closed = r.wait('the SessionClosed is applied (VR: Closed)', lambda: output(rid)['state'] == OUT_CLOSED or None, 900, every=10)
    times['rejected'] = vr_recover.utc()
    r.expect(bool(closed), 'the output is Closed', str(seen))
    built = {}
    for m in incumbents:
        log = rec.logs(f'root{m}')
        r.keep_redacted(ev / f'root{m}.log', log)
        lines = [l for l in log.splitlines() if 'election result due for rejection' in l]
        built[m] = len(lines)
    r.say(f'  rejection built by roots: {built}; first seen at progress {seen}')
    r.expect(any(built.values()), 'the roots built the RejectResult v2 themselves (no keeper or relay)', str(built))
    refused = [l for m in incumbents for l in (ev / f'root{m}.log').read_text().splitlines() if 'rejection left out of this proposal' in l]
    r.say(f'  rejection trial refusals: {len(refused)}' + (': ' + r.scrub(refused[-1][-300:]) if refused else ''))

    # 5. the next election names the incumbents only; they publish it and the roots activate the next root epoch
    def next_output():
        nrid = open_result()
        return (nrid, output(nrid)) if nrid and nrid != rid else None
    nrid, no = r.wait('the election reserves the next result', next_output, 1800, every=15)
    r.say(f'  next result {nrid}: members {no["members"]}')
    r.expect(ident not in no['members'] and sorted(no['members']) == sorted(ids.values()),
             'the next election names the incumbents only (the joiner requested its exit)', str(no['members']))
    target = rec.participate_until(epoch)
    times['activated'] = vr_recover.utc()
    r.expect(target > epoch, f'the incumbents\' handoff completed after the rejection: root epoch {epoch} -> {target}', str(target))
    (ev / 'result.json').write_text(json.dumps({'result': rid, 'members': o['members'], 'joiner': ident, 'reservedAt': o['reserved'],
        'expiresAt': o['expires'], 'expiredSeenAt': at, 'statesSeenAt': seen, 'builtBy': built, 'trialRefusals': len(refused),
        'next': nrid, 'nextMembers': no['members'], 'rootEpoch': [epoch, target], 'times': times}, indent=1) + '\n')

    # the joiner's own services only
    rec.dc('rm', '-sf', f'authority{j}', f'ureth{j}', f'pod{j}', check=False)
