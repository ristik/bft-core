"""The owner-key operations of the PoS profile on a running package (TN-S #430, P8-TEST #437; OPERATOR.md 5c): a paid reward claim and an exit declaration.

Stage `pos-owner`, the LAST of POS_STAGES. Precondition: the network pos-handoff-2 and pos-recreate leave (epoch 3: root records exist, the custody has applied
all of them, the pool is funded at genesis, the identities are the four genesis identities at unit weight, and each identity still has its one lot). The stage
changes state that later stages would depend on (an identity declares retirement), so nothing may follow it.

Part 1, a paid claim: `reward settle` closes the intervals the pool can close (the ended segments; the tail may wait, see contracts#72), the payee of identity 1 has
credit, claims half then the rest to a fresh address (the recipient receives exactly the amount, the pool pays exactly it, the credit falls by it), a further claim
and a claim by a key without credit are refused and move nothing.

Part 2, an exit declaration: a non-owner's `requestRetirement` is refused (NotOwner), the owner's succeeds (event RetirementRequested), a second request is refused
(RetirementAlreadyRequested), a new bond is refused (GenerationClosing), `mature` of the lot is refused by one of the gates, and the identity's withdrawal address
holds no credit afterwards (nothing was released). A completed withdrawal needs the identity to leave the committee through a handoff and the retirement imported
by the roots: NOT covered here.

The module only uses what `Rehearsal` already provides (call, view, expect, relayer, faucet_send, balance, cast_run, wait, rpc); nothing here changes those.
"""
import json
import subprocess
import sys
from pathlib import Path

DEAD = '0x' + '88' * 20          # a fresh recipient: it holds nothing before the claims
STRANGER = '0x' + '99' * 20      # an address that owns nothing


def _ip(r):
    return sys.modules[type(r).__module__].PROXY_IPS[0] + '10'


def revert_data(r, sender, to, signature, *args, value=0):
    """The revert data (hex string, '' when the call would succeed) of an eth_call from `sender`: the error selector the contract names."""
    data = r.cast_run('calldata', signature, *args)
    status, text = r.rpc({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_call', 'params': [{'from': sender, 'to': to, 'value': hex(value), 'data': data}, 'latest']}, _ip(r))
    r.expect(status == 200, f'eth_call {signature} answers', f'{status} {text[:120]}')
    return str((json.loads(text).get('error') or {}).get('data', ''))


def expect_reverts(r, error, sender, to, signature, *args, value=0, what=''):
    selector = r.cast_run('sig', error)
    got = revert_data(r, sender, to, signature, *args, value=value)
    r.expect(got.startswith(selector), what or f'{signature} reverts with {error}', f'{got[:20]} (want {selector})')


def owner_tx(r, key_file, to, signature, *args, value=0, gas=1_500_000):
    """Sign `signature(args)` to `to` with the key in `key_file` and submit it through the gateway (cast cannot set X-Forwarded-For); the mined receipt.
    The key goes to one `cast mktx` process on a rehearsal runner; the keys are the generation's throwaway ones."""
    key = Path(key_file).read_text().strip()
    sender = r.cast_run('wallet', 'address', '--private-key', key)
    nonce = int(r.call('eth_getTransactionCount', [sender, 'latest']), 16)
    price = int(r.call('eth_gasPrice'), 16)
    raw = subprocess.run([r.cast, 'mktx', '--private-key', key, '--legacy', '--nonce', str(nonce), '--gas-price', str(price), '--gas-limit', str(gas),
                          '--chain', str(r.chain_id), '--value', str(value), to, signature, *map(str, args)], check=True, text=True, capture_output=True).stdout.strip()
    sent = r.call('eth_sendRawTransaction', [raw])
    return r.wait(f'{signature} is mined', lambda: r.call('eth_getTransactionReceipt', [sent]), 180)


def pos_owner(r):
    pos = r.manifest.get('pos')
    r.expect(bool(pos), 'the manifest carries a pos block (this generation was made with --pos)')
    deployment = json.loads((r.gen / 'network' / 'pos-deployment.json').read_text())
    identities = json.loads((r.gen / 'network' / 'pos-plan.json').read_text())['identities']
    custody, pool = deployment['custody'], deployment['rewardPool']
    count = r.view(r.REGISTRY, 'recordCount()(uint64)')[0]
    cursor = r.view(custody, 'recordCursor()(uint64)')[0]
    r.say(f'  root records {count}, applied by the custody {cursor}')
    r.expect(count > 0 and cursor == count, 'precondition: root records exist and the custody has applied all of them', f'{count} / {cursor}')
    for who in (identities[0], identities[1]):
        for role in ('owner', 'withdrawal', 'payee'):
            if r.balance(who[role]) < 10 ** 17:
                r.faucet_send(who[role], 10 ** 18)

    # --- part 1: a paid reward claim --------------------------------------------------------------------------------------------
    first = identities[0]
    keys = r.gen / pos['owner_keys'] / f'identity-{first["stakingId"]}'
    payee = first['payee']
    status, out = r.relayer(keys / 'owner.key', 'reward', 'settle', '--max-steps', '64')
    r.expect(status == 0, 'reward settle (any key) succeeds against the chain with root records', out.strip()[-300:])
    credit = r.view(pool, 'credits(address)(uint256)', payee)[0]
    r.say(f'  nextStart {r.view(pool, "nextStart()(uint64)")[0]}, available {r.view(pool, "available()(uint256)")[0]}, credit of payee {payee}: {credit}')
    r.expect(credit > 0, 'the payee of identity %s has reward credit from the closed intervals' % first['stakingId'], str(credit))
    pool_before = r.balance(pool)
    r.expect(pool_before >= r.view(pool, 'accounted()(uint256)')[0], 'the pool holds at least what it has accounted for')
    r.expect(r.balance(DEAD) == 0, 'the recipient holds nothing before the claims')
    half = credit // 2
    status, out = r.relayer(keys / 'payee.key', 'reward', 'claim', '--amount-wei', str(half), '--to', DEAD)
    r.expect(status == 0, 'the payee claims half of its credit', out.strip()[-300:])
    r.wait('the recipient received the first claim', lambda: r.balance(DEAD) == half, 120)
    r.expect(r.balance(DEAD) == half and r.balance(pool) == pool_before - half, 'the recipient gets exactly the amount and the pool pays exactly it', f'{r.balance(DEAD)} / {r.balance(pool)}')
    r.expect(r.view(pool, 'credits(address)(uint256)', payee)[0] == credit - half, 'the payee credit fell by the amount')
    rest = credit - half
    status, out = r.relayer(keys / 'payee.key', 'reward', 'claim', '--amount-wei', str(rest), '--to', DEAD)
    r.expect(status == 0, 'the payee claims the rest', out.strip()[-300:])
    r.wait('the recipient received the rest', lambda: r.balance(DEAD) == credit, 120)
    r.expect(r.view(pool, 'credits(address)(uint256)', payee)[0] == 0 and r.balance(pool) == pool_before - credit, 'the credit is zero and the pool paid exactly the credit')
    expect_reverts(r, 'InsufficientCredit()', payee, pool, 'claim(uint256,address)', 1, DEAD, what='a further claim of one wei is refused with InsufficientCredit')
    expect_reverts(r, 'InsufficientCredit()', first['owner'], pool, 'claim(uint256,address)', 1, DEAD, what='a claim by a key without credit (the owner) is refused with InsufficientCredit')
    r.expect(r.balance(DEAD) == credit, 'the refused claims moved nothing')

    # --- part 2: an exit declaration ----------------------------------------------------------------------------------------------
    second = identities[1]
    ident = str(second['stakingId'])
    keys2 = r.gen / pos['owner_keys'] / f'identity-{ident}'
    expect_reverts(r, 'NotOwner()', STRANGER, custody, 'requestRetirement(uint64)', ident, what='requestRetirement by a stranger is refused with NotOwner')
    expect_reverts(r, 'NotOwner()', second['withdrawal'], custody, 'requestRetirement(uint64)', ident, what='requestRetirement by the withdrawal key is refused with NotOwner')
    lots = [int(x) for x in r.view_text(custody, 'generationLots(uint64,uint64)(uint256[])', ident, '1').strip('[]').replace(',', ' ').split()]
    r.expect(len(lots) == 1, 'the genesis identity has its one lot', str(lots))
    receipt = owner_tx(r, keys2 / 'owner.key', custody, 'requestRetirement(uint64)', ident)
    r.expect(receipt['status'] == '0x1', 'the owner declares retirement', json.dumps(receipt)[:300])
    topic = r.cast_run('keccak', 'RetirementRequested(uint64,uint64)')
    r.expect(any(log['address'].lower() == custody.lower() and log['topics'][0].lower() == topic.lower() for log in receipt['logs']), 'the receipt carries RetirementRequested from the custody')
    expect_reverts(r, 'RetirementAlreadyRequested()', second['owner'], custody, 'requestRetirement(uint64)', ident, what='a second request is refused with RetirementAlreadyRequested')
    expect_reverts(r, 'GenerationClosing()', second['owner'], custody, 'bond(uint64)', ident, value=1, what='a new bond while the generation retires is refused with GenerationClosing')
    gates = ('LotStillReferenced()', 'RetirementNotImported()', 'RecordsPending()', 'RoundGateNotMet()', 'TimeGateNotMet()', 'EvidenceHoldPending()')
    got = revert_data(r, STRANGER, custody, 'mature(uint256[])', '[%d]' % lots[0])
    named = [g for g in gates if got.startswith(r.cast_run('sig', g))]
    r.say(f'  mature of lot {lots[0]} before any handoff: {got[:12]} = {named}')
    r.expect(bool(named), 'mature of the retiring lot is refused by one of the named gates', got[:40])
    r.expect(r.view(custody, 'credit(address)(uint256)', second['withdrawal'])[0] == 0, 'nothing was released: the withdrawal address holds no credit')
    expect_reverts(r, 'InsufficientCredit()', second['withdrawal'], custody, 'claim(uint256,address)', 1, DEAD, what='a withdrawal claim without credit is refused with InsufficientCredit')
