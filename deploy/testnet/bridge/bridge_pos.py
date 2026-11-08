"""The bridge across a PoS root handoff (bft-core #430 row 2; briefs/pos-release-rerun-plan.md §4.1 preflight, arch §8/§9): two stages of rehearse_bridge.py
on a generation made with generate.py --pos --utb, run around rehearse.py's handoff stages, which order their own list. Because of that, the sequence is
three invocations on one generation:

    rehearse.py        --stages up,identity,first-tx,pos-smoke
    rehearse_bridge.py --stages deploy,fund,pos-epoch1          (the epoch-1 artifacts, before the election; within the declared cadence)
    rehearse.py        --stages pos-election,pos-proposal,pos-propose,pos-install,pos-advance
    rehearse_bridge.py --stages pos-redeem,custody              (after activation)

  pos-epoch1  The bridge client's trust and the epoch-1 artifacts, before the root install:
              - the deployed bundle's genesis EntryID is the generation's UTB genesis id (manifest utb.genesis_id): the one history the roots extend;
              - a tester wallet of its own (pos-wallet), lock and mint; the root epoch that sealed the mint's proof, as the token carries it (an old
                block can acquire a newer seal, so the epoch is read, not inferred);
              - the wallet's held trust, still the shipped genesis only;
              - the on-chain B1 registry's imported tip (SealRegistry storage) before the handoff;
              - the offline cache: the token file and its record, kept in the evidence (no key).
  pos-redeem  After activation, with the same wallet:
              - the B1 registry imported the new epoch: its bodyID (the entry id) and member count (at most the priced 16-member ceiling,
                B1Layout.MAX_MEMBERS);
              - a transfer and the burn certified at the new epoch; the seal epochs recorded;
              - the negative first: on a copy of the wallet, BRIDGE_TRUST_FETCH=0 redeem fails with ErrNoEntryForEpoch and the vault does not move;
              - then the redeem: the client fetches the missing contiguous entries from the aggregator through its pinned SDK, appends (each
                authenticated from its predecessor), persists and retries, the vault credits exactly the lock, the claim pays it back;
              - the wallet's held history afterwards: genesis = the pin, contiguous to a tip at the new epoch, the new epoch's EntryID equal to the
                registry's bodyID, persisted (trust-history.cbor); the shipped bundle on disk is unchanged (no history replaced from a file);
              - the release manifest still names what the chain runs (check_release), so the deploy survives activation.

Not here: the lagging replica and range repair, the public SDK clients, the restarts, and the replay negatives beyond the bridge's own stages (§4.2
steps 6-8). Those are stage work after this preflight.
"""
import hashlib
import json
import os
import secrets
import shutil
from pathlib import Path

from rehearse import Failure   # noqa: E402  (rehearse_bridge.py puts the package directory on sys.path first)

SEAL_REGISTRY = '0xff00000000000000000000000000000000000002'   # q3_lane_cmd.go --registry-address: the seal registry predeploy
MAX_MEMBERS = 16   # unicity-pos-contracts B1Layout.MAX_MEMBERS: the priced ceiling of an imported entry
# B1Layout entry fields (E(e,f), f = 0..10): present, bodyKind, bodyID, activationCommitID, start, end, hasEnd, signingScheme, signingConfigHash,
# memberCount, totalWeight
F_PRESENT, F_BODY_ID, F_MEMBER_COUNT = 0, 2, 9
POS_WALLET, POS_KEY = 'pos-wallet', 'pos-tester.key'
POS_LOCK_WEI = 4 * 10 ** 17
POS_FUNDS = 2 * 10 ** 18


def _word(n):
    return f'{n:064x}'


class BridgePos:
    """Mixed into BridgeRehearsal: self is the rehearsal (call, expect, say, cast_run, tester, faucet_send, vault_balance)."""

    # ---- the B1 registry, as the chain stores it ----------------------------------------------------------------------------
    def b1_field_name(self, name):
        return '0x' + self.cast_run('keccak', f'unicity.seal-registry/{name}')[2:]

    def b1_load(self, slot):
        return int(self.call('eth_getStorageAt', [SEAL_REGISTRY, slot, 'latest']), 16)

    def b1_entry(self, epoch, field):
        prefix = self.b1_field_name('b1.entry')[2:]
        return self.b1_load(self.cast_run('keccak', '0x' + prefix + _word(epoch) + _word(field)))

    def b1_state(self):
        return {'genesisEpoch': self.b1_load(self.b1_field_name('b1.genesisEpoch')), 'importedTip': self.b1_load(self.b1_field_name('b1.importedTipEpoch'))}

    # ---- the wallet -----------------------------------------------------------------------------------------------------------
    def pos_tester(self, *args, check=True, env=None):
        return self.tester(*args, check=check, wallet=POS_WALLET, key=POS_KEY, env=env)

    def held_trust(self, token=None):
        _, text = self.pos_tester('trust', *(('--token', token) if token else ()))
        return json.loads(text[text.index('{'):text.rindex('}') + 1])

    def keep_pos(self, label):
        """The offline cache: each token file and record, the held history and its listing (never keys.json)."""
        out = self.evidence / 'pos-bridge' / label
        out.mkdir(parents=True, exist_ok=True)
        wallet = self.gen / 'bridge' / POS_WALLET
        for f in (wallet / 'tokens').glob('*/*'):
            if f.suffix in ('.json', '.cbor') or f.name == 'token':
                shutil.copy(f, out / f'{f.parent.name}-{f.name}')
        if (wallet / 'trust-history.cbor').exists():
            shutil.copy(wallet / 'trust-history.cbor', out / 'trust-history.cbor')
        return out

    def record(self, name, data):
        out = self.evidence / 'pos-bridge'
        out.mkdir(parents=True, exist_ok=True)
        (out / f'{name}.json').write_text(json.dumps(data, indent=2) + '\n')

    # ---- the stages -----------------------------------------------------------------------------------------------------------
    def pos_epoch1(self):
        utb = self.manifest.get('utb')
        self.expect(bool(self.manifest.get('pos')) and bool(utb), 'the generation is a PoS generation with the signed trust-base history (--pos --utb)')
        work = self.gen / 'bridge'
        pin = (work / 'trust-base.genesis.entryid').read_text().strip().lower().removeprefix('0x')
        self.expect(pin == utb['genesis_id'].lower().removeprefix('0x'), 'the bridge\'s trust pin is the generation\'s UTB genesis entry id (one history)', pin[:16])
        shipped = hashlib.sha256((work / 'public/trust-base.bundle.cbor').read_bytes()).hexdigest()
        # the wallet and its key stay in GENERATION/bridge between the invocations (the key never in the evidence)
        shutil.rmtree(work / POS_WALLET, ignore_errors=True)
        (work / POS_WALLET).mkdir()
        key = f'0x{secrets.token_hex(32)}'
        (work / POS_KEY).write_text(key + '\n')
        os.chmod(work / POS_KEY, 0o600)
        if os.getuid() == 0:
            os.chown(work / POS_KEY, 10001, 10001)
            os.chown(work / POS_WALLET, 10001, 10001)
        me = self.cast_run('wallet', 'address', '--private-key', key)
        self.faucet_send(me, POS_FUNDS)
        self.pos_tester('init', '--config', '/work/public/tester-config.json', '--eth-key-file', '/work/tester.key')
        before = self.vault_balance()
        self.pos_tester('lock', '--amount', f'{POS_LOCK_WEI}wei')
        self.pos_tester('mint')
        self.expect(self.vault_balance() == before + POS_LOCK_WEI, 'the vault holds the epoch-1 lock', str(self.vault_balance() - before))
        trust = self.held_trust()
        record = json.loads(next((work / POS_WALLET / 'tokens').glob('*/token.json')).read_text())
        seals = self.held_trust(token=str(record['nonce']))['seals']
        genesis = int(trust['genesisEpoch'])
        self.expect(int(trust['tipEpoch']) == genesis, 'the wallet holds the shipped genesis entry only', f'epoch {genesis}')
        self.expect(all(int(s['rootEpoch']) == genesis for s in seals), f'the mint\'s proof is sealed at the genesis root epoch {genesis} (read from its seal)',
                    json.dumps(seals))
        b1 = self.b1_state()
        self.expect(b1['importedTip'] == genesis, 'the B1 registry\'s imported tip is the genesis epoch before the handoff', json.dumps(b1))
        cache = self.keep_pos('epoch1')
        state = {'pin': pin, 'shippedBundleSha256': shipped, 'wallet': me, 'lockWei': POS_LOCK_WEI, 'token': record['nonce'], 'seals': seals,
                 'trust': trust, 'b1': b1, 'vaultBefore': before, 'offlineCache': str(cache)}
        self.record('epoch1', state)
        # the next invocation (pos-redeem, after rehearse.py's handoff) has its own evidence directory: the state travels in the generation (no secret in it)
        (work / 'pos-epoch1.json').write_text(json.dumps(state, indent=2) + '\n')

    def pos_redeem(self):
        work = self.gen / 'bridge'
        epoch1 = json.loads((work / 'pos-epoch1.json').read_text())
        genesis = int(epoch1['trust']['genesisEpoch'])
        self.expect((work / POS_WALLET / 'keys.json').exists(), 'the epoch-1 wallet is there (run pos-epoch1 before the handoff)')
        shipped = hashlib.sha256((work / 'public/trust-base.bundle.cbor').read_bytes()).hexdigest()
        self.expect(shipped == epoch1['shippedBundleSha256'], 'the shipped trust bundle is unchanged on disk')
        # the registry imported the activated epoch through the shard's B1 update
        new = genesis + 1
        b1 = self.wait('the B1 registry to import the new root epoch', lambda: (lambda s: s if s['importedTip'] >= new else None)(self.b1_state()), 180)
        body = self.b1_entry(new, F_BODY_ID)
        members = self.b1_entry(new, F_MEMBER_COUNT)
        self.expect(self.b1_entry(new, F_PRESENT) == 1 and 0 < members <= MAX_MEMBERS,
                    f'epoch {new} is installed in the B1 registry with {members} members (at most the priced {MAX_MEMBERS})', json.dumps(b1))
        # epoch-2 artifacts: a transfer and the burn certified after activation
        nonce = str(epoch1['token'])
        self.pos_tester('transfer', '--count', '1', '--token', nonce)
        self.pos_tester('burn', '--token', nonce)
        seals = self.held_trust(token=nonce)['seals']
        self.expect(int(seals[0]['rootEpoch']) == genesis and int(seals[-1]['rootEpoch']) >= new,
                    f'the mint sealed at epoch {genesis}, the burn at epoch {seals[-1]["rootEpoch"]}', json.dumps(seals))
        self.expect(int(self.held_trust()['tipEpoch']) == genesis, 'the wallet still holds only the genesis entry (it fetches when a verification needs it)')
        # the negative: fetch disabled, the redeem fails for want of the entry and the vault does not move
        copy = POS_WALLET + '-nofetch'
        shutil.rmtree(work / copy, ignore_errors=True)
        shutil.copytree(work / POS_WALLET, work / copy)
        if os.getuid() == 0:
            for p in [work / copy, *(work / copy).rglob('*')]:
                os.chown(p, 10001, 10001)
        balance = self.vault_balance()
        try:
            code, text = self.tester('redeem', '--token', nonce, check=False, wallet=copy, key=POS_KEY, env={'BRIDGE_TRUST_FETCH': '0'})
        finally:
            shutil.rmtree(work / copy, ignore_errors=True)
        self.expect(code != 0 and 'ErrNoEntryForEpoch' in text, 'with the fetch disabled the redeem fails with ErrNoEntryForEpoch', text.splitlines()[-1] if text else '')
        self.expect(self.vault_balance() == balance, 'the refused redeem did not move the vault')
        # the redeem with the live trust refresh
        code, text = self.pos_tester('redeem', '--token', nonce)
        fetches = [line.strip() for line in text.splitlines() if 'trust: fetched' in line]
        self.expect(bool(fetches), 'the bridge client fetched the missing trust-base entries from the aggregator through its SDK', '; '.join(fetches))
        held = self.held_trust()
        ids = {int(e['epoch']): e['entryId'].lower() for e in held['entries']}
        self.expect(held['pin'].lower() == epoch1['pin'] and int(held['genesisEpoch']) == genesis and sorted(ids) == list(range(genesis, int(held['tipEpoch']) + 1))
                    and int(held['tipEpoch']) >= new, f'the held history is contiguous from the pinned genesis to epoch {held["tipEpoch"]}', json.dumps(ids))
        self.expect(ids[new].removeprefix('0x') == f'{body:064x}', f'the wallet\'s epoch-{new} EntryID is the B1 registry\'s bodyID', ids[new][:18])
        self.expect((work / POS_WALLET / 'trust-history.cbor').exists(), 'the wallet persisted its grown history')
        credit = int(self.inner_response(1, 'eth_call', [{'to': self.addresses()['BridgeVault'],
                                                         'data': self.cast_run('calldata', 'claimable(address)', epoch1['wallet'])}, 'latest'])['result'], 16)
        self.expect(credit == POS_LOCK_WEI, 'the redemption across the handoff credits exactly the epoch-1 lock', str(credit))
        self.pos_tester('claim')
        self.expect(self.vault_balance() == epoch1['vaultBefore'], 'the vault paid back the epoch-1 lock', str(self.vault_balance()))
        self.check_release(self.addresses())
        cache = self.keep_pos('redeemed')
        self.record('redeem', {'b1': b1, 'newEpoch': new, 'bodyId': f'0x{body:064x}', 'members': members, 'seals': seals, 'fetches': fetches,
                               'trust': held, 'credit': credit, 'evidence': str(cache)})
        self.record('result', {'stage': '430-bridge-pos-preflight', 'generation': self.gen.name, 'epochs': [genesis, new], 'pass': True})
        if Path(work / POS_KEY).exists():
            (work / POS_KEY).unlink()
