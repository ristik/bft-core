"""The bridge across a PoS root handoff (bft-core #430 row 2; briefs/pos-release-rerun-plan.md §4.1 preflight, arch §8/§9): two stages of rehearse_bridge.py
on a generation made with generate.py --pos --utb, run around rehearse.py's handoff stages, which order their own list. Because of that, the sequence is
eight invocations on one generation (the workflow then runs rehearse.py utb-live):

    rehearse.py        --stages up,identity,first-tx,pos-smoke
    rehearse_bridge.py --stages deploy,fund,pos-epoch1          (the epoch-1 artifacts, before the election; within the declared cadence)
    rehearse.py        --stages pos-election,pos-proposal,pos-propose,pos-install,pos-advance
    rehearse_bridge.py --stages pos-redeem,pos-historical   (after activation)
    rehearse.py        --stages pos-handoff-2                   (root epoch 2 -> 3)
    rehearse_bridge.py --stages pos-gap                         (at epoch 3)
    rehearse.py        --stages pos-restart-2                   (each entity's execution client, root and shard node stopped and restarted, at epoch 3)
    rehearse_bridge.py --stages pos-agg-restart,pos-after-restart,pos-replays,custody
    rehearse_bridge.py --stages pos-sdk-clients                 (the public JS/Rust/Java SDK clients: sdk_clients.py)

  pos-epoch1  The bridge client's trust and the epoch-1 artifacts, before the root install:
              - the deployed bundle's genesis EntryID is the generation's UTB genesis id (manifest utb.genesis_id): the one history the roots extend;
              - a tester wallet of its own (pos-wallet), lock and mint; the root epoch that sealed the mint's proof, as the token carries it (an old
                block can acquire a newer seal, so the epoch is read, not inferred);
              - the wallet's held trust, still the shipped genesis only;
              - the on-chain B1 registry's imported tip (SealRegistry storage) before the handoff;
              - a second token B, locked, minted AND burned in epoch 1 and left unspent: the historical artifact for pos-historical;
              - a separate lagging wallet (its own wallet directory and durable history) with token C, locked and minted in epoch 1: it is never
                refreshed until pos-gap;
              - the offline cache: the token files and their records, kept in the evidence (no key).
  pos-redeem  After activation, with the same wallet:
              - the B1 registry imported the new epoch: its bodyID (the activated handoff's V3 body id) and member count (at most the priced 16-member ceiling,
                B1Layout.MAX_MEMBERS);
              - a transfer and the burn certified at the new epoch; the seal epochs recorded;
              - the negative first: on a copy of the wallet, BRIDGE_TRUST_FETCH=0 redeem fails with ErrNoEntryForEpoch and the vault does not move;
              - then the redeem: the client fetches the missing contiguous entries from the aggregator through its pinned SDK, appends (each
                authenticated from its predecessor), persists and retries, the vault credits exactly the lock, the claim pays it back;
              - the wallet's held history afterwards: genesis = the pin, contiguous to a tip at the new epoch, the tip's EntryID equal to the
                roots' served history (utb_history, under --ubft), persisted (trust-history.cbor); the shipped bundle on disk is unchanged (no history replaced from a file);
              - the release manifest still names what the chain runs (check_release), so the deploy survives activation.

  pos-historical  The separate epoch-1 artifact redeemed after activation on the per-SID path (tester redeem --per-sid: no consolidation, no fallback):
              - the submitted envelope is the redeem transaction's input as the chain holds it (eth_getTransactionByHash, the redeem(bytes) calldata of
                envelope.bin), and its anchors carry the epoch-1 seal (decoded from the envelope, not inferred from the token's age);
              - the redeem's receipt succeeded after the B1 registry had imported the new epoch, the vault credits exactly the lock and the claim pays it.
  pos-gap     After the second handoff (2 -> 3), the controlled gap: the lagging wallet still holds only the genesis entry, while the source (the
              aggregator) retains entry 2. Token C is transferred and burned at epoch 3; with the fetch disabled the redeem fails (ErrNoEntryForEpoch) and
              the vault's whole state is unchanged; then the redeem with one-entry pages (BRIDGE_TRUST_MAX_ENTRIES=1) repairs the range: exactly the
              fetches from epoch 2 and from epoch 3, one entry each; a fresh process then holds 1..3 contiguous from the pin, its epoch-3 EntryID the
              roots' served one and its epoch-2 EntryID the main wallet's; the B1 registry imported epoch 3 (bodyID the second handoff's V3 body id,
              at most 16 members); exact credit and the claim. This is the pull client's gap (a consumer that missed entry 2), not the push-offer path.
  Negatives check the vault's whole state, not its balance alone (a redeem creates credit before any claim): balance, the wallet's claimable, the
  lock's remaining and redeemed amounts and the credited total.

  pos-agg-restart    The aggregator restarted: the same verified history (tip epoch and EntryID) reloaded, a replay of it answered as the same, and no refused
                     trust-base update or finalized-branch conflict in its log after the restart.
  pos-after-restart  After the pods' and the aggregator's restarts, token D round-trips at epoch 3 with the main wallet: a fresh process reloads its durable
                     history (to epoch 2), fetches entry 3 from the restarted aggregator, ends with the lagging wallet's EntryIDs 1..3; exact credit and claim.
  pos-replays        The replay negatives at epoch 3, against the vault's whole state and the B1 tip (unchanged after all of them): every redeemed envelope
                     again (A epoch 2, B per-SID epoch 1, C and D epoch 3: PartAlreadyRedeemed), a claimed credit claimed again (InsufficientCredit); and per
                     token A, B, C (tester replays): the envelope mined again (status 0), a fresh consolidated proof under the epoch-3 seal (PartAlreadyRedeemed:
                     refused on the nullifier, not for its age), that proof with its recipient changed and re-signed by unknown keys (BridgeRejected; the plug-in
                     ErrQuorumNotMet), and a conflicting burn of the burned state (not certified once later blocks are built). Then custody (the existing checker) over all four locks.

Not here: the gap through a deliberately suppressed push offer (§4.2 step 6 as written: this is the pull client's gap). The public SDK clients (step 7) are
sdk_clients.py's pos-sdk-clients.
"""
import hashlib
import json
import os
import secrets
import shutil
import time

from rehearse import Failure   # noqa: E402  (rehearse_bridge.py puts the package directory on sys.path first)

SEAL_REGISTRY = '0xff00000000000000000000000000000000000002'   # q3_lane_cmd.go --registry-address: the seal registry predeploy
MAX_MEMBERS = 16   # unicity-pos-contracts B1Layout.MAX_MEMBERS: the priced ceiling of an imported entry
# B1Layout entry fields (E(e,f), f = 0..10): present, bodyKind, bodyID, activationCommitID, start, end, hasEnd, signingScheme, signingConfigHash,
# memberCount, totalWeight
F_PRESENT, F_BODY_ID, F_MEMBER_COUNT = 0, 2, 9
POS_WALLET, POS_KEY = 'pos-wallet', 'pos-tester.key'
LAG_WALLET = 'pos-lagging-wallet'   # pos-gap's consumer: its own wallet directory and durable history, never refreshed before the gap
POS_LOCK_WEI = 3 * 10 ** 17
POS_FUNDS = 2 * 10 ** 18   # four locks of POS_LOCK_WEI (A, B, C, and D after the restarts; each claimed back before the next) and their gas
# BridgeVault errors (as rehearse_bridge.py; not imported from it, which imports this module)
PART_ALREADY_REDEEMED, INSUFFICIENT_CREDIT = '0xe8f8709e', '0x4eb7eaec'


def _word(n):
    return f'{n:064x}'


class BridgePos:
    """Mixed into BridgeRehearsal: self is the rehearsal (call, expect, say, cast_run, tester, faucet_send, vault_balance)."""

    # ---- the B1 registry, as the chain stores it ----------------------------------------------------------------------------
    def b1_field_name(self, name):
        return '0x' + self.cast_run('keccak', f'unicity.seal-registry/{name}')[2:]

    def b1_load(self, slot):
        # the operator's read, inside the validators network: the public gateway does not serve eth_getStorageAt
        return int(self.ureth(1, 'eth_getStorageAt', [SEAL_REGISTRY, slot, 'latest']), 16)

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

    def keep_pos(self, label, wallet=None):
        """The offline cache: each token file and record, the held history and its listing (never keys.json)."""
        out = self.evidence / 'pos-bridge' / label
        out.mkdir(parents=True, exist_ok=True)
        wallet = self.gen / 'bridge' / (wallet or POS_WALLET)
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
        try:
            self.pos_epoch1_steps()
        except Exception:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)   # the later invocations will not run: the key goes now
            raise

    def tokens(self, wallet=POS_WALLET):
        return sorted(p.name for p in (self.gen / 'bridge' / wallet / 'tokens').iterdir() if (p / 'token.json').exists())

    def lag_tester(self, *args, check=True, env=None):
        return self.tester(*args, check=check, wallet=LAG_WALLET, key=POS_KEY, env=env)

    def vault_state(self, nonce, who):
        # what a redeem changes, not only the balance: balance, the recipient's claimable, the lock's remaining and redeemed amounts, the credited total
        view = lambda sig, *args: int(self.vault_view(sig, *args), 16)
        return {'balance': self.vault_balance(), 'claimable': view('claimable(address)', who), 'remaining': view('remaining(uint256)', str(nonce)),
                'redeemed': view('redeemedAmount(uint256)', str(nonce)), 'credited': view('credited()')}

    def pos_epoch1_steps(self):
        utb = self.manifest.get('utb')
        self.expect(bool(self.manifest.get('pos')) and bool(utb), 'the generation is a PoS generation with the signed trust-base history (--pos --utb)')
        work = self.gen / 'bridge'
        pin = (work / 'trust-base.genesis.entryid').read_text().strip().lower().removeprefix('0x')
        self.expect(pin == utb['genesis_id'].lower().removeprefix('0x'), 'the bridge\'s trust pin is the generation\'s UTB genesis entry id (one history)', pin[:16])
        shipped = hashlib.sha256((work / 'public/trust-base.bundle.cbor').read_bytes()).hexdigest()
        # the lock-proof endpoint on validator 1's archive (the lockproof stage starts it on the PoA generation; this sequence does not run that stage)
        self.start_endpoint(1)
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
        (token_a,) = self.tokens()
        self.pos_tester('mint', '--token', token_a)
        # token B: the separate historical artifact, burned in epoch 1 too, redeemed only after activation (pos-historical)
        self.pos_tester('lock', '--amount', f'{POS_LOCK_WEI}wei')
        (token_b,) = set(self.tokens()) - {token_a}
        self.pos_tester('mint', '--token', token_b)
        self.pos_tester('burn', '--token', token_b)
        # the lagging consumer: its own wallet, token C locked and minted now, nothing else until pos-gap
        shutil.rmtree(work / LAG_WALLET, ignore_errors=True)
        (work / LAG_WALLET).mkdir()
        if os.getuid() == 0:
            os.chown(work / LAG_WALLET, 10001, 10001)
        self.lag_tester('init', '--config', '/work/public/tester-config.json', '--eth-key-file', '/work/tester.key')
        self.lag_tester('lock', '--amount', f'{POS_LOCK_WEI}wei')
        self.lag_tester('mint')
        (token_c,) = self.tokens(LAG_WALLET)
        self.expect(self.vault_balance() == before + 3 * POS_LOCK_WEI, 'the vault holds the three epoch-1 locks', str(self.vault_balance() - before))
        trust = self.held_trust()
        record = json.loads((work / POS_WALLET / 'tokens' / token_a / 'token.json').read_text())
        seals = self.held_trust(token=token_a)['seals']
        seals_b = self.held_trust(token=token_b)['seals']
        self.expect(all(int(s['rootEpoch']) == int(trust['genesisEpoch']) for s in seals_b),
                    'token B\'s mint and burn are sealed at the genesis root epoch (read from their seals)', json.dumps(seals_b))
        genesis = int(trust['genesisEpoch'])
        self.expect(int(trust['tipEpoch']) == genesis, 'the wallet holds the shipped genesis entry only', f'epoch {genesis}')
        self.expect(all(int(s['rootEpoch']) == genesis for s in seals), f'the mint\'s proof is sealed at the genesis root epoch {genesis} (read from its seal)',
                    json.dumps(seals))
        b1 = self.b1_state()
        self.expect(b1['importedTip'] == genesis, 'the B1 registry\'s imported tip is the genesis epoch before the handoff', json.dumps(b1))
        cache = self.keep_pos('epoch1')
        state = {'pin': pin, 'shippedBundleSha256': shipped, 'wallet': me, 'lockWei': POS_LOCK_WEI, 'token': token_a, 'lockNonce': record['nonce'], 'seals': seals,
                 'tokenC': token_c, 'lockNonceC': json.loads((work / LAG_WALLET / 'tokens' / token_c / 'token.json').read_text())['nonce'],
                 'tokenB': token_b, 'lockNonceB': json.loads((work / POS_WALLET / 'tokens' / token_b / 'token.json').read_text())['nonce'], 'sealsB': seals_b,
                 'trust': trust, 'b1': b1, 'vaultBefore': before, 'offlineCache': str(cache)}
        self.record('epoch1', state)
        # the next invocation (pos-redeem, after rehearse.py's handoff) has its own evidence directory: the state travels in the generation (no secret in it)
        (work / 'pos-epoch1.json').write_text(json.dumps(state, indent=2) + '\n')

    def pos_redeem(self):
        try:
            self.pos_redeem_steps()
        except Exception:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)
            raise

    def pos_redeem_steps(self):
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
        state = self.vault_state(epoch1['lockNonce'], epoch1['wallet'])
        try:
            code, text = self.tester('redeem', '--token', nonce, check=False, wallet=copy, key=POS_KEY, env={'BRIDGE_TRUST_FETCH': '0'})
        finally:
            shutil.rmtree(work / copy, ignore_errors=True)
        self.expect(code != 0 and 'ErrNoEntryForEpoch' in text, 'with the fetch disabled the redeem fails with ErrNoEntryForEpoch', text.splitlines()[-1] if text else '')
        after = self.vault_state(epoch1['lockNonce'], epoch1['wallet'])
        self.expect(after == state, 'the refused redeem changed nothing in the vault (balance, claimable, remaining, redeemed, credited)', json.dumps(after))
        # the redeem with the live trust refresh
        code, text = self.pos_tester('redeem', '--token', nonce)
        fetches = [line.strip() for line in text.splitlines() if 'trust: fetched' in line]
        self.expect(bool(fetches), 'the bridge client fetched the missing trust-base entries from the aggregator through its SDK', '; '.join(fetches))
        held = self.held_trust()
        ids = {int(e['epoch']): e['entryId'].lower() for e in held['entries']}
        self.expect(held['pin'].lower() == epoch1['pin'] and int(held['genesisEpoch']) == genesis and sorted(ids) == list(range(genesis, int(held['tipEpoch']) + 1))
                    and int(held['tipEpoch']) >= new, f'the held history is contiguous from the pinned genesis to epoch {held["tipEpoch"]}', json.dumps(ids))
        # the registry's bodyID of a handoff entry is the handoff's V3 body id (b1state BodyKind 2: the activated body), not the trust-base EntryID: it is
        # compared with the body id of the handoff rehearse.py drove (its candidate's v3-body-id.txt, which the activation record names)
        v3 = (self.gen / 'network/handoff/v3-body-id.txt').read_text().strip().lower().removeprefix('0x')
        self.expect(v3 == f'{body:064x}', f'the B1 registry\'s epoch-{new} bodyID is the activated handoff\'s V3 body id', v3[:16])
        self.expect((work / POS_WALLET / 'trust-history.cbor').exists(), 'the wallet persisted its grown history')
        # the roots' served history (rehearse.py utb_history, verified offline from the pinned genesis with ubft): the wallet's entry at that tip is the same entry
        roots = None
        if self.ubft:
            tip, tip_id, _ = self.utb_history('bridge-redeem', self.manifest['utb']['genesis_id'])
            roots = {'tip': tip, 'tipEntryId': tip_id}
            mine = ids.get(int(tip))
            self.expect(mine is not None and mine.removeprefix('0x') == str(tip_id).lower().removeprefix('0x'),
                        f'the wallet\'s epoch-{tip} EntryID is the one in the roots\' served history', str(tip_id)[:18])
        else:
            self.say('  (no --ubft: the comparison with the roots\' served history is skipped; the B1 registry\'s bodyID was compared above)')
        credit = int(self.inner_response(1, 'eth_call', [{'to': self.addresses()['BridgeVault'],
                                                         'data': self.cast_run('calldata', 'claimable(address)', epoch1['wallet'])}, 'latest'])['result'], 16)
        self.expect(credit == POS_LOCK_WEI, 'the redemption across the handoff credits exactly the epoch-1 lock', str(credit))
        self.pos_tester('claim')
        self.expect(self.vault_balance() == epoch1['vaultBefore'] + 2 * POS_LOCK_WEI, 'the vault paid back lock A (B\'s and C\'s locks still held)', str(self.vault_balance()))
        self.check_release(self.addresses())
        cache = self.keep_pos('redeemed')
        self.record('redeem', {'b1': b1, 'newEpoch': new, 'bodyId': f'0x{body:064x}', 'members': members, 'seals': seals, 'fetches': fetches,
                               'trust': held, 'roots': roots, 'credit': credit, 'evidence': str(cache)})
        (work / 'pos-redeem.json').write_text(json.dumps({'trust': held}, indent=2) + '\n')
        self.record('result-redeem', {'stage': '430-bridge-pos pos-redeem (consolidated)', 'generation': self.gen.name, 'epochs': [genesis, new], 'pass': True})

    def pos_historical(self):
        try:
            self.pos_historical_steps()
        except Exception:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)
            raise

    def pos_gap(self):
        try:
            self.pos_gap_steps()
        except Exception:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)   # the later invocations will not run: the key goes now
            raise

    def pos_gap_steps(self):
        work = self.gen / 'bridge'
        epoch1 = json.loads((work / 'pos-epoch1.json').read_text())
        genesis = int(epoch1['trust']['genesisEpoch'])
        token, nonce, me = epoch1['tokenC'], epoch1['lockNonceC'], epoch1['wallet']
        third = genesis + 2
        b1 = self.wait('the B1 registry to import the second handoff\'s epoch', lambda: (lambda s: s if s['importedTip'] >= third else None)(self.b1_state()), 180)
        body = self.b1_entry(third, F_BODY_ID)
        members = self.b1_entry(third, F_MEMBER_COUNT)
        v3 = (self.gen / 'network/handoff/v3-body-id.txt').read_text().strip().lower().removeprefix('0x')
        self.expect(self.b1_entry(third, F_PRESENT) == 1 and 0 < members <= MAX_MEMBERS and v3 == f'{body:064x}',
                    f'epoch {third} is in the B1 registry: {members} members (at most {MAX_MEMBERS}), bodyID the second handoff\'s V3 body id', v3[:16])
        lag = self.tester('trust', wallet=LAG_WALLET, key=POS_KEY)[1]
        lag = json.loads(lag[lag.index('{'):lag.rindex('}') + 1])
        self.expect(int(lag['tipEpoch']) == genesis, 'the lagging wallet holds only the genesis entry (it missed entry 2 and entry 3)', lag['tipEpoch'])
        self.lag_tester('transfer', '--count', '1', '--token', token)
        self.lag_tester('burn', '--token', token)
        _, text = self.lag_tester('trust', '--token', token)
        seals = json.loads(text[text.index('{'):text.rindex('}') + 1])['seals']
        self.expect(int(seals[0]['rootEpoch']) == genesis and int(seals[-1]['rootEpoch']) >= third, f'token C minted at epoch {genesis}, burned at epoch {seals[-1]["rootEpoch"]}',
                    json.dumps(seals))
        # fetch disabled while entry 2 is missing: refused, nothing changed
        copy = LAG_WALLET + '-nofetch'
        shutil.rmtree(work / copy, ignore_errors=True)
        shutil.copytree(work / LAG_WALLET, work / copy)
        if os.getuid() == 0:
            for q in [work / copy, *(work / copy).rglob('*')]:
                os.chown(q, 10001, 10001)
        state = self.vault_state(nonce, me)
        try:
            code, text = self.tester('redeem', '--token', token, check=False, wallet=copy, key=POS_KEY, env={'BRIDGE_TRUST_FETCH': '0'})
        finally:
            shutil.rmtree(work / copy, ignore_errors=True)
        self.expect(code != 0 and 'ErrNoEntryForEpoch' in text, 'with entry 2 missing and the fetch disabled the redeem fails with ErrNoEntryForEpoch', text.splitlines()[-1] if text else '')
        after = self.vault_state(nonce, me)
        self.expect(after == state, 'the refused redeem changed nothing in the vault', json.dumps(after))
        # the range repair: one-entry pages from the held tip
        _, text = self.lag_tester('redeem', '--token', token, env={'BRIDGE_TRUST_MAX_ENTRIES': '1'})
        fetches = [line.strip() for line in text.splitlines() if 'trust: fetched' in line]
        want = [f'trust: fetched from epoch {genesis + 1} (max 1): 1 appended, tip {genesis} -> {genesis + 1}',
                f'trust: fetched from epoch {third} (max 1): 1 appended, tip {genesis + 1} -> {third}']
        self.expect(fetches == want, 'the lagging wallet repaired the range in one-entry pages: from epoch 2, then from epoch 3', '; '.join(fetches))
        held = self.tester('trust', wallet=LAG_WALLET, key=POS_KEY)[1]   # a fresh process: what it reloads from its durable history
        held = json.loads(held[held.index('{'):held.rindex('}') + 1])
        ids = {int(e['epoch']): e['entryId'].lower() for e in held['entries']}
        self.expect(sorted(ids) == list(range(genesis, third + 1)) and held['pin'].lower() == epoch1['pin'],
                    f'a fresh process holds the history {genesis}..{third}, contiguous from the pin', json.dumps(ids))
        main = json.loads((self.evidence / 'pos-bridge/redeem.json').read_text()) if (self.evidence / 'pos-bridge/redeem.json').exists() else None
        main = main or json.loads((work / 'pos-redeem.json').read_text())
        main_ids = {int(e['epoch']): e['entryId'].lower() for e in main['trust']['entries']}
        self.expect(ids[genesis + 1] == main_ids[genesis + 1], 'its epoch-2 EntryID is the one the main wallet fetched across the first handoff', ids[genesis + 1][:16])
        roots = None
        if self.ubft:
            tip, tip_id, _ = self.utb_history('bridge-gap', self.manifest['utb']['genesis_id'])
            roots = {'tip': tip, 'tipEntryId': tip_id}
            self.expect(int(tip) == third and ids[third].removeprefix('0x') == str(tip_id).lower().removeprefix('0x'),
                        f'its epoch-{third} EntryID is the roots\' served tip', str(tip_id)[:18])
        credited = self.vault_state(nonce, me)
        self.expect(credited['claimable'] == POS_LOCK_WEI and credited['remaining'] == 0, 'the vault credits exactly token C\'s lock', json.dumps(credited))
        self.lag_tester('claim')
        self.expect(self.vault_balance() == epoch1['vaultBefore'], 'the vault paid back all three epoch-1 locks', str(self.vault_balance()))
        cache = self.keep_pos('gap', wallet=LAG_WALLET)
        self.record('gap', {'token': token, 'lockNonce': nonce, 'b1': b1, 'epoch': third, 'bodyId': f'0x{body:064x}', 'members': members, 'seals': seals,
                            'fetches': fetches, 'trust': held, 'roots': roots, 'credited': credited, 'evidence': str(cache)})
        self.record('result-gap', {'stage': '430-bridge-pos pos-gap (2 -> 3, one-entry pages)', 'generation': self.gen.name, 'epochs': [genesis, third], 'pass': True})

    def pos_historical_steps(self):
        work = self.gen / 'bridge'
        epoch1 = json.loads((work / 'pos-epoch1.json').read_text())
        genesis = int(epoch1['trust']['genesisEpoch'])
        token, nonce, me = epoch1['tokenB'], epoch1['lockNonceB'], epoch1['wallet']
        b1 = self.b1_state()
        self.expect(b1['importedTip'] > genesis, 'the redeem comes after activation: the B1 registry holds the new epoch', json.dumps(b1))
        before = self.vault_state(nonce, me)
        self.expect(before['remaining'] == POS_LOCK_WEI and before['claimable'] == 0, 'token B\'s lock is unspent and nothing is claimable', json.dumps(before))
        self.pos_tester('redeem', '--token', token, '--per-sid')
        _, text = self.pos_tester('envelope', '--token', token)
        env = json.loads(text[text.index('{'):text.rindex('}') + 1])
        record = json.loads((work / POS_WALLET / 'tokens' / token / 'token.json').read_text())
        tx = self.ureth(1, 'eth_getTransactionByHash', [record['redeemTx']])
        submitted = self.cast_run('calldata', 'redeem(bytes)', '0x' + env['envelopeHex'])
        self.expect(tx is not None and tx['input'].lower() == submitted.lower(), 'the decoded envelope is the redeem transaction\'s input as the chain holds it',
                    f'{record["redeemTx"]} {env["bytes"]} bytes sha256 {env["sha256"][:16]}')
        epochs = sorted({int(a['rootEpoch']) for a in env['anchors']})
        self.expect(genesis in epochs, f'the submitted envelope carries an epoch-{genesis} seal ({len(env["anchors"])} anchors, per-SID)',
                    json.dumps([(a['partition'], a['rootEpoch'], a['rootRound']) for a in env['anchors']]))
        receipt = self.ureth(1, 'eth_getTransactionReceipt', [record['redeemTx']])
        self.expect(receipt['status'] == '0x1', 'the redeem succeeded on chain after activation', f'block {int(receipt["blockNumber"], 16)}, gas {int(receipt["gasUsed"], 16)}')
        credited = self.vault_state(nonce, me)
        self.expect(credited['claimable'] == POS_LOCK_WEI and credited['remaining'] == 0 and credited['redeemed'] == POS_LOCK_WEI,
                    'the vault credits exactly token B\'s lock (claimable, remaining 0, redeemed)', json.dumps(credited))
        self.pos_tester('claim')
        self.expect(self.vault_balance() == epoch1['vaultBefore'] + POS_LOCK_WEI, 'the vault paid back lock B (C\'s lock still held)', str(self.vault_balance()))
        cache = self.keep_pos('historical')
        self.record('historical', {'token': token, 'lockNonce': nonce, 'redeemTx': record['redeemTx'], 'envelope': {k: env[k] for k in ('bytes', 'sha256', 'anchors')},
                                   'anchorEpochs': epochs, 'receipt': {'block': int(receipt['blockNumber'], 16), 'gasUsed': int(receipt['gasUsed'], 16)},
                                   'b1': b1, 'before': before, 'credited': credited, 'evidence': str(cache)})
        self.record('result-historical', {'stage': '430-bridge-pos pos-historical (per-SID)', 'generation': self.gen.name, 'anchorEpochs': epochs, 'pass': True})

    # ---- after the second handoff: the aggregator restart, the bridge after the restarts, the replay negatives --------------------
    def pos_whole_state(self, epoch1, extra=()):
        """The vault's whole state for every lock of these stages (not the balance alone), and the B1 registry's tip: what no refused operation may change."""
        me = epoch1['wallet']
        view = lambda sig, *args: self.vault_view(sig, *args)
        locks = {}
        for name, nonce in (('A', epoch1['lockNonce']), ('B', epoch1['lockNonceB']), ('C', epoch1['lockNonceC']), *extra):
            locks[name] = {'remaining': int(view('remaining(uint256)', str(nonce)), 16), 'redeemed': int(view('redeemedAmount(uint256)', str(nonce)), 16)}
        return {'balance': self.vault_balance(), 'credited': int(view('credited()'), 16), 'claimable': int(view('claimable(address)', me), 16),
                'locks': locks, 'b1': self.b1_state()}

    def pos_agg_restart(self):
        """The aggregator restarted at epoch 3: its history is reloaded (the same verified tip and EntryID, and a replay of that history answered as the same), and
        it keeps serving the chain; its log after the restart shows no refused trust-base update. Needs --ubft (the offline verifier)."""
        self.expect(bool(self.ubft), 'pos-agg-restart needs --ubft (the offline verifier)')
        pin = self.manifest['utb']['genesis_id']
        tip, tip_id, _ = self.utb_history('agg-before-restart', pin)
        self.expect(int(tip) >= 3, 'before the restart the aggregator serves the history to epoch 3', str(tip))
        since = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time() - 1))   # the host's clock: the docker daemon's, which --since reads
        self.say('  restarting the aggregator')
        self.compose('restart', 'aggregator')
        def served():
            status, body = self.utb_page('from=1&maxEntries=64')
            return True if status == 200 and body else None
        self.wait('the restarted aggregator serves its history', served, 180)
        after_tip, after_id, _ = self.utb_history('agg-after-restart', pin)
        self.expect((int(after_tip), str(after_id).lower()) == (int(tip), str(tip_id).lower()),
                    'the restarted aggregator reloaded the same history (tip epoch and EntryID)', f'{after_tip} {after_id}')
        self.utb_history('agg-after-restart-replay', pin, (after_tip, after_id))
        logs = self.compose('logs', '--no-color', '--since', since, 'aggregator', check=False)
        refused = [line for line in logs.splitlines() if 'dropping an invalid trust-base update' in line or 'finalized-branch conflict' in line]
        self.expect(not refused, 'after the restart the aggregator refused no trust-base update and reported no finalized-branch conflict', ' | '.join(refused)[:300])
        self.record('agg-restart', {'before': {'tip': tip, 'tipEntryId': tip_id}, 'after': {'tip': after_tip, 'tipEntryId': after_id}, 'logSince': since})

    def pos_after_restart(self):
        try:
            self.pos_after_restart_steps()
        except Exception:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)
            raise

    def pos_after_restart_steps(self):
        """After the pods' restarts (rehearse.py pos-restart-2) and the aggregator's (pos-agg-restart), a round trip at epoch 3 with the main wallet: its held history
        (to epoch 2, from pos-redeem) is reloaded by a fresh process, entry 3 is fetched from the restarted aggregator, the vault credits exactly the lock and the claim
        pays it. Token D is the replay stage's artifact too."""
        work = self.gen / 'bridge'
        epoch1 = json.loads((work / 'pos-epoch1.json').read_text())
        genesis = int(epoch1['trust']['genesisEpoch'])
        me = epoch1['wallet']
        # validator 1 was restarted, and the shard epoch advanced at each handoff: the endpoint is restarted with every shard epoch's configuration
        # (overlay.py), so a lock certified under the current shard epoch is served (it is proven under the configuration its certificate commits to)
        self.start_endpoint(1)
        overlay = json.loads((self.gen / 'compose.bridge.yaml').read_text())['services']['lockproof']['entrypoint']
        confs = [overlay[k + 1] for k, x in enumerate(overlay) if x == '--full-shard-conf']
        self.expect(len(confs) >= 3, 'the lock-proof endpoint holds the genesis shard configuration and each handoff\'s', ' '.join(confs))
        held = self.held_trust()
        self.expect(int(held['tipEpoch']) == genesis + 1, 'a fresh process reloads the main wallet\'s durable history to epoch 2 (as pos-redeem left it)', held['tipEpoch'])
        before = self.vault_balance()
        known = set(self.tokens())
        self.pos_tester('lock', '--amount', f'{POS_LOCK_WEI}wei')
        (token,) = set(self.tokens()) - known
        nonce = json.loads((work / POS_WALLET / 'tokens' / token / 'token.json').read_text())['nonce']
        self.pos_tester('mint', '--token', token)
        self.pos_tester('transfer', '--count', '1', '--token', token)
        self.pos_tester('burn', '--token', token)
        seals = self.held_trust(token=token)['seals']
        self.expect(all(int(x['rootEpoch']) >= genesis + 2 for x in seals[1:]), 'token D\'s transfer and burn are sealed at epoch 3', json.dumps(seals))
        _, text = self.pos_tester('redeem', '--token', token)
        fetches = [line.strip() for line in text.splitlines() if 'trust: fetched' in line]
        self.expect(any(f'tip {genesis + 1} -> {genesis + 2}' in f for f in fetches), 'the main wallet fetched entry 3 from the restarted aggregator', '; '.join(fetches))
        after = self.held_trust()
        ids = {int(e['epoch']): e['entryId'].lower() for e in after['entries']}
        lag = self.tester('trust', wallet=LAG_WALLET, key=POS_KEY)[1]   # the lagging wallet's durable history (pos-gap), reloaded
        lag_ids = {int(e['epoch']): e['entryId'].lower() for e in json.loads(lag[lag.index('{'):lag.rindex('}') + 1])['entries']}
        self.expect(ids == lag_ids and sorted(ids) == list(range(genesis, genesis + 3)),
                    'the main wallet\'s history 1..3 is the lagging wallet\'s, entry for entry (the same EntryIDs)', json.dumps(ids))
        state = self.vault_state(nonce, me)
        self.expect(state['claimable'] == POS_LOCK_WEI and state['remaining'] == 0 and state['redeemed'] == POS_LOCK_WEI, 'the vault credits exactly token D\'s lock', json.dumps(state))
        self.pos_tester('claim')
        self.expect(self.vault_balance() == before, 'the vault paid back token D\'s lock', str(self.vault_balance()))
        state_file = {'tokenD': token, 'lockNonceD': nonce}
        (work / 'pos-after-restart.json').write_text(json.dumps(state_file, indent=2) + '\n')
        self.record('after-restart', {'token': token, 'lockNonce': nonce, 'seals': seals, 'fetches': fetches, 'trust': after, 'credited': state,
                                      'evidence': str(self.keep_pos('after-restart'))})

    def pos_replays(self):
        try:
            self.pos_replays_steps()
        finally:
            (self.gen / 'bridge' / POS_KEY).unlink(missing_ok=True)   # the last stage that needs the wallets' key

    def pos_replays_steps(self):
        """The replay negatives at epoch 3, against the vault's whole state (every lock's remaining and redeemed amounts, the credited total, the wallet's claimable,
        the balance, the B1 tip), which must be unchanged after all of them:
          - every redeemed envelope again, as the chain holds it (A sealed at epoch 2, B per-SID at epoch 1, C and D at epoch 3): PartAlreadyRedeemed of its lock and token;
          - the claim of a credit already claimed: InsufficientCredit (none left);
          - per token (tester replays, under the held trust): the redeemed envelope mined again (status 0), a fresh consolidated proof of the redeemed burn
            under the epoch-3 seal (PartAlreadyRedeemed: refused on the nullifier, not for its age), that proof with its return recipient changed and re-signed by
            unknown keys (BridgeRejected; the plug-in ErrQuorumNotMet), and a conflicting burn of the pre-burn state (not certified: after a sentinel submitted later is certified, the first burn's proof is still served)."""
        work = self.gen / 'bridge'
        epoch1 = json.loads((work / 'pos-epoch1.json').read_text())
        d = json.loads((work / 'pos-after-restart.json').read_text())
        me = epoch1['wallet']
        word = lambda n: int(n).to_bytes(32, 'big').hex()
        extra = (('D', d['lockNonceD']),)
        before = self.pos_whole_state(epoch1, extra)
        self.expect(all(v['remaining'] == 0 and v['redeemed'] == POS_LOCK_WEI for v in before['locks'].values()) and before['claimable'] == 0,
                    'every lock of these stages is redeemed and claimed (the replays start from a settled vault)', json.dumps(before))
        tokens = {'A': (POS_WALLET, epoch1['token'], epoch1['lockNonce']), 'B': (POS_WALLET, epoch1['tokenB'], epoch1['lockNonceB']),
                  'C': (LAG_WALLET, epoch1['tokenC'], epoch1['lockNonceC']), 'D': (POS_WALLET, d['tokenD'], d['lockNonceD'])}
        record = {'before': before, 'tokens': {}}
        for name, (wallet, token, nonce) in tokens.items():
            rec = json.loads((work / wallet / 'tokens' / token / 'token.json').read_text())
            tx = self.ureth(1, 'eth_getTransactionByHash', [rec['redeemTx']])
            _, part = self.credited(rec['redeemTx'])[:2]
            r = self.inner_response(1, 'eth_call', [{'from': me, 'to': self.addresses()['BridgeVault'], 'data': tx['input']}, 'latest'])
            want = PART_ALREADY_REDEEMED + word(nonce) + part[2:]
            self.expect((r.get('error') or {}).get('data') == want, f'token {name}\'s redeemed envelope is refused again (PartAlreadyRedeemed of lock {nonce} and its token)', json.dumps(r)[:300])
            record['tokens'][name] = {'token': token, 'lockNonce': nonce, 'redeemTx': rec['redeemTx'], 'replayRefusal': want}
        claim = self.cast_run('calldata', 'claim(uint256,address)', str(POS_LOCK_WEI), me)
        r = self.inner_response(1, 'eth_call', [{'from': me, 'to': self.addresses()['BridgeVault'], 'data': claim}, 'latest'])
        self.expect((r.get('error') or {}).get('data') == INSUFFICIENT_CREDIT + word(0) + word(POS_LOCK_WEI),
                    'the claim of an already claimed credit is refused (InsufficientCredit: none left)', json.dumps(r)[:300])
        record['duplicateClaim'] = (r.get('error') or {}).get('data')
        epoch = self.b1_state()['importedTip']
        for name, (wallet, token, nonce) in tokens.items():
            if name == 'D':
                continue   # D is sealed at epoch 3 already: its fresh proof is not of a newer epoch; A, B and C carry the cross-epoch cases
            _, text = self.tester('replays', '--token', token, wallet=wallet, key=POS_KEY)
            out = json.loads((work / wallet / 'tokens' / token / 'replays.json').read_text())
            mined = out['duplicate']['mined']
            rc = self.ureth(1, 'eth_getTransactionReceipt', [mined['tx']])
            self.expect(rc is not None and rc['status'] == '0x0', f'token {name}: its redeemed envelope, mined again, reverted on chain', f'{mined["tx"]} block {int(rc["blockNumber"], 16) if rc else "?"}')
            orig = sorted({int(a['rootEpoch']) for a in out['duplicate']['originalAnchors']})
            fresh = sorted({int(a['rootEpoch']) for a in out['freshReplay']['anchors']})
            # A (redeemed under epoch 2) and B (per-SID, epoch 1) cross epochs; C was redeemed at epoch 3, so its fresh proof is a newer round of the same epoch
            # (the tester asserts the fresh seal's round is newer than every redeemed anchor's)
            self.expect(fresh == [epoch] and (name == 'C' or orig != fresh),
                        f'token {name}: a fresh proof of its redeemed burn under the epoch-{epoch} seal (redeemed under epoch {orig}) is refused as PartAlreadyRedeemed',
                        out['freshReplay']['refusal'][:80])
            self.expect(out['changedRecipient']['status'] == 36, f'token {name}: the fresh proof with its return recipient changed is refused by the composition (BridgeRejected, V2 status {out["changedRecipient"]["status"]}, ErrCDMismatch is 36)')
            forged = out['unknownKeyForgery']
            self.expect('ErrQuorumNotMet' in forged['pluginRefusal'] and forged['status'] == 61,
                        f'token {name}: re-signed by unknown keys, refused by the plug-in (ErrQuorumNotMet) and the composition (V2 status {forged["status"]}, ErrAnchorAuth is 61)', forged['pluginRefusal'][:160])
            cb = out['conflictingBurn']
            wt = cb.get('waited') or {}
            self.expect(bool(wt) and int(wt['settledAtBlock']) >= int(wt['submittedAtBlock']) + 2 and wt['sentinelStateId']
                        and wt['firstRead']['transactionHash'] == wt['reRead']['transactionHash'] == cb['servedTransactionHash'],
                        f'token {name}: the conflict\'s verdict is read after a later block (submitted at block {wt.get("submittedAtBlock")}; a sentinel submitted after it certified; '
                        f're-read at block {wt.get("settledAtBlock")}, the same certified transaction as the first read)', json.dumps(wt)[:300])
            self.expect(cb['servedTransactionHash'] != cb['conflictingTransactionHash'] and cb['pluginRefusal'],
                        f'token {name}: a conflicting burn of its burned state is not certified once later blocks are built (submission {cb["submission"]}; the first burn\'s proof is still served)', cb['pluginRefusal'][:160])
            (self.evidence / 'pos-bridge').mkdir(parents=True, exist_ok=True)
            (self.evidence / 'pos-bridge' / f'replays-{name}.json').write_bytes((work / wallet / 'tokens' / token / 'replays.json').read_bytes())
            record['tokens'][name].update({'originalEpochs': orig, 'freshEpochs': fresh, 'minedReplay': mined['tx']})
        after = self.pos_whole_state(epoch1, extra)
        self.expect(after == before, 'no replay changed the vault\'s whole state or the B1 registry (every lock, credited, claimable, balance, B1 tip)', json.dumps(after))
        record['after'] = after
        self.record('replays', record)
        self.record('result-replays', {'stage': '430-bridge-pos pos-replays (epoch 3)', 'generation': self.gen.name, 'pass': True})
