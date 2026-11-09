"""The public SDK clients of the PoS bridge rehearsal (bft-core #430 row 2; briefs/pos-release-rerun-plan.md §4.2 step 7, §4.3): the JS, Rust and Java SDKs, each at its pinned
main commit (deploy/testnet/sdk-clients/pins.json), use their own trust-base fetch/cache API (TrustBaseSession / Session with the file store) against the live aggregator,
in the validators network, and are compared with the roots' served history.

  pos-sdk-clients  At root epoch >= 3 (after the second handoff), for each SDK in its own image:
                   - cold:    an empty store; trusts only the generation's genesis EntryID (the shipped genesis bundle, pinned by manifest utb.genesis_id); fetches the chain
                              genesis..tip through the SDK's session; every entry is authenticated from its predecessor by the SDK; the history is persisted;
                   - warm:    a fresh store seeded (through the SDK's store API) with the epoch-1 entry alone; the session loads it and fetches the rest;
                   - restart: a fresh process on the cold run's store: it reloads the held history from the store (and fetches only what is newer);
                   - every reported EntryID and the tip are compared with the roots' served history (rehearse.py utb_history, verified offline with ubft from the pinned genesis);
                   - the typed negatives, offline, from fixtures made out of the REAL served entries (sdk-clients/utbcbor.py; nothing is signed): a missing middle entry (epoch 3
                     offered to a session holding the genesis only, nothing fetched), entry 2 with its signatures reduced below floor(2W/3)+1 of the genesis' weights, and a session
                     of another network id than the entries'; each is the SDK's typed error, recorded by name, and each has a control that accepts the unmodified input.
                   What this does and does not show: the SDKs verify the trust-base entry objects (the epoch chain). They are not bridge verifiers: the plug-in and contracts judge
                   the lock/return envelope (bridge_pos.py). The three SDKs do not expose one bridge-verifier API and none is claimed.

The clients are built by `build_sdk_clients` (docker build, from the pinned commits); the stage builds an image that is missing.
"""
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from rehearse import Failure   # noqa: E402  (rehearse_bridge.py puts the package directory on sys.path first)
from deploy_bridge import validators_network   # noqa: E402

CLIENTS = Path(__file__).resolve().parents[1] / 'sdk-clients'
sys.path.insert(0, str(CLIENTS))
import sdkaccept   # noqa: E402
import utbcbor   # noqa: E402

LANGS = ('js', 'rust', 'java')
TRUST_BASE_NETWORK_ID = 3   # generate.py TRUST_BASE_NETWORK_ID (`trust-base generate --network-id`): the package's network; the clients also check the shipped genesis declares it
MIN_TIP_ABOVE_GENESIS = 2   # run after the second handoff (root epoch genesis + 2)
RUN_TIMEOUT = 600


class SdkClients:
    """Mixed into BridgeRehearsal: self is the rehearsal (expect, say, gen, evidence, manifest, ubft, utb_history)."""

    def sdk_pins(self):
        return json.loads((CLIENTS / 'pins.json').read_text())

    def sdk_image(self, lang):
        return f'tnops-sdk-{lang}:{self.sdk_pins()[lang]["commit"][:12]}'

    def build_sdk_client(self, lang):
        """docker build of one client from the pinned SDK commit; returns the image id."""
        pin = self.sdk_pins()[lang]
        image = self.sdk_image(lang)
        self.say(f'  building {image} from {pin["repo"]} @ {pin["commit"][:12]}')
        run = subprocess.run(['docker', 'build', '-t', image, '--build-arg', f'SDK_REPO={pin["repo"]}', '--build-arg', f'SDK_COMMIT={pin["commit"]}',
                              '-f', str(CLIENTS / lang / 'Dockerfile'), str(CLIENTS / lang)], text=True, capture_output=True)
        out = self.evidence / 'pos-bridge' / 'sdk-clients'
        out.mkdir(parents=True, exist_ok=True)
        (out / f'build-{lang}.log').write_text(run.stdout + run.stderr)
        if run.returncode:
            raise Failure(f'building the {lang} SDK client failed: ' + (run.stdout + run.stderr).strip()[-500:])
        return subprocess.check_output(['docker', 'image', 'inspect', '--format={{.Id}}', image], text=True).strip()

    def build_sdk_clients(self, force=False):
        ids = {}
        for lang in LANGS:
            have = subprocess.run(['docker', 'image', 'inspect', '--format={{.Id}}', self.sdk_image(lang)], text=True, capture_output=True)
            ids[lang] = have.stdout.strip() if have.returncode == 0 and not force else self.build_sdk_client(lang)
        return ids

    def sdk_run(self, lang, mode, store, public, negatives, out):
        """One run of the client in its image on the validators network: the published directory and the negatives read-only, its store writable. Returns the client's JSON."""
        args = ['--agg-url', self.sdk_agg_url, '--network-id', str(TRUST_BASE_NETWORK_ID), '--genesis-pin', self.sdk_pin, '--genesis', '/public/trust-base.bundle.cbor',
                '--store', '/store', '--mode', mode]
        mounts = ['-v', f'{public}:/public:ro', '-v', f'{store}:/store', '-v', f'{negatives}:/negatives:ro']
        if mode == 'cold':
            args += ['--negatives', '/negatives']
        run = subprocess.run(['docker', 'run', '--rm', '--read-only', '--network', validators_network(self.gen), '--user', '10001:10001', '--tmpfs', '/tmp', '-e', 'HOME=/tmp/home',
                              *mounts, self.sdk_image(lang), *args], text=True, capture_output=True, timeout=RUN_TIMEOUT)
        (out / f'{lang}-{mode}.stderr.log').write_text(run.stderr)
        lines = [line for line in run.stdout.splitlines() if line.startswith('{')]
        try:
            result = json.loads(lines[-1])
        except (IndexError, ValueError):
            raise Failure(f'the {lang} client printed no JSON result in {mode} mode (exit {run.returncode}): ' + (run.stdout + run.stderr).strip()[-400:])
        (out / f'{lang}-{mode}.json').write_text(json.dumps(result, indent=2) + '\n')
        self.say(f'  $ sdk-{lang} {mode} (exit {run.returncode}): tip {result.get("tipEpoch")}, held at open {result.get("heldAtOpen")}, fetched {result.get("fetched")}'
                 + (f', ERROR {result.get("error")}: {result.get("message")}' if 'error' in result else ''))
        return result

    def served_ids(self, bundle):
        """{epoch: EntryID hex} of the complete served history file (already verified offline by utb_history)."""
        _, entries = utbcbor.history(Path(bundle).read_bytes())
        return {utbcbor.entry_fields(e)[2]: utbcbor.entry_id(e).hex() for e in entries}

    def pos_sdk_clients(self):
        utb = self.manifest.get('utb')
        self.expect(bool(self.manifest.get('pos')) and bool(utb), 'the generation is a PoS generation with the signed trust-base history (--pos --utb)')
        self.expect(bool(self.ubft), 'the pinned ubft verifies the roots\' served history offline (--ubft): the clients are compared with it')
        public = self.gen / 'bridge' / 'public'
        self.sdk_pin = utb['genesis_id'].lower().removeprefix('0x')
        shipped = (public / 'trust-base.genesis.entryid').read_text().strip().lower().removeprefix('0x')
        self.expect(shipped == self.sdk_pin, 'the operator\'s shipped genesis pin is the generation\'s UTB genesis EntryID', self.sdk_pin[:16])
        # the shipped genesis bundle holds the epoch-1 entry alone; its EntryID is the pin (the clients check it themselves, from the SDK's decoded entry)
        _, genesis_entries = utbcbor.history((public / 'trust-base.bundle.cbor').read_bytes())
        self.expect(len(genesis_entries) == 1 and utbcbor.entry_id(genesis_entries[0]).hex() == self.sdk_pin, 'the shipped trust-base bundle is the genesis entry alone, of the pinned EntryID')
        self.sdk_agg_url = json.loads((public / 'tester-config.json').read_text())['aggUrl']
        out = self.evidence / 'pos-bridge' / 'sdk-clients'
        out.mkdir(parents=True, exist_ok=True)
        images = self.build_sdk_clients()

        tip0, _, history0 = self.utb_history('sdk-clients-before', self.sdk_pin)
        genesis = self.utb_genesis_epoch()
        min_tip = genesis + MIN_TIP_ABOVE_GENESIS
        self.expect(int(tip0) >= min_tip, f'the roots serve a history to at least epoch {min_tip} (after the second handoff)', str(tip0))
        shutil.copy(history0, out / 'served-history-before.cbor')
        negatives = out / 'negatives'
        shutil.rmtree(negatives, ignore_errors=True)
        facts = utbcbor.build_negatives(history0.read_bytes(), negatives)
        self.expect(facts['network'] == TRUST_BASE_NETWORK_ID, 'the served history is of the package\'s trust-base network', str(facts['network']))
        self.say(f'  negatives from the real served entries: {json.dumps(facts)}')

        results, work = {}, self.gen / 'bridge' / 'sdk-clients'
        shutil.rmtree(work, ignore_errors=True)
        for lang in LANGS:
            runs = {}
            for mode, store in (('cold', 'cold'), ('warm', 'warm'), ('restart', 'cold')):
                path = work / lang / store
                if mode != 'restart':
                    path.mkdir(parents=True)
                    if os.getuid() == 0:
                        os.chown(path, 10001, 10001)   # written by the client as the unprivileged user
                runs[mode] = self.sdk_run(lang, mode, path, public, negatives, out)
            shutil.copytree(work / lang / 'cold', out / f'{lang}-cold-store')
            results[lang] = runs

        tip1, _, history1 = self.utb_history('sdk-clients-after', self.sdk_pin)
        shutil.copy(history1, out / 'served-history-after.cbor')
        served = self.served_ids(history1)
        checks, failed = [], []
        for lang in LANGS:
            for ok, what, detail in sdkaccept.check_runs(lang, self.sdk_pins()[lang]['commit'], results[lang], served, (int(tip0), int(tip1)), min_tip=min_tip, genesis=genesis):
                checks.append({'ok': ok, 'what': what, 'detail': detail})
                if not ok:
                    failed.append((what, detail))
        (out / 'summary.json').write_text(json.dumps({'generation': self.gen.name, 'aggUrl': self.sdk_agg_url, 'networkId': TRUST_BASE_NETWORK_ID, 'genesisPin': self.sdk_pin,
                                                      'servedTip': [int(tip0), int(tip1)], 'pins': self.sdk_pins(), 'images': images,
                                                      'scope': 'trust-base entry objects through each SDK\'s session/store; not a bridge verifier',
                                                      'pass': not failed, 'checks': checks}, indent=2) + '\n')
        for c in checks:
            self.expect(c['ok'], c['what'], '' if c['ok'] else c['detail'])
        self.expect(not failed, 'every public SDK client passed', '; '.join(w for w, _ in failed))
