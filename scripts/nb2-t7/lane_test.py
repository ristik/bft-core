"""Isolated launcher regressions. Run with python3 scripts/nb2-t7/lane_test.py."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest

SCRIPTS = Path(__file__).resolve().parent
CHILD = """#!/usr/bin/env bash
trap 'echo child-term >>"$TRACE"; while [[ ! -e "$ALLOW_EXIT" ]]; do sleep .05; done
      echo child-exit >>"$TRACE"; exit 0' TERM
echo child-ready >>"$TRACE"
while :; do sleep .05; done
"""


class LaneTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for path in ('bin', 'build', 'scripts/ci', 'scripts/nb2-t7', 'plugin/node_modules/.bin'):
            (self.root / path).mkdir(parents=True)
        self.env = dict(os.environ, PATH=f"{self.root / 'bin'}:{os.environ['PATH']}",
                        TRACE=str(self.root / 'trace'), ALLOW_EXIT=str(self.root / 'allow-exit'),
                        NB2_OUT=str(self.root / 'output'), NB2_CONTRACTS=str(self.root / 'contracts'),
                        NB2_PLUGIN=str(self.root / 'plugin'), AGG_BIN=str(self.root / 'agg'),
                        URETH_BIN=str(self.root / 'bin/ureth'), UTB_VERIFIER=str(self.root / 'bin/utb'),
                        NB2_URETH_SOURCE=str(self.root / 'ureth'), NB2_LANE_SLOT='0')
        for name in ('run.sh', 'drive.sh', 'driver.ts', 'receipt.ts'):
            shutil.copy(SCRIPTS / name, self.root / 'scripts/nb2-t7')
        for name in ('build/ubft', 'build/utb-evidence', 'agg', 'bin/utb', 'bin/cast'):
            self.executable(name, '#!/bin/sh\nexit 0\n')
        self.executable('bin/git', '#!/bin/sh\ncase "$*" in *rev-parse*) echo pinned;; esac\n')
        self.executable('bin/go', "#!/bin/sh\nprintf 'vcs.revision=pinned\\nvcs.modified=false\\n'\n")
        self.executable('bin/ureth', '#!/bin/sh\necho "Commit SHA: pinned"\n')
        (self.root / 'scripts/nb2-t7/pins.json').write_text(json.dumps(
            dict(contracts='pinned', plugin='pinned', aggregator='pinned', ureth='pinned')))

    def executable(self, name, script):
        path = self.root / name
        path.write_text(script)
        path.chmod(0o755)

    def wait_trace(self, line, child):
        trace = self.root / 'trace'
        for _ in range(100):
            if trace.exists() and line in trace.read_text().splitlines():
                return
            if child.poll() is not None:
                self.fail(f'launcher exited while waiting for {line}: {child.communicate()[0]}')
            time.sleep(.05)
        self.fail(f'did not observe {line}')

    def interrupt_twice(self, script, *args):
        with subprocess.Popen(['bash', f'scripts/nb2-t7/{script}', *args], cwd=self.root, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              start_new_session=True) as child:
            try:
                self.wait_trace('child-ready', child)
                child.send_signal(signal.SIGTERM)
                self.wait_trace('child-term', child)
                child.send_signal(signal.SIGHUP)
                child.send_signal(signal.SIGINT)
                (self.root / 'allow-exit').touch()
                output, _ = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 143, output)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        return (self.root / 'trace').read_text().splitlines()

    def stub_launcher_services(self):
        self.executable('scripts/ci/mongo-up.sh', '#!/bin/sh\necho "mongo-$1" >>"$TRACE"\n')
        self.executable('scripts/nb2-t7/build-plugin.sh', '''#!/bin/sh
mkdir -p "$3/packages/native-bridge-plugin/lib"
touch "$3/packages/native-bridge-plugin/lib/index.js"
''')

    def test_repeated_signals_keep_lane_cleanup_order_and_token(self):
        self.stub_launcher_services()
        self.executable('scripts/reth-paired-devnet.sh', CHILD)
        self.executable('scripts/lane-slot.sh', '''#!/bin/sh
case "$1" in
  acquire) test "$6" = --token && test -n "$7" && test "$8 $9" = "--slot 0" || exit 1
           printf '%s\\n' "$7" > acquired-token
           echo "0 $7";;
  release) test "$*" = "release --owner nb2-t7 --token $(cat acquired-token)" || exit 1
           echo release-our-token >>"$TRACE";;
esac
''')
        self.assertEqual(self.interrupt_twice('run.sh'), [
            'mongo-up', 'child-ready', 'child-term', 'child-exit', 'mongo-down', 'release-our-token'])
        self.assertEqual(list((self.root / 'output').glob('.plugin.*')), [])

    @unittest.skipUnless(shutil.which('flock'), 'real slot acquisition requires flock')
    def test_interrupt_during_slot_acquisition_releases_claim_before_mongo(self):
        self.stub_launcher_services()
        self.executable('scripts/reth-paired-devnet.sh', '#!/bin/sh\necho lane-started >>"$TRACE"\n')
        (self.root / 'scripts/lib').mkdir()
        for path in ('lane-slot.sh', 'lib/lane-slot.sh'):
            shutil.copy(SCRIPTS.parent / path, self.root / 'scripts' / path)
        locks = self.root / 'locks'
        self.env.update(LANE_LOCK_DIR=str(locks), LANE_SLOT_TEST_STALL='wait-for-test', LANE_SLOT='3')
        self.executable('bin/sleep', '''#!/bin/sh
if [ "$1" != wait-for-test ]; then exec /bin/sleep "$@"; fi
echo acquire-stalled >>"$TRACE"
while [ ! -e "$ALLOW_EXIT" ]; do /bin/sleep .05; done
''')
        with subprocess.Popen(['bash', 'scripts/nb2-t7/run.sh'], cwd=self.root, env=self.env,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                              start_new_session=True) as child:
            try:
                self.wait_trace('acquire-stalled', child)
                self.assertEqual(len(list(locks.glob('slot-0.txt.tmp.*'))), 1)
                self.assertFalse((locks / 'slot-0.txt').exists())
                self.assertEqual(len(list((self.root / 'output').glob('.plugin.*'))), 1)
                child.send_signal(signal.SIGTERM)
                (self.root / 'allow-exit').touch()
                output, _ = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 143, output)
                self.assertIn('released slot 0', output)
            finally:
                if child.poll() is None:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
        self.assertEqual((self.root / 'trace').read_text().splitlines(), ['acquire-stalled'])
        self.assertEqual(list(locks.glob('slot-*.txt*')), [])
        self.assertEqual(list((self.root / 'output').glob('.plugin.*')), [])

    def test_repeated_signals_remove_driver_scratch(self):
        self.executable('plugin/node_modules/.bin/tsx', CHILD)
        (self.root / 'scripts/nb2-t7/descriptors.py').write_text('')
        (self.root / 'plugin/package-lock.json').touch()
        (self.root / 'output').mkdir()
        for path in ('pins.json', 'plugin-lib.sha256'):
            shutil.copy(self.root / 'scripts/nb2-t7/pins.json', self.root / 'output' / path)
        (self.root / 'test-nodes/utb').mkdir(parents=True)
        for path in ('utb-genesis.id', 'execution-genesis-hash', 'utb/utb-manifest.json'):
            (self.root / 'test-nodes' / path).touch()
        (self.root / 'testvectors/nb2-continuation-v1.1-supplement/descriptors').mkdir(parents=True)
        (self.root / 'scripts/evmtx').mkdir()
        (self.root / 'scripts/evmtx/main.go').write_text('const testKeyHex = "00"\n')
        self.assertEqual(self.interrupt_twice('drive.sh', 'rpc', 'agg', '1', 'history'),
                         ['child-ready', 'child-term', 'child-exit'])
        self.assertEqual(list((self.root / 'output').glob('.driver.*')), [])

    def test_sdk_is_rebuilt_from_the_pin_without_ignored_inputs(self):
        source = self.root / 'source'
        source.mkdir()
        real_env = {**self.env, 'PATH': os.environ['PATH']}

        def run(*args):
            subprocess.run(args, cwd=source, env=real_env, check=True, capture_output=True, text=True)

        run('git', 'init', '-q')
        (source / '.gitignore').write_text('lib/\nnode_modules/\n')
        (source / 'package.json').write_text(json.dumps(dict(
            name='nb2-provenance-test', version='1.0.0', scripts={'build': 'node build.cjs'})))
        (source / 'package-lock.json').write_text(json.dumps({
            'name': 'nb2-provenance-test', 'version': '1.0.0', 'lockfileVersion': 3,
            'packages': {'': {'name': 'nb2-provenance-test', 'version': '1.0.0'}},
        }))
        (source / 'build.cjs').write_text("""
const fs = require('node:fs');
const dir = 'packages/native-bridge-plugin/lib/nb2';
if (fs.existsSync(dir) || fs.existsSync('node_modules/poison.js')) process.exit(17);
fs.mkdirSync(dir, { recursive: true });
fs.copyFileSync('input.js', dir + '/index.js');
""")
        (source / 'input.js').write_text('export const value = "pinned";\n')
        run('git', 'add', '.')
        run('git', '-c', 'user.email=test@example.invalid', '-c', 'user.name=Lane test', 'commit', '-qm', 'pin')
        revision = subprocess.check_output(['git', '-C', source, 'rev-parse', 'HEAD'], env=real_env, text=True).strip()
        poison = source / 'packages/native-bridge-plugin/lib/nb2/index.js'
        poison.parent.mkdir(parents=True)
        poison.write_text('export const value = "poisoned";\n')
        (source / 'node_modules').mkdir()
        (source / 'node_modules/poison.js').touch()
        destination = self.root / 'rebuilt'
        run('bash', SCRIPTS / 'build-plugin.sh', source, revision, destination)
        built = destination / poison.relative_to(source)
        self.assertEqual(built.read_text(), (source / 'input.js').read_text())
        self.assertIn('poisoned', poison.read_text())


if __name__ == '__main__':
    unittest.main()
