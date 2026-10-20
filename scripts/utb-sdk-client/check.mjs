// The SDK-client check of the combined UTB lane (design 11.4): the JS SDK of the fork (ristik/state-transition-sdk-js, built in SDK_JS_DIR) verifies a unicity
// certificate of the epoch after a trust-base change using nothing but the genesis entry and its pin: the first verification names the missing epoch ("no entry for
// epoch e"), the fetch-and-retry loop gets the entries from the aggregator's GetTrustBase endpoint (GET /api/v1/trustbases), authenticates each from the one before,
// and the second verification succeeds. The report is the evidence; every claim in it is checked here, not printed.
//
//   node check.mjs --sdk DIR --url AGGREGATOR_ORIGIN --genesis FILE --pin 0x.. --uc FILE --expect-tip N [--entry E=FILE ...] [--partition ID] [--out REPORT]
import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';

const args = process.argv.slice(2);
const opt = (name, many = false) => {
  const out = [];
  for (let i = 0; i < args.length; i++) if (args[i] === `--${name}`) out.push(args[++i]);
  if (!many && out.length > 1) throw new Error(`--${name} given twice`);
  return many ? out : out[0];
};
const need = (name) => opt(name) ?? (() => { throw new Error(`missing --${name}`); })();

const sdk = need('sdk');
const imp = (p) => import(pathToFileURL(join(sdk, 'lib', p)).href);
const [{ TrustBaseHistory }, { UnicityCertificate }, { UnicityCertificateVerifier }, { UnicitySealQuorumSignaturesVerificationRule }, { Secp256k1SignatureVerifier }, { verifyWithTrustBaseUpdate }, { AggregatorClient }, { HexConverter }] =
  await Promise.all([
    imp('api/bft/trustbase/TrustBaseHistory.js'),
    imp('api/bft/UnicityCertificate.js'),
    imp('api/bft/verification/UnicityCertificateVerifier.js'),
    imp('api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js'),
    imp('crypto/secp256k1/Secp256k1SignatureVerifier.js'),
    imp('util/TrustBaseUtils.js'),
    imp('api/AggregatorClient.js'),
    imp('util/HexConverter.js'),
  ]);

const fail = (m) => { console.error(`FAIL: ${m}`); process.exit(1); };
const pin = need('pin').replace(/^0x/, '');
const expectTip = BigInt(need('expect-tip'));
const partition = opt('partition') ? BigInt(opt('partition')) : undefined;
const certificate = UnicityCertificate.fromCBOR(new Uint8Array(readFileSync(need('uc'))));
const verifier = new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()));
const history = await TrustBaseHistory.fromGenesis(new Uint8Array(readFileSync(need('genesis'))), HexConverter.decode(pin));
const verify = (h) => verifier.verifyCertificate(h, certificate, partition === undefined ? undefined : { partitionId: partition });
const lines = [];
const say = (l) => { lines.push(l); console.log(l); };

say(`sdk client: genesis epoch ${history.genesisEpoch}, tip ${history.tipEpoch}, network ${history.networkId.id}`);
const before = await verify(history);
if (before.verdict !== 'no_entry_for_epoch' || before.missing === null) fail(`the genesis-only client should meet an unknown epoch, got verdict ${before.verdict}: ${before.message}`);
say(`before: verdict ${before.verdict}, certificate epoch ${before.missing.epoch}, latest held ${before.missing.latest}`);

const source = new AggregatorClient(need('url'));
const calls = [];
const counting = { getTrustBaseEntries: (from, max, o) => { calls.push(from); return source.getTrustBaseEntries(from, max, o); } };
const after = await verifyWithTrustBaseUpdate(verify, history, counting);
if (after.verdict !== 'ok') fail(`after the fetch-and-retry the certificate does not verify: ${after.verdict} ${after.message}`);
if (history.tipEpoch !== expectTip) fail(`the client's tip is ${history.tipEpoch}, expected ${expectTip}`);
if (calls.length === 0 || calls[0] !== 2n) fail(`the first fetch must ask from the held tip + 1 (2), asked ${calls.join(',')}`);
say(`after: verdict ok; fetched from epoch ${calls.join(', ')} (held tip + 1); tip now ${history.tipEpoch}`);

for (const kv of opt('entry', true)) {
  const [e, file] = [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)];
  const got = history.bytes(BigInt(e));
  if (!got || Buffer.compare(Buffer.from(got), readFileSync(file)) !== 0) fail(`the client's entry of epoch ${e} is not byte for byte ${file}`);
  say(`entry of epoch ${e}: the client's bytes equal ${file}`);
}

// a second client with the final history verifies at once, with no fetch: held entries are never fetched again
const again = [];
const none = { getTrustBaseEntries: () => { again.push(1); return Promise.reject(new Error('unexpected fetch')); } };
const second = await verifyWithTrustBaseUpdate(verify, history, none);
if (second.verdict !== 'ok' || again.length !== 0) fail('a client holding the epoch verified with a fetch or failed');
say('second verification: ok with no fetch');
say('sdk client check: PASSED');
if (opt('out')) writeFileSync(opt('out'), lines.join('\n') + '\n');
