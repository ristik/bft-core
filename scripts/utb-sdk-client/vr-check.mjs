// The SDK-client check of a VR generation (VR_UTB, scripts/vr-utb-steps.sh): the JS SDK 4.0 (`--sdk DIR`: a built package or checkout) holding the genesis
// entry alone, authenticated from its pin, across the first registry-driven rotation.
//   1. the certificate of epoch 1 (saved before the handoff) verifies under the genesis alone, and again under the history 1..2 after the switch;
//   2. the certificate of epoch 2 names an unknown epoch; the SDK's own fetch-and-retry gets it from the aggregator's GetTrustBase and then it verifies;
//   3. a forged entry (one signature byte changed; and an entry of another epoch) is refused by TrustBaseHistory.append, and so is the genuine entry
//      appended to a history that does not hold its predecessor.
//
//   node vr-check.mjs --sdk DIR --url AGGREGATOR_ORIGIN --genesis FILE --pin 0x.. --epoch1-uc FILE --uc FILE [--entry 2=FILE] [--partition ID] [--out REPORT]
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
// a built checkout has lib/ at its root; a packed package unpacks to package/lib
const imp = (p) => import(pathToFileURL(join(sdk, 'lib', p)).href);
const [{ TrustBaseHistory }, { RootTrustBaseV2 }, { UnicityCertificate }, { UnicityCertificateVerifier }, { UnicitySealQuorumSignaturesVerificationRule }, { Secp256k1SignatureVerifier }, { verifyWithUpdate }, { AggregatorClient }, { HexConverter }] =
  await Promise.all([
    imp('api/bft/trustbase/TrustBaseHistory.js'),
    imp('api/bft/trustbase/RootTrustBaseV2.js'),
    imp('api/bft/UnicityCertificate.js'),
    imp('api/bft/verification/UnicityCertificateVerifier.js'),
    imp('api/bft/verification/rule/UnicitySealQuorumSignaturesVerificationRule.js'),
    imp('crypto/secp256k1/Secp256k1SignatureVerifier.js'),
    imp('api/bft/verification/verifyWithUpdate.js'),
    imp('api/AggregatorClient.js'),
    imp('util/HexConverter.js'),
  ]);

const lines = [];
const say = (l) => { lines.push(l); console.log(l); };
const fail = (m) => { say(`FAIL: ${m}`); if (opt('out')) writeFileSync(opt('out'), lines.join('\n') + '\n'); process.exit(1); };
const pin = HexConverter.decode(need('pin').replace(/^0x/, ''));
const genesis = RootTrustBaseV2.decode(new Uint8Array(readFileSync(need('genesis'))));
const partition = opt('partition') ? BigInt(opt('partition')) : undefined;
const cert = (f) => UnicityCertificate.fromCBOR(new Uint8Array(readFileSync(f)));
const old = cert(need('epoch1-uc')), fresh = cert(need('uc'));
const verifier = new UnicityCertificateVerifier(new UnicitySealQuorumSignaturesVerificationRule(new Secp256k1SignatureVerifier()));
const verify = (history, c) => verifier.verifyCertificate(history, c, partition === undefined ? undefined : { partitionId: partition });
const newHistory = async () => { const h = TrustBaseHistory.create(pin); await h.append(genesis); return h; };

const history = await newHistory();
say(`sdk client: genesis epoch ${history.entries[0].epoch}, tip ${history.tip.epoch}, network ${history.networkId.id}`);
const o1 = await verify(history, old);
if (o1.verdict !== 'ok') fail(`the epoch-1 certificate does not verify under the genesis alone: ${o1.verdict} ${o1.message}`);
say('epoch-1 certificate under the genesis alone: ok');
const b = await verify(history, fresh);
if (b.verdict !== 'no_entry_for_epoch' || b.missing === null) fail(`the genesis-only client should meet an unknown epoch for the epoch-2 certificate, got ${b.verdict}: ${b.message}`);
say(`epoch-2 certificate: verdict ${b.verdict} (certificate epoch ${b.missing.epoch}, latest held ${b.missing.latest})`);

const source = new AggregatorClient(need('url'));
const calls = [];
const counting = { getTrustBasePage: (request, o) => { calls.push(request.fromEpoch); return source.getTrustBasePage(request, o); } };
const after = await verifyWithUpdate(history, [counting], (/* held */) => verify(history, fresh));
if (after.verdict !== 'ok') fail(`after the fetch-and-retry the epoch-2 certificate does not verify: ${after.verdict} ${after.message}`);
if (history.tip.epoch !== 2n && Number(history.tip.epoch) !== 2) fail(`the client's tip is ${history.tip.epoch}, expected 2`);
if (calls.length === 0 || Number(calls[0]) !== 2) fail(`the first fetch must ask from the held tip + 1 (2), asked ${calls.join(',')}`);
say(`epoch-2 certificate after the SDK's own fetch (from epoch ${calls.join(', ')}): ok; tip ${history.tip.epoch}`);
const o2 = await verify(history, old);
if (o2.verdict !== 'ok') fail(`the epoch-1 certificate does not verify under the history after the switch: ${o2.verdict} ${o2.message}`);
say('epoch-1 certificate under the history 1..2 after the switch: ok');

for (const kv of opt('entry', true)) {
  const [e, file] = [kv.slice(0, kv.indexOf('=')), kv.slice(kv.indexOf('=') + 1)];
  const got = history.entryForEpoch(BigInt(e))?.encode();
  if (!got || Buffer.compare(Buffer.from(got), readFileSync(file)) !== 0) fail(`the client's entry of epoch ${e} is not byte for byte ${file}`);
  say(`entry of epoch ${e}: the client's bytes equal ${file}`);
}

// forged entries: each must be refused by a fresh history that holds the genesis only
const real = history.entryForEpoch(2n).encode();
const refused = async (label, bytes) => {
  const h = await newHistory();
  let entry;
  try { entry = RootTrustBaseV2.decode(new Uint8Array(bytes)); } catch (e) { say(`forged entry (${label}): refused at decoding (${String(e.message ?? e).slice(0, 100)})`); return; }
  try { await h.append(entry); } catch (e) { say(`forged entry (${label}): refused by the history (${String(e.message ?? e).slice(0, 100)})`); return; }
  fail(`the forged entry (${label}) was accepted into the history`);
};
const control = await newHistory(); await control.append(RootTrustBaseV2.decode(new Uint8Array(real)));
say('control: the unmodified epoch-2 entry is accepted by a genesis-only history');
const flip = (i) => { const c = Buffer.from(real); c[i] ^= 0x01; return c; };
// the signatures are the last field of the record: change a byte inside the last 40, then one in the middle of the committee, then the epoch start
await refused('a signature byte changed', flip(real.length - 8));
await refused('a committee byte changed', flip(Math.floor(real.length / 2)));
{ // the same entry appended behind a history that does not hold its predecessor is not an extension
  const h = TrustBaseHistory.create(pin);
  try { await h.append(RootTrustBaseV2.decode(new Uint8Array(real))); fail('the epoch-2 entry was accepted without its predecessor'); } catch (e) { if (String(e.message ?? e).startsWith('FAIL')) throw e; say(`epoch-2 entry without its predecessor: refused (${String(e.message ?? e).slice(0, 100)})`); }
}
say('sdk client check: PASSED');
if (opt('out')) writeFileSync(opt('out'), lines.join('\n') + '\n');
