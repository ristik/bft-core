/**
 * The boundary stage's counterfactual steps (boundary_shape.ts) and the envelope's parts (envelope_shape.ts) against the pinned plug-in's own
 * gas bound (MeasuredGasModel, estimate-nb2-1179), on parts built from the lane's template (envelope_template.cbor). Run in the bridge tools
 * image, beside the plug-in: npx --no-install tsx --test tests/live/nb2lane/boundary_shape.test.ts
 */
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';

import { MeasuredGasModel, redeemFeatures, type RedeemShape } from '../../../packages/native-bridge-plugin/src/nb2/gas.js';
import { encodeToken, type Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { burnPairBound } from '../../../packages/native-bridge-plugin/src/nb2/bridge.js';
import { shapeHolds, type Probe } from './boundary_search.js';
import { marginals, withOneFewer, withOneMore } from './boundary_shape.js';
import { history, template } from './envelope_shape.js';

const tp = template(Uint8Array.from(readFileSync(new URL('./envelope_template.cbor', import.meta.url))));
const model = new MeasuredGasModel();
/** The preflight's shape of a lineage: the burn pending at its bound, 64 + 3 proofs. */
const shape = (lineage: Token[]): RedeemShape => ({
  evidenceBytes: encodeToken(lineage[lineage.length - 1]).length + 2 + burnPairBound(104), lineage, pendingTransactions: 1, proofs: 67n, K: 4n,
});
const G = (lineage: Token[]) => (part: Token): bigint | null => model.redeemGasLimit(shape([...lineage.slice(0, -1), part]));

test('one more repeats the last pair, one fewer drops it; a part without transfers has neither', () => {
  const [root] = history(tp, 20, 0, 4);
  const more = withOneMore(root)!;
  const fewer = withOneFewer(root)!;
  assert.equal(more.transfers.length, 21);
  assert.equal(fewer.transfers.length, 19);
  assert.equal(encodeToken(root).length - encodeToken(fewer).length, encodeToken(more).length - encodeToken(root).length);
  assert.ok(encodeToken(more).length - encodeToken(root).length >= tp.pair.raw.length + tp.pair.proof.uc.length);
  const [bare] = history(tp, 0, 0, 1);
  assert.equal(withOneMore(bare), null);
  assert.equal(withOneFewer(bare), null);
  assert.deepEqual(marginals(bare, G([bare])), { up: null, down: null });
});

test("the steps are the bound's own, and grow with the length (the verifier's memory term)", () => {
  let last = 0n;
  for (const h of [16, 100, 200, 300]) {
    const l = history(tp, h, 0, 16);
    const part = l[l.length - 1];
    const { up, down } = marginals(part, G(l));
    assert.equal(up, G(l)(withOneMore(part)!)! - G(l)(part)!);
    assert.equal(down, G(l)(part)! - G(l)(withOneFewer(part)!)!);
    assert.ok(up! > 100_000n && down! > 100_000n, `${h}: +${up} -${down}`);
    assert.ok(up! >= last, `${h}: the step ${up} below the shorter token's ${last}`);
    last = up!;
  }
});

test('shapeHolds over the bound: a pass with its next step over the limit and a refusal with its previous one within it hold', () => {
  const l = history(tp, 200, 0, 16);
  const part = l[l.length - 1];
  const g = G(l)(part)!;
  const { up, down } = marginals(part, G(l));
  const probe = (label: string, real: Probe['real'], gas: bigint): Probe => ({ label, transfers: 200, conditions: 'c', gas, up, down, real });
  // the limit at the token's own bound: it passes, one more is over, and a refusal one step above it is within the limit one fewer
  assert.equal(shapeHolds(probe('p', 'passes', g), probe('f', 'CapacityPreflight', g + down!), g), null);
});

test("the envelope's parts: their lineage, certificates and split edges as the bound counts them, monotone in the history", () => {
  for (const levels of [0, 1, 2]) {
    const l = history(tp, 100, levels, 16);
    assert.equal(l.length, levels + 1);
    const f = redeemFeatures(shape(l))!;
    assert.equal(f.edges, levels);
    assert.equal(f.allocSteps, levels);
    // every root transfer, each split burn, every mint and the pending burn
    assert.equal(f.steps, 100 + levels + (levels + 1) + 1);
    // the EVM UC, the mints' certificate (the template's), 16 for the history (the split burns share its first), the pending burn's
    assert.ok(f.claims.length === 1 + 16 + 1 || f.claims.length === 1 + 1 + 16 + 1, `${f.claims.length} claims`);
    assert.ok(model.redeemGasLimit(shape(history(tp, 101, levels, 16)))! > model.redeemGasLimit(shape(l))!);
    if (levels > 0) assert.ok(model.redeemGasLimit(shape(l))! > model.redeemGasLimit(shape(history(tp, 100, levels - 1, 16)))!);
  }
});
