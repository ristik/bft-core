/**
 * The boundary stage's counterfactual steps (boundary_shape.ts marginals, the arithmetic of driver.ts shapeOf) against the pinned plug-in's
 * own MeasuredGasModel: with an empty lineage the model's hops are its pending transactions, each at the signature bound, so the gas of a
 * token with one more or one fewer transfer of a given shape is the model's own answer. Run in the bridge tools image, beside the plug-in:
 * npx --no-install tsx --test tests/live/nb2lane/boundary_shape.test.ts
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { MEASURED_VERIFIER, MeasuredGasModel } from '../../../packages/native-bridge-plugin/src/nb2/gas.js';
import { shapeHolds, type Probe } from './boundary_search.js';
import { marginals, type TokenShape } from './boundary_shape.js';

const model = new MeasuredGasModel();
const SIGS = MEASURED_VERIFIER.maxSignatures - MEASURED_VERIFIER.measuredSignatures; // a pending transaction's certificate, at the bound
/** The model's gas of HOPS transfers in EVIDENCEBYTES (no lineage: every hop a pending transaction). */
const G = (hops: number, evidenceBytes: number): bigint => {
  const g = model.redeemGasLimit({ evidenceBytes, lineage: [], pendingTransactions: hops, proofs: 0n, K: 4n });
  assert.ok(g !== null);
  return g;
};
const shapedBytes = (hops: number): number => MEASURED_VERIFIER.baseBytes + MEASURED_VERIFIER.bytesPerTransfer * hops;

test("sol's clipping case (r8): 1,100-byte pairs at zero excess cost 200,064 more, and one fewer saves 190,000 (plus the signatures)", () => {
  const hops = 200;
  const shape: TokenShape = { evidenceBytes: shapedBytes(hops), hops, levels: 0, pairBytes: 1_100, extraSignatures: 0 };
  const { up, down } = marginals(shape, MEASURED_VERIFIER);
  assert.equal(up, 200_064n);
  assert.equal(down, 190_000n);
  // a refusal at 60,195,000 is 60,005,000 one transfer fewer: still over 60,000,000, so the pair is refused (the forward step would take it in)
  const p = (label: string, transfers: number, gas: bigint): Probe => ({ label, transfers, conditions: 'c', gas, up, down, real: gas <= 60_000_000n ? 'passes' : 'CapacityPreflight' });
  assert.match(shapeHolds(p('p', hops - 1, 59_950_000n), p('f', hops, 60_195_000n), 60_000_000n)!, /one transfer fewer/);
});

test('the steps are the model\'s own, at and around the clip, with signatures', () => {
  for (const hops of [17, 100, 204, 255]) {
    for (const pairBytes of [0, 500, 1_026, 1_027, 1_100, 1_490, 3_000]) {
      for (const offset of [-5_000, -1_100, -1_026, -74, -1, 0, 1, 74, 463, 1_100, 50_000]) {
        const bytes = shapedBytes(hops) + offset;
        if (bytes - pairBytes < 0) continue;
        const { up, down } = marginals({ evidenceBytes: bytes, hops, levels: 0, pairBytes, extraSignatures: SIGS }, MEASURED_VERIFIER);
        const at = `hops ${hops}, pair ${pairBytes}, excess offset ${offset}`;
        assert.equal(up, G(hops + 1, bytes + pairBytes) - G(hops, bytes), `up: ${at}`);
        assert.equal(down, G(hops, bytes) - G(hops - 1, bytes - pairBytes), `down: ${at}`);
      }
    }
  }
});

test('no transfer to remove: no backward step (never a refusal\'s pair)', () => {
  assert.equal(marginals({ evidenceBytes: 5_000, hops: 0, levels: 0, pairBytes: 1_000, extraSignatures: 0 }, MEASURED_VERIFIER).down, null);
});

test('split levels move the measured shape the steps clip at', () => {
  const levels = 2;
  const hops = 50;
  const bytes = MEASURED_VERIFIER.baseBytes + MEASURED_VERIFIER.bytesPerTransfer * hops + MEASURED_VERIFIER.bytesPerSplitLevel * levels; // zero excess
  const { up, down } = marginals({ evidenceBytes: bytes, hops, levels, pairBytes: 1_100, extraSignatures: 1 }, MEASURED_VERIFIER);
  assert.equal(up, MEASURED_VERIFIER.perTransfer + 74n * MEASURED_VERIFIER.perExcessByte + MEASURED_VERIFIER.perExtraSignature);
  assert.equal(down, MEASURED_VERIFIER.perTransfer + MEASURED_VERIFIER.perExtraSignature);
});
