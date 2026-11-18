/**
 * The operating envelope's tokens (driver.ts envelope, bft-core#1179): parts of a given history built from a template, so the plug-in's gas
 * bound prices them exactly as it prices a real part. The template (envelope_template.cbor) is the evidence of a two-transfer part from the
 * K = 4 lane (one transfer, then its return burn): its mint, its transfer pair and its UC stand for every mint, transfer and certificate.
 *
 *   history(H, L, G)   a part with L split levels whose root carries H transfers (the history is all upstream of the splits: each child's
 *                      mint embeds its parent, the costlier place for it), each split edge one split burn and one allocation step, the
 *                      part's own transfers none, and the root's transfers certified under G distinct certificates (the template's UC with
 *                      one hash byte varied: same size and shape, a distinct claim)
 *
 * Nothing here is a valid token: the bound does not verify, it counts (proofs, bytes, items, siblings, claims, keys, memory), and these parts
 * have the template's counts in every place, each step with its own state ID and the template's few owner keys. Pure, so the unit tests run without a chain (envelope_shape.test.ts).
 */
import { encodeMint, encodeToken, type InclusionProof, type Token } from '../../../packages/native-bridge-plugin/src/nb2/token.js';
import { encodeSplitJustification } from '../../../packages/native-bridge-plugin/src/nb2/split.js';
import { decodeEvidence } from '../../../packages/native-bridge-plugin/src/nb2/verify.js';
import { varied } from './boundary_shape.js';

export interface Template {
  root: Token; // the template's root with no transfer
  pair: { tx: Token['transfers'][number]; raw: Uint8Array; proof: InclusionProof };
  ucHashAt: number; // the offset in the UC of the first 32-byte hash's content (a byte the bound's parse does not judge)
}

/** The template of an evidence file: its root without transfers, its first transfer pair, and where its UC can be varied. */
export function template(evidence: Uint8Array): Template {
  const t = decodeEvidence(evidence);
  if (t.transfers.length < 2) throw new Error('the envelope template needs a transfer before its burn');
  const uc = t.proofs[0].uc;
  // the first 32-byte byte string (58 20 ...): varying its content keeps the UC's shape and makes its claim another
  let at = -1;
  for (let i = 0; i + 34 <= uc.length; i++) {
    if (uc[i] === 0x58 && uc[i + 1] === 0x20) {
      at = i + 2;
      break;
    }
  }
  if (at < 0) throw new Error('the template UC has no 32-byte hash to vary');
  return { root: { ...t, transfers: [], proofs: [], transfersRaw: [] }, pair: { tx: t.transfers[0], raw: t.transfersRaw[0], proof: t.proofs[0] }, ucHashAt: at };
}

/** The template's UC varied in one byte of a hash: certificate G of the history (0 is the template's own). */
function certificate(tp: Template, g: number): Uint8Array {
  const uc = Uint8Array.from(tp.pair.proof.uc);
  uc[tp.ucHashAt] ^= g & 0xff;
  uc[tp.ucHashAt + 1] ^= (g >> 8) & 0xff;
  return uc;
}

/** H transfers on TOKEN, in G consecutive certificate groups. */
function chained(tp: Template, token: Token, h: number, groups: number): Token {
  const ucs = Array.from({ length: Math.max(1, groups) }, (_, g) => certificate(tp, g));
  // each step from its own state (a distinct state ID, as a real chain of transfers has); the owners' keys stay the template's (the lane's few)
  const at = token.transfers.length;
  const proofs = Array.from({ length: h }, (_, i) => ({
    ...tp.pair.proof, cd: { ...tp.pair.proof.cd, sourceHash: varied(tp.pair.proof.cd.sourceHash, at + i + 1) }, uc: ucs[Math.floor((i * ucs.length) / Math.max(1, h))],
  }));
  return { ...token, transfers: [...token.transfers, ...Array(h).fill(tp.pair.tx)], proofs: [...token.proofs, ...proofs], transfersRaw: [...token.transfersRaw, ...Array(h).fill(tp.pair.raw)] };
}

/** The lineage, root first, of a part with H root transfers in G certificate groups and L split levels (see the file's comment). */
export function history(tp: Template, h: number, levels: number, groups: number): Token[] {
  let parent = chained(tp, tp.root, h, groups);
  const lineage: Token[] = [];
  for (let l = 0; l < levels; l++) {
    parent = chained(tp, parent, 1, 1); // the split burn (the template pair's size)
    lineage.push(parent);
    const step = { depth: 255, hash: new Uint8Array(32), sum: 1n };
    const mint = { ...tp.root.mint, justification: encodeSplitJustification(encodeToken(parent), [step]) };
    parent = { ...tp.root, mint, mintRaw: encodeMint(mint) };
  }
  lineage.push(parent);
  return lineage;
}
