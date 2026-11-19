// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Parsing, signature and hash-chain checks. Async (WebCrypto). Independent of the replay order.

import { canonicalize } from './canonical';
import { hashCanonical, importPublicKey, keyIdFromPublicKey, signBytes, verifyBytes } from './crypto';
import { BATCH, type Domain, type OpItem } from './domain';
import { utf8 } from './encoding';
import { compareHlc, isValidHlc } from './hlc';
import { parsePath, type ParsedPath } from './paths';
import type { Envelope, Issue, TrustRoot, UnsignedEnvelope, VerifiedOp } from './types';
import { checkObject, isPlainObject } from './validate';

const envelopeSchema = {
  v: 'int',
  opId: 'id',
  scope: 'id',
  authorKeyId: 'id',
  seq: 'int',
  prevHash: 'any',
  hlc: { object: { t: 'int', c: 'int' } },
  wallTime: 'str',
  type: 'str',
  payload: 'any',
  'enc?': 'any',
  sig: 'str',
} as const;

export interface ParsedOp {
  env: Envelope;
  hash: string;
}

type ScopeMap = Pick<Domain, 'scopeDir' | 'scopeFromDir'>;

/** Parses an op file and checks it against its path. Does not check the signature. */
export async function parseOpFile(path: string, text: string, domain: ScopeMap): Promise<ParsedOp | Issue> {
  const pp = parsePath(path, (d) => domain.scopeFromDir(d));
  if (!pp || pp.kind !== 'ops') return { kind: 'unknown-file', path, detail: 'file name does not match the op pattern' };
  let env: Envelope;
  try {
    env = JSON.parse(text);
  } catch {
    return { kind: 'parse-error', path, detail: 'not valid JSON' };
  }
  return checkEnvelope(env, path, domain, pp);
}

export async function checkEnvelope(env: Envelope, path: string, domain: ScopeMap, pp: ParsedPath | null = parsePath(path, (d) => domain.scopeFromDir(d))): Promise<ParsedOp | Issue> {
  const e = checkObject(env, envelopeSchema as never, 'envelope');
  if (e) return { kind: 'parse-error', path, detail: e };
  if (env.v !== 1) return { kind: 'parse-error', path, detail: `unsupported version ${env.v}` };
  if (!isPlainObject(env.payload)) return { kind: 'parse-error', path, detail: 'payload must be an object' };
  if (env.enc !== undefined) return { kind: 'parse-error', path, detail: 'encrypted payloads are not supported in v1' };
  if (env.prevHash !== null && typeof env.prevHash !== 'string') return { kind: 'parse-error', path, detail: 'bad prevHash' };
  if (!depthOk(env, MAX_DEPTH)) return { kind: 'parse-error', path, detail: `nested deeper than ${MAX_DEPTH} levels` };
  if (env.seq < 1 || !isValidHlc(env.hlc)) return { kind: 'parse-error', path, detail: 'bad seq or hlc (out of range)' };
  if (domain.scopeDir(env.scope) === null) return { kind: 'parse-error', path, detail: 'invalid scope' };
  if (!pp || pp.scope !== env.scope || pp.keyId !== env.authorKeyId || pp.seq !== env.seq)
    return { kind: 'misplaced', path, opId: env.opId, detail: 'scope, author or seq does not match the file path' };
  let hash: string;
  try {
    hash = await hashCanonical(env);
  } catch (err) {
    return { kind: 'parse-error', path, detail: `not canonicalizable: ${(err as Error).message}` };
  }
  return { env, hash };
}

/** Maximum nesting of an op. A fixed limit gives the same result on all clients (the stack limit differs). */
export const MAX_DEPTH = 32;

/** True if no array or object in `v` is nested deeper than `max`. Iterative, so it never uses the stack. */
export function depthOk(v: unknown, max: number): boolean {
  const stack: [unknown, number][] = [[v, 0]];
  while (stack.length) {
    const [x, d] = stack.pop()!;
    if (x === null || typeof x !== 'object') continue;
    if (d >= max) return false;
    for (const c of Array.isArray(x) ? x : Object.values(x)) stack.push([c, d + 1]);
  }
  return true;
}

export const signingBytes = (env: UnsignedEnvelope | Envelope): Uint8Array => {
  const { sig: _sig, ...rest } = env as Envelope;
  return utf8(canonicalize(rest));
};

export async function signEnvelope(u: UnsignedEnvelope, sign: (b: Uint8Array) => Promise<string>): Promise<Envelope> {
  return { ...u, sig: await sign(signingBytes(u)) };
}

export const signWithKey = (privateKey: CryptoKey) => (b: Uint8Array) => signBytes(privateKey, b);

/** The items of an op: the Batch items, or the op itself. */
export function itemsOf(env: { type: string; payload: Record<string, unknown> }): OpItem[] {
  // The data is not validated here: use only items with a string type and an object payload.
  if (env.type === BATCH && Array.isArray(env.payload.ops))
    return (env.payload.ops as unknown[]).filter((o): o is Record<string, unknown> => isPlainObject(o) && typeof o.type === 'string').map((o) => ({ type: o.type as string, payload: isPlainObject(o.payload) ? o.payload : {} }));
  return [{ type: env.type, payload: env.payload }];
}

// ---- Key map ---------------------------------------------------------------------------

/** keyId → public key, from the trust root and from the ops that register keys. */
export class KeyMap {
  private keys = new Map<string, CryptoKey>();
  readonly validBindings = new Set<string>();
  private checked = new Set<string>();

  get(keyId: string): CryptoKey | undefined {
    return this.keys.get(keyId);
  }

  async add(keyId: string, publicKey: string): Promise<boolean> {
    const b = `${keyId}|${publicKey}`;
    if (this.checked.has(b)) return this.validBindings.has(b);
    this.checked.add(b);
    try {
      if ((await keyIdFromPublicKey(publicKey)) !== keyId) return false;
      // The first valid binding wins. A keyId is a hash of the public key, so a second binding cannot be valid.
      if (!this.keys.has(keyId)) this.keys.set(keyId, await importPublicKey(publicKey));
      this.validBindings.add(b);
      return true;
    } catch {
      return false;
    }
  }

  async addFromTrustRoot(tr: TrustRoot | null): Promise<void> {
    for (const r of tr?.roots ?? []) await this.add(r.keyId, r.publicKey);
  }

  /** Collects keys from ops (any op, valid or not: the binding check makes this safe). */
  async addFromOps(envs: Iterable<Envelope>, domain: Pick<Domain, 'keysIn'>): Promise<void> {
    for (const env of envs)
      for (const it of itemsOf(env)) {
        // keysIn gets unsigned, unvalidated data. An error in it ignores this item only.
        let keys: { keyId: unknown; publicKey: unknown }[] = [];
        try {
          keys = domain.keysIn(it);
        } catch {
          continue;
        }
        for (const k of keys) if (typeof k.keyId === 'string' && typeof k.publicKey === 'string') await this.add(k.keyId, k.publicKey);
      }
  }
}

export type SigStatus = 'ok' | 'bad' | 'unknown-key';

export async function verifySignature(env: Envelope, keys: KeyMap): Promise<SigStatus> {
  const k = keys.get(env.authorKeyId);
  if (!k) return 'unknown-key';
  return (await verifyBytes(k, env.sig, signingBytes(env))) ? 'ok' : 'bad';
}

// ---- Chains ------------------------------------------------------------------------------

export interface ChainInput {
  path: string;
  env: Envelope;
  hash: string;
  sig: SigStatus;
}

/** Identity of an op without its signature: 2 files with the same content and different signature texts are 1 op. */
const contentKey = (env: Envelope): string => {
  const { sig: _sig, ...rest } = env;
  return canonicalize(rest);
};

export interface ChainResult {
  valid: VerifiedOp[];
  issues: Issue[];
  /** (scope|author) → last valid seq and hash. */
  heads: Map<string, { seq: number; hash: string }>;
}

/**
 * Checks each (scope, author) hash chain. Rules (chain format 2, mytasker Q-24):
 * - Only validly signed ops of the author are chain members. Any other file in the
 *   author folder (bad signature, garbage, a misplaced copy) is an issue, and the chain
 *   skips it. Thus a file that another user saves under the next number does not block
 *   the author.
 * - The chain follows the prevHash links from the first op (prevHash null).
 *   seq must increase along the chain, but it can have gaps.
 * - The HLC must increase along the chain.
 * - An op whose prevHash points to an op that is not present waits (chain-gap):
 *   a deleted or changed op stops the chain there.
 * - 2 different valid ops with the same seq, or with the same prevHash, are a fork.
 *   The chain stops before the fork.
 * - An unknown key: the ops wait (the op that registers the key can still be in sync).
 */
export function checkChains(entries: ChainInput[]): ChainResult {
  const groups = new Map<string, ChainInput[]>();
  for (const e of entries) {
    const k = `${e.env.scope}|${e.env.authorKeyId}`;
    let g = groups.get(k);
    if (!g) groups.set(k, (g = []));
    g.push(e);
  }
  const valid: VerifiedOp[] = [];
  const issues: Issue[] = [];
  const heads = new Map<string, { seq: number; hash: string }>();
  const base = (e: ChainInput) => ({ scope: e.env.scope, authorKeyId: e.env.authorKeyId, seq: e.env.seq, path: e.path, opId: e.env.opId });
  for (const [k, g] of groups) {
    // 1. Members: validly signed ops, 1 for each content. Other files are issues only.
    const members: ChainInput[] = [];
    const seenHash = new Set<string>();
    const contentBySeq = new Map<number, Set<string>>();
    const seqMembers = new Map<number, ChainInput[]>();
    let unknownKey = false;
    for (const e of [...g].sort((a, b) => a.env.seq - b.env.seq || (a.path < b.path ? -1 : 1))) {
      if (e.sig === 'unknown-key') {
        unknownKey = true;
        issues.push({ ...base(e), kind: 'unknown-key', detail: 'signing key is not known (yet)' });
        continue;
      }
      if (e.sig === 'bad') {
        issues.push({ ...base(e), kind: 'bad-signature', detail: 'not a validly signed op of this author (changed, or written by another person): skipped' });
        continue;
      }
      // 2 files with the same content are 1 op. The same content always has the same seq, so the
      // canonical form is needed only for a seq that has more than 1 hash (rare). O(m) in total.
      if (seenHash.has(e.hash)) continue;
      seenHash.add(e.hash);
      const prevSame = seqMembers.get(e.env.seq) ?? [];
      if (prevSame.length) {
        let set = contentBySeq.get(e.env.seq);
        if (!set) contentBySeq.set(e.env.seq, (set = new Set(prevSame.map((x) => contentKey(x.env)))));
        const ck = contentKey(e.env);
        if (set.has(ck)) continue;
        set.add(ck);
      }
      members.push(e);
      seqMembers.set(e.env.seq, [...prevSame, e]);
    }
    if (unknownKey) continue; // the full chain waits for the key
    // 2. Forks: 2 members with the same seq or the same prevHash. The chain stops before the first fork.
    const forkAt = new Set<ChainInput>();
    const bySeq = new Map<number, ChainInput[]>();
    const byPrev = new Map<string, ChainInput[]>();
    for (const e of members) {
      bySeq.set(e.env.seq, [...(bySeq.get(e.env.seq) ?? []), e]);
      const pk = e.env.prevHash ?? 'null';
      byPrev.set(pk, [...(byPrev.get(pk) ?? []), e]);
    }
    for (const l of [...bySeq.values(), ...byPrev.values()]) if (l.length > 1) for (const e of l) forkAt.add(e);
    // 3. Walk the links.
    let prev: ChainInput | null = null;
    const used = new Set<ChainInput>();
    let stop: string | null = null;
    for (;;) {
      const next: ChainInput[] = byPrev.get(prev ? prev.hash : 'null') ?? [];
      if (next.length === 0) break;
      if (next.some((e) => forkAt.has(e)) || next.length > 1) {
        for (const e of next) issues.push({ ...base(e), kind: 'fork', detail: `${next.length} different ops follow the same op` });
        for (const e of next) used.add(e);
        stop = 'fork';
        break;
      }
      const e: ChainInput = next[0];
      used.add(e);
      if (bySeq.get(e.env.seq)!.length > 1) {
        issues.push({ ...base(e), kind: 'fork', detail: `${bySeq.get(e.env.seq)!.length} different ops with seq ${e.env.seq}` });
        stop = 'fork';
        break;
      }
      if (prev && e.env.seq <= prev.env.seq) {
        issues.push({ ...base(e), kind: 'chain-broken', detail: 'seq is not greater than the seq of the previous op' });
        stop = 'seq';
        break;
      }
      if (prev && compareHlc(e.env.hlc, prev.env.hlc) <= 0) {
        issues.push({ ...base(e), kind: 'chain-broken', detail: 'HLC is not greater than the HLC of the previous op' });
        stop = 'hlc';
        break;
      }
      valid.push({ env: e.env, hash: e.hash });
      heads.set(k, { seq: e.env.seq, hash: e.hash });
      prev = e;
    }
    // 4. Members that are not on the chain wait for a missing op, or come after a stop.
    for (const e of members) {
      if (used.has(e)) continue;
      if (stop) issues.push({ ...base(e), kind: 'chain-broken', detail: `not applied: the chain stops before (${stop})` });
      else if (forkAt.has(e)) issues.push({ ...base(e), kind: 'fork', detail: 'another valid op has the same seq or the same previous op' });
      else issues.push({ ...base(e), kind: 'chain-gap', detail: `waiting for the previous op ${e.env.prevHash ?? '(first)'} (missing or changed file)` });
    }
  }
  return { valid, issues, heads };
}
