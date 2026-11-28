// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Parsing, signature and hash-chain checks. Async (WebCrypto). Independent of the replay order.

import { canonicalize } from './canonical';
import { hashCanonical, importWellFormedPublicKey, isAcceptableEd25519PublicKey, isWebCryptoRejection, isWellFormedEd25519PublicKey, keyIdFromPublicKey, signBytes, verifyBytes } from './crypto';
import { BATCH, MAX_BATCH, type Domain, type OpItem } from './domain';
import { fromB64u } from './encoding';
import { utf8 } from './encoding';
import { compareHlc, isValidHlc } from './hlc';
import { parsePath, type ParsedPath } from './paths';
import type { KeyBindings } from './replay';
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

/**
 * keyId → public key, from the trust root and from the ops that register keys.
 *
 * The checks are in 2 steps, so that unsigned or hostile files cannot cost much CPU time:
 * - add() does only the cheap checks: base64url, the form of the key (isWellFormedEd25519PublicKey)
 *   and keyId = hash of the key. It does not import the key into WebCrypto.
 * - The full check of the key (isAcceptableEd25519PublicKey, about 1 ms) runs lazily, 1 time for each
 *   public key: in verify() before the WebCrypto import (so at most 1 time for each authorKeyId that
 *   has an op file), and in isValid(). A key that fails the full check gives 'bad' and is not a valid
 *   binding. Rule for the app: the domain must call isValidKeyBinding only after authorize accepted
 *   the item, so that the cost stays low. The replay does not enforce this.
 * All results are deterministic functions of the data, so all clients agree.
 */
export class KeyMap implements KeyBindings {
  /** keyId → the first binding that passed add(). A keyId is a hash of the key, so there is only 1. */
  private bindings = new Map<string, { publicKey: string; raw: Uint8Array }>();
  /** "keyId|publicKey" → the result of add(). */
  private checked = new Map<string, boolean>();
  /** public key → the result of the full check. */
  private full = new Map<string, boolean>();
  /** keyId → the WebCrypto key (a cached promise). */
  private imported = new Map<string, Promise<CryptoKey>>();

  /** True if a binding for this keyId passed add() (the full check can still fail). */
  has(keyId: string): boolean {
    return this.bindings.has(keyId);
  }

  /** Adds a binding after the cheap checks. Returns true if the binding passed them. */
  async add(keyId: string, publicKey: string): Promise<boolean> {
    const b = `${keyId}|${publicKey}`;
    const known = this.checked.get(b);
    if (known !== undefined) return known;
    this.checked.set(b, false);
    try {
      const raw = fromB64u(publicKey);
      if (!isWellFormedEd25519PublicKey(raw) || (await keyIdFromPublicKey(publicKey)) !== keyId) return false;
      if (!this.bindings.has(keyId)) this.bindings.set(keyId, { publicKey, raw });
      this.checked.set(b, true);
      return true;
    } catch {
      return false;
    }
  }

  /** The full check of a public key, cached. Sync and deterministic. */
  private fullOk(publicKey: string, raw: Uint8Array): boolean {
    let ok = this.full.get(publicKey);
    if (ok === undefined) this.full.set(publicKey, (ok = isAcceptableEd25519PublicKey(raw)));
    return ok;
  }

  /** True if the binding passed add() and the key passes the full check. For the replay (KeyBindings). */
  isValid(keyId: string, publicKey: string): boolean {
    const e = this.checked.get(`${keyId}|${publicKey}`) ? this.bindings.get(keyId) : undefined;
    return !!e && e.publicKey === publicKey && this.fullOk(publicKey, e.raw);
  }

  /**
   * Verifies a signature with the key of `keyId`. The only signature check of the engine.
   * `data` can be a function: then the method computes the data only if it needs it (not for
   * 'unknown-key' and not for a key that fails the full check).
   * - No binding for keyId: 'unknown-key'.
   * - The full check of the key (cached, sync): a fail gives 'bad'. Thus WebCrypto never gets a key
   *   that is off the curve or not in the prime-order subgroup.
   * - WebCrypto import (cached): a rejection of the key gives 'bad'.
   * - verifyBytes (form checks of the signature, then WebCrypto): false gives 'bad'. Else 'ok'.
   * Errors that are not a WebCrypto rejection (for example of the environment) are thrown again.
   */
  async verify(keyId: string, sig: string, data: Uint8Array | (() => Uint8Array)): Promise<SigStatus> {
    const e = this.bindings.get(keyId);
    if (!e) return 'unknown-key';
    if (!this.fullOk(e.publicKey, e.raw)) return 'bad';
    let p = this.imported.get(keyId);
    if (!p) {
      this.imported.set(keyId, (p = importWellFormedPublicKey(e.raw)));
      // Do not keep an error of the environment: the next call tries again.
      p.catch((err) => {
        if (!isWebCryptoRejection(err)) this.imported.delete(keyId);
      });
    }
    let key: CryptoKey;
    try {
      key = await p;
    } catch (err) {
      if (isWebCryptoRejection(err)) return 'bad';
      throw err;
    }
    return (await verifyBytes(key, sig, typeof data === 'function' ? data() : data)) ? 'ok' : 'bad';
  }

  async addFromTrustRoot(tr: TrustRoot | null): Promise<void> {
    for (const r of tr?.roots ?? []) await this.add(r.keyId, r.publicKey);
  }

  /**
   * Collects keys from ops (any op, valid or not: the binding check makes this safe). For each op, it
   * reads only the first MAX_BATCH items (the replay refuses a larger Batch, so other keys cannot be
   * used) and only the first MAX_BATCH keys, in the order of the items and of keysIn. Thus 1 op cannot
   * cost much time, also if keysIn returns many keys for 1 item. The limits are deterministic.
   * A domain must not register more than MAX_BATCH keys in 1 op: the replay result is then
   * undefined (a later key is valid only if another file registers it).
   */
  async addFromOps(envs: Iterable<Envelope>, domain: Pick<Domain, 'keysIn'>): Promise<void> {
    for (const env of envs) {
      let n = 0;
      for (const it of itemsOf(env).slice(0, MAX_BATCH)) {
        // keysIn gets unsigned, unvalidated data. An error in it ignores this item only.
        let keys: unknown;
        try {
          keys = domain.keysIn(it);
        } catch {
          continue;
        }
        if (!Array.isArray(keys)) continue;
        for (const k of keys) {
          // Each entry counts, also an entry that is not valid: the order of the entries decides.
          if (n++ >= MAX_BATCH) break;
          if (typeof k?.keyId === 'string' && typeof k.publicKey === 'string') await this.add(k.keyId, k.publicKey);
        }
        if (n >= MAX_BATCH) break;
      }
    }
  }
}

export type SigStatus = 'ok' | 'bad' | 'unknown-key';

/**
 * Verifies the signature of an op. The signing bytes (a canonicalize of the op, up to the size of the
 * file) are computed only if the key is known: the engine does not cache an 'unknown-key' result.
 */
export const verifySignature = (env: Envelope, keys: KeyMap): Promise<SigStatus> => keys.verify(env.authorKeyId, env.sig, () => signingBytes(env));

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
 * Checks each (scope, author) hash chain. Rules (chain format 2):
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
