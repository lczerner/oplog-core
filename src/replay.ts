// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Deterministic replay.
//
// Input: verified ops (signature + chain OK), the trust root and the Domain.
// Output: state, audit log, integrity issues. Same input set → same output,
// independent of the order of the input array.

import { canonicalize } from './canonical';
import { BATCH, hasOp, MAX_BATCH, REVERT, type Domain, type EffectCtx, type OpItem, type OpMeta, type RevertTarget, type Superseded } from './domain';
import { compareHlc } from './hlc';
import type { AppliedWrite, AuditEntry, Cutoff, Entity, Envelope, Issue, ItemNote, State, TrustRoot, VerifiedOp, Write } from './types';
import { checkObject, isIso, isUnsafeKey, type Schema } from './validate';

export const FUTURE_CLOCK_MS = 3600_000;

/** What an applied op wrote. Replay keeps it for Revert. */
export interface AppliedInfo {
  opId: string;
  hash: string;
  scope: string;
  type: string;
  /** [type] for a plain op; the item types for a Batch. */
  itemTypes: string[];
  userId: string;
  writes: AppliedWrite[];
}

export interface ReplayResult {
  state: State;
  audit: AuditEntry[];
  issues: Issue[];
  /**
   * The applied ops, by the hash of the op (not by the opId: an opId is unique only
   * for 1 author key, so 2 authors can use the same opId).
   */
  applied: Map<string, AppliedInfo>;
  cutoffs: Map<string, Cutoff>;
}

/** The key bindings that the replay can use (EffectCtx.isValidKeyBinding). KeyMap in verify.ts implements it. */
export interface KeyBindings {
  /** True if publicKey is a valid key for keyId (sync and deterministic). */
  isValid(keyId: string, publicKey: string): boolean;
}

/** No valid key binding. For tests and tools. */
export const NO_KEY_BINDINGS: KeyBindings = { isValid: () => false };

export interface ReplayOptions {
  domain: Domain;
  trustRoot: TrustRoot | null;
  /** The key bindings checked by verify.ts (KeyMap). */
  validKeyBindings: KeyBindings;
}

// An empty Batch is rejected: it would skip authorize (a user without rights would get no-effect, not a rejection).
export const batchSchema: Schema = { ops: { list: { object: { type: 'str', payload: 'any' } }, max: MAX_BATCH, min: 1 } };
export const revertSchema: Schema = {
  target: { object: { opId: 'id', hash: 'str' } },
  inverse: { list: { object: { e: 'str', id: 'id', f: 'str', v: 'any' } }, max: 100_000 },
};

export const orderKey = (a: Envelope, b: Envelope): number =>
  compareHlc(a.hlc, b.hlc) ||
  (a.authorKeyId < b.authorKeyId ? -1 : a.authorKeyId > b.authorKeyId ? 1 : 0) ||
  a.seq - b.seq ||
  (a.scope < b.scope ? -1 : a.scope > b.scope ? 1 : 0);

export function sortOps(ops: VerifiedOp[]): VerifiedOp[] {
  return [...ops].sort((x, y) => orderKey(x.env, y.env));
}

const MAX_FIXPOINT = 6;

export function replay(ops: VerifiedOp[], opts: ReplayOptions): ReplayResult {
  return replayFull(ops, opts).result();
}

/**
 * Full replay with the revocation fixpoint. Returns the Replayer for later incremental use.
 * Revocation cutoffs apply to ALL ops of a key, also to ops ordered before the
 * revocation op. A revocation can invalidate another revocation, so iterate.
 */
export function replayFull(ops: VerifiedOp[], opts: ReplayOptions): Replayer {
  const sorted = sortOps(ops);
  const rootCut = rootCutoffs(opts.trustRoot);
  let cutoffs = rootCut;
  let res = replayOnce(sorted, opts, cutoffs);
  for (let i = 0; i < MAX_FIXPOINT; i++) {
    let found: Map<string, Cutoff>;
    try {
      found = opts.domain.revocations(res.state);
    } catch (e) {
      res.issues.push({ kind: 'domain', detail: `revocations: internal error: ${e instanceof Error ? e.message : String(e)}` });
      res.endIssue = true;
      return res;
    }
    const next = mergeCutoffs(rootCut, found);
    if (sameCutoffs(next, cutoffs)) return res;
    cutoffs = next;
    res = replayOnce(sorted, opts, cutoffs);
  }
  res.issues.push({ kind: 'unauthorized', detail: `revocation cutoffs did not become stable after ${MAX_FIXPOINT} rounds` });
  res.endIssue = true;
  return res;
}

/** True if an op contains a revocation (then an incremental apply is not safe). */
export function hasRevocation(env: Envelope, domain: Domain): boolean {
  try {
    if (env.type === BATCH && Array.isArray(env.payload.ops)) return (env.payload.ops as OpItem[]).some((o) => o && domain.isRevocation(o));
    return domain.isRevocation({ type: env.type, payload: env.payload });
  } catch {
    return true; // unknown: a full replay is always correct
  }
}

function rootCutoffs(tr: TrustRoot | null): Map<string, Cutoff> {
  const m = new Map<string, Cutoff>();
  for (const r of tr?.roots ?? []) if (r.cutoffs) m.set(r.keyId, { ...r.cutoffs });
  return m;
}

/** Cutoff of a key in a scope. A scope that is not in the cutoff has the cutoff 0. */
export const cutoffFor = (c: Cutoff, scope: string): number => (Object.prototype.hasOwnProperty.call(c, scope) ? c[scope] : 0);

/** The lowest cutoff of each key and scope. */
export function mergeCutoffs(a: Map<string, Cutoff>, b: Map<string, Cutoff>): Map<string, Cutoff> {
  const out = new Map<string, Cutoff>();
  for (const m of [a, b])
    for (const [k, c] of m) {
      const cur = out.get(k);
      if (!cur) {
        out.set(k, { ...c });
        continue;
      }
      const merged: Cutoff = {};
      for (const s of new Set([...Object.keys(cur), ...Object.keys(c)])) merged[s] = Math.min(cutoffFor(cur, s), cutoffFor(c, s));
      out.set(k, merged);
    }
  return out;
}

function sameCutoffs(a: Map<string, Cutoff>, b: Map<string, Cutoff>): boolean {
  if (a.size !== b.size) return false;
  for (const [k, v] of a) {
    const w = b.get(k);
    if (!w || canonicalize(v) !== canonicalize(w)) return false;
  }
  return true;
}

// ---- State helpers ------------------------------------------------------------------------

const has = (o: object, k: string): boolean => Object.prototype.hasOwnProperty.call(o, k);

/** Own-property lookup: an ID such as "constructor" never finds a prototype member. */
export function getEntity(state: State, scope: string, e: string, id: string): Entity | undefined {
  const s = state.scopes;
  if (!has(s, scope) || !has(s[scope], e) || !has(s[scope][e], id)) return undefined;
  return s[scope][e][id];
}

/**
 * The table of an entity type. Makes the scope and the table if they do not exist.
 * Own-property checks only: a scope or a type such as "constructor" must not find a
 * prototype member (for example the global `Object`) and write into it.
 */
function table(state: State, scope: string, e: string): Record<string, Entity> {
  const s = has(state.scopes, scope) ? state.scopes[scope] : (state.scopes[scope] = {});
  return has(s, e) ? s[e] : (s[e] = {});
}

interface JournalEntry {
  scope: string;
  e: string;
  id: string;
  f: string;
  hadEntity: boolean;
  hadField: boolean;
  prev: unknown;
  /** This write made the table (and possibly the scope) of the entity. */
  newTable: boolean;
  newScope: boolean;
}

/** Applies writes and records each change in the journal, so that it can be undone. */
function applyWrites(state: State, scope: string, writes: Write[], journal: JournalEntry[]): AppliedWrite[] {
  const out: AppliedWrite[] = [];
  for (const w of writes) {
    if (isUnsafeKey(scope) || isUnsafeKey(w.e) || isUnsafeKey(w.id) || isUnsafeKey(w.f)) throw new Reject('invalid-payload', `unsafe key in a write: ${w.e}.${w.id}.${w.f}`);
    const newScope = !has(state.scopes, scope);
    const newTable = newScope || !has(state.scopes[scope], w.e);
    const t = table(state, scope, w.e);
    const cur = has(t, w.id) ? t[w.id] : undefined;
    const hadField = !!cur && has(cur, w.f);
    const prev = hadField ? cur![w.f] : undefined;
    journal.push({ scope, e: w.e, id: w.id, f: w.f, hadEntity: !!cur, hadField, prev, newTable, newScope });
    const ent = cur ?? (t[w.id] = { id: w.id });
    ent[w.f] = w.v;
    out.push({ ...w, before: prev === undefined ? null : prev, existed: !!cur });
  }
  return out;
}

function undo(state: State, journal: JournalEntry[], mark: number): void {
  for (let i = journal.length - 1; i >= mark; i--) {
    const j = journal[i];
    const t = table(state, j.scope, j.e);
    if (!j.hadEntity) delete t[j.id];
    else if (j.hadField) t[j.id][j.f] = j.prev;
    else delete t[j.id][j.f];
    if (j.newTable) delete state.scopes[j.scope][j.e];
    if (j.newScope) delete state.scopes[j.scope];
  }
  journal.length = mark;
}

/** True if a write changes a protected entity (from the trust root) or sets the `root` flag. */
function touchesRoot(state: State, scope: string, writes: Write[]): boolean {
  for (const w of writes) {
    if (w.f === 'root') return true;
    if (getEntity(state, scope, w.e, w.id)?.root === true) return true;
  }
  return false;
}

export function makeCtx(state: State, op: OpMeta, validKeyBindings: KeyBindings): EffectCtx {
  return {
    op,
    state,
    get: (e, id) => getEntity(state, op.scope, e, id),
    getIn: (scope, e, id) => getEntity(state, scope, e, id),
    list: (e, scope = op.scope) => (has(state.scopes, scope) && has(state.scopes[scope], e) ? Object.values(state.scopes[scope][e]) : []),
    isValidKeyBinding: (k, p) => validKeyBindings.isValid(k, p),
  };
}

// ---- Inverse of an op (Revert) ------------------------------------------------------------

export type InverseResult = { writes: Write[]; computed: Set<string> } | Superseded;

/**
 * A read-only copy of an applied op, for `EffectCtx.revertTarget`. The copy is shallow:
 * the values `v` and `before` of the writes are the same objects as in the state. Do not change them.
 */
export function revertTargetOf(t: AppliedInfo): RevertTarget {
  return Object.freeze({
    opId: t.opId,
    hash: t.hash,
    scope: t.scope,
    type: t.type,
    itemTypes: Object.freeze([...t.itemTypes]),
    userId: t.userId,
    writes: Object.freeze(t.writes.map((w) => Object.freeze({ ...w }))),
  });
}

/** True if the op type is valid in the scope: OpDef.scopes against Domain.scopeKind(scope), or the scope itself. */
export function validInScope(domain: Domain, scopes: readonly string[], scope: string): boolean {
  return scopes.includes(domain.scopeKind ? domain.scopeKind(scope) : scope);
}

/** A superseded note with the code of the domain, if the domain gave a string code. */
function supersededNote(item: number, type: string, s: Superseded): ItemNote {
  const n: ItemNote = { item, type, status: 'superseded', reason: s.superseded };
  if (typeof s.code === 'string') n.code = s.code;
  return n;
}

const wkey = (w: { e: string; id: string; f: string }): string => `${w.e}|${w.id}|${w.f}`;

/**
 * The inverse of an applied op, at the state of ctx:
 * - a field of an entity that existed before the target: the `before` value;
 * - an entity that the target created: Domain.removeWrites.
 * The UI (planRevert) and the replay use the same function.
 */
export function computeInverse(target: AppliedInfo, ctx: EffectCtx, domain: Domain): InverseResult {
  const first = new Map<string, AppliedWrite>();
  const created = new Set<string>();
  for (const w of target.writes) {
    if (domain.isDerived?.(w.e, w.f)) continue;
    if (!first.has(wkey(w))) first.set(wkey(w), w);
    if (!w.existed) created.add(`${w.e}|${w.id}`);
  }
  const writes: Write[] = [];
  const computed = new Set<string>();
  const removed = new Set<string>();
  for (const w of first.values()) {
    const ek = `${w.e}|${w.id}`;
    if (created.has(ek)) {
      if (removed.has(ek)) continue;
      removed.add(ek);
      const r = domain.removeWrites(w.e, w.id, ctx);
      if ('superseded' in r) return r;
      for (const x of r.writes) {
        writes.push(x);
        if (r.computed.includes(x.f)) computed.add(wkey(x));
      }
    } else writes.push({ e: w.e, id: w.id, f: w.f, v: w.before ?? null });
  }
  return { writes, computed };
}

/** The inverse without the computed fields, as it goes into the Revert payload. */
export const payloadInverse = (r: { writes: Write[]; computed: Set<string> }): Write[] => r.writes.filter((w) => !r.computed.has(wkey(w)));

// ---- Replay -----------------------------------------------------------------------------------

class Reject extends Error {
  constructor(
    readonly kind: Issue['kind'],
    readonly reason: string,
  ) {
    super(reason);
  }
}

/**
 * Applies ops one by one, in the total order. replay() uses it for a full
 * replay. The engine keeps it to apply new ops that sort after all known ops.
 */
export class Replayer {
  readonly state: State;
  readonly audit: AuditEntry[] = [];
  readonly issues: Issue[] = [];
  /** The applied ops, by the hash of the op. */
  readonly applied = new Map<string, AppliedInfo>();
  /** The opIds of all ops before this point (also of rejected ops), for each author key. */
  private readonly seenOpIds = new Map<string, Set<string>>();
  /** The highest HLC time of the earlier ops that the replay did not reject or rejected only because of a revocation cutoff. */
  private maxT = 0;
  last: Envelope | null = null;
  /**
   * True if replayFull() added an issue after the last op (revocations failed or did not become
   * stable). Then the issues of later ops would come after it, but a full replay puts them before
   * it. Thus the caller must not apply more ops or take back ops: it must do a full replay.
   */
  endIssue = false;
  /**
   * The ops at the end of the order that the replay rejected (the longest such tail), with what
   * the run of each op changed. takeBackRejected() uses it to undo these runs exactly.
   */
  private tail: { op: VerifiedOp; before: Envelope | null; maxT: number; addedOpId: boolean; issues: Issue[] }[] = [];

  constructor(
    private readonly opts: ReplayOptions,
    readonly cutoffs: Map<string, Cutoff>,
  ) {
    this.state = opts.domain.rootState(opts.trustRoot);
  }

  result(): ReplayResult {
    return { state: this.state, audit: this.audit, issues: this.issues, applied: this.applied, cutoffs: this.cutoffs };
  }

  apply(op: VerifiedOp): AuditEntry {
    const entry = this.run(op, false);
    this.last = op.env;
    return entry;
  }

  /**
   * The ops at the end of the order that the replay rejected, in order. `before` is the last op
   * before the op (null if there is none).
   */
  rejectedTail(): { op: VerifiedOp; before: Envelope | null }[] {
    return this.tail.map((t) => ({ op: t.op, before: t.before }));
  }

  /**
   * Takes back the last `n` ops of rejectedTail() and returns them in order. After this, the
   * Replayer is the same as if these ops never ran: the audit log, the issues, the opIds, maxT and
   * `last` are as before them. A rejected op does not change the state or `applied`. The caller
   * can then apply new ops and these ops again, in the total order: the result is the same as a
   * full replay with the same cutoffs.
   */
  takeBackRejected(n: number): VerifiedOp[] {
    if (!Number.isSafeInteger(n) || n < 0 || n > this.tail.length) throw new Error(`takeBackRejected: ${n} is not in 0..${this.tail.length}`);
    const out = this.tail.splice(this.tail.length - n, n);
    for (let i = out.length - 1; i >= 0; i--) {
      const t = out[i];
      this.audit.pop();
      // Remove the issues of this run. Each issue object is unique. replayFull can add issues after
      // the last op, thus remove by identity and not by position.
      for (let k = t.issues.length - 1; k >= 0; k--) {
        const at = this.issues.lastIndexOf(t.issues[k]);
        if (at >= 0) this.issues.splice(at, 1);
      }
      // Remove the opId only if this run added it (a duplicate opId was there before).
      if (t.addedOpId) this.seenOpIds.get(t.op.env.authorKeyId)?.delete(t.op.env.opId);
      this.maxT = t.maxT;
      this.last = t.before;
    }
    return out.map((t) => t.op);
  }

  /**
   * Applies an op as if it were the next op, and undoes it. For the check
   * before a write. The audit log, the issues and the state do not change.
   */
  probe(env: Envelope): AuditEntry {
    return this.run({ env, hash: 'probe' }, true);
  }

  private run({ env, hash }: VerifiedOp, dry: boolean): AuditEntry {
    const { domain } = this.opts;
    const { state } = this;
    const entry: AuditEntry = {
      opId: env.opId,
      hash,
      scope: env.scope,
      type: env.type,
      authorKeyId: env.authorKeyId,
      userId: null,
      seq: env.seq,
      hlc: env.hlc,
      wallTime: env.wallTime,
      status: 'rejected',
      writes: [],
      notes: [],
      payload: env.payload,
    };
    const issues: Issue[] = [];
    const issue = (kind: Issue['kind'], detail: string) =>
      issues.push({ kind, detail, opId: env.opId, scope: env.scope, authorKeyId: env.authorKeyId, seq: env.seq });

    if (!dry) {
      // Deterministic future-clock check: the HLC is far after the op's own wall time,
      // and greater than maxT (the HLCs of the earlier ops that count, see below).
      // Honest clients only copy such an HLC.
      const wall = isIso(env.wallTime) ? Date.parse(env.wallTime) : NaN;
      if (Number.isFinite(wall) && env.hlc.t > wall + FUTURE_CLOCK_MS && env.hlc.t > this.maxT)
        issue('future-clock', `HLC is ${Math.round((env.hlc.t - wall) / 60_000)} minutes after the wall time of the op`);
    }

    const journal: JournalEntry[] = [];
    const ownIds = this.seenOpIds.get(env.authorKeyId);
    let rejectKind: Issue['kind'] | null = null;
    try {
      // An opId is unique only for 1 author key. Thus a copied opId of another author
      // cannot cancel an op: an author can only hurt own ops.
      if (ownIds?.has(env.opId)) throw new Reject('invalid-payload', 'duplicate opId');
      if (domain.scopeDir(env.scope) === null) throw new Reject('invalid-payload', 'invalid scope');
      const userId = domain.keyOwner(state, env.authorKeyId);
      if (typeof userId !== 'string') throw new Reject('unauthorized', 'unknown key');
      entry.userId = userId;
      const cut = this.cutoffs.get(env.authorKeyId);
      if (cut && env.seq > cutoffFor(cut, env.scope)) throw new Reject('revoked', `key revoked after seq ${cutoffFor(cut, env.scope)} in ${env.scope}`);

      const meta = (item: number): OpMeta => ({ opId: env.opId, scope: env.scope, authorKeyId: env.authorKeyId, userId, seq: env.seq, hlc: env.hlc, wallTime: env.wallTime, envType: env.type, item });
      if (env.type === REVERT) this.revert(env, meta(0), entry, journal);
      else this.items(env, meta, entry, journal);
    } catch (err) {
      // An error in domain code rejects this op only. It must not block the replay for all clients.
      const e = err instanceof Reject ? err : new Reject('domain', `internal error: ${err instanceof Error ? err.message : String(err)}`);
      undo(state, journal, 0);
      rejectKind = e.kind;
      entry.status = 'rejected';
      entry.reason = e.reason;
      entry.writes = [];
      entry.notes = [];
      issue(e.kind, `${env.type}: ${e.reason}`);
    }

    if (dry) {
      undo(state, journal, 0);
      return entry;
    }
    const addedOpId = !ownIds?.has(env.opId);
    const maxTBefore = this.maxT;
    if (ownIds) ownIds.add(env.opId);
    else this.seenOpIds.set(env.authorKeyId, new Set([env.opId]));
    // maxT grows from ops that the replay did not reject. It also grows from ops that only a
    // revocation cutoff rejects: before the revocation, honest clients applied such an op and
    // copied its HLC, so their later ops must not become future-clock ops. Other rejected ops
    // (for example of a key that nobody granted) do not move maxT. Else they can hide the
    // future clock of a later op.
    if ((rejectKind === null || rejectKind === 'revoked') && env.hlc.t > this.maxT) this.maxT = env.hlc.t;
    this.audit.push(entry);
    this.issues.push(...issues);
    // run() runs before apply() sets `last`: this.last is the op before this op.
    if (entry.status === 'rejected') this.tail.push({ op: { env, hash }, before: this.last, maxT: maxTBefore, addedOpId, issues });
    else this.tail = [];
    if (entry.status === 'applied')
      this.applied.set(hash, {
        opId: env.opId,
        hash,
        scope: env.scope,
        type: env.type,
        itemTypes: entry.itemTypes ?? [env.type],
        userId: entry.userId!,
        writes: entry.writes,
      });
    return entry;
  }

  /** A plain op or a Batch. */
  private items(env: Envelope, meta: (i: number) => OpMeta, entry: AuditEntry, journal: JournalEntry[]): void {
    const { domain, validKeyBindings } = this.opts;
    let items: OpItem[];
    if (env.type === BATCH) {
      const e = checkObject(env.payload, batchSchema);
      if (e) throw new Reject('invalid-payload', e);
      items = env.payload.ops as OpItem[];
      entry.itemTypes = items.map((i) => i.type);
      if (items.some((i) => i.type === BATCH || i.type === REVERT)) throw new Reject('invalid-payload', 'nested Batch or Revert');
    } else items = [{ type: env.type, payload: env.payload }];

    const all: AppliedWrite[] = [];
    items.forEach((it, i) => {
      const where = items.length > 1 ? `item ${i} (${it.type})` : it.type;
      if (!hasOp(domain.catalog, it.type)) throw new Reject('invalid-payload', `${where}: unknown op type`);
      const def = domain.catalog[it.type];
      if (!validInScope(domain, def.scopes, env.scope)) throw new Reject('invalid-payload', `${where}: not valid in scope ${env.scope}`);
      const err = checkObject(it.payload, def.schema) ?? def.check?.(it.payload) ?? null;
      if (err) throw new Reject('invalid-payload', `${where}: ${err}`);
      const ctx = makeCtx(this.state, meta(i), validKeyBindings);
      const a = domain.authorize(it, ctx);
      if (!a.ok) throw new Reject('unauthorized', `${where}: ${a.reason}`);
      const r = def.effects(it.payload, ctx);
      if ('noEffect' in r) return void entry.notes.push({ item: i, type: it.type, status: 'no-effect', reason: r.noEffect });
      if ('superseded' in r) return void entry.notes.push(supersededNote(i, it.type, r));
      const res = this.applyChecked(r.writes, ctx, journal);
      if (!Array.isArray(res)) return void entry.notes.push(supersededNote(i, it.type, res));
      all.push(...res);
    });
    this.finish(entry, all);
  }

  /** Applies writes, the domain's derived writes, and the state check. Returns a Superseded result if the item is superseded. */
  private applyChecked(writes: Write[], ctx: EffectCtx, journal: JournalEntry[]): AppliedWrite[] | Superseded {
    const { domain } = this.opts;
    const scope = ctx.op.scope;
    if (touchesRoot(this.state, scope, writes)) throw new Reject('unauthorized', 'trust root entities cannot be changed by ops');
    const mark = journal.length;
    const done = applyWrites(this.state, scope, writes, journal);
    const derived = domain.normalize?.(done, ctx) ?? [];
    if (derived.length) {
      if (touchesRoot(this.state, scope, derived)) throw new Reject('unauthorized', 'trust root entities cannot be changed by ops');
      done.push(...applyWrites(this.state, scope, derived, journal));
    }
    const bad = domain.checkState?.(done, ctx) ?? null;
    if (bad) {
      undo(this.state, journal, mark);
      return typeof bad === 'string' ? { superseded: bad } : bad;
    }
    // Writes that set a field to the value it had are no change. Keep only real changes.
    return done.filter((w) => !(w.existed && canonicalize(w.before ?? null) === canonicalize(w.v ?? null)));
  }

  private finish(entry: AuditEntry, writes: AppliedWrite[]): void {
    entry.writes = writes;
    if (writes.length) entry.status = 'applied';
    else entry.status = entry.notes.some((n) => n.status === 'superseded') ? 'superseded' : 'no-effect';
    const reasons = entry.notes.map((n: ItemNote) => (entry.notes.length > 1 || entry.type === BATCH ? `item ${n.item} (${n.type}): ${n.reason}` : n.reason));
    if (reasons.length) entry.reason = reasons.join('; ');
    const code = entry.notes[0]?.code;
    if (entry.status === 'superseded' && entry.type !== BATCH && code !== undefined) entry.code = code;
  }

  private revert(env: Envelope, meta: OpMeta, entry: AuditEntry, journal: JournalEntry[]): void {
    const { domain, validKeyBindings } = this.opts;
    const e = checkObject(env.payload, revertSchema);
    if (e) throw new Reject('invalid-payload', e);
    const p = env.payload as { target: { opId: string; hash: string }; inverse: Write[] };
    entry.revertOf = p.target.opId;
    entry.revertOfHash = p.target.hash;
    entry.itemTypes = [REVERT];
    const ctx = makeCtx(this.state, meta, validKeyBindings);
    // Find the target before authorize, so that authorize can see it (for example its author).
    // The order of the rejections does not change: authorize first, then the target checks.
    // The hash identifies the target. The opId of the payload must be the opId of that op.
    const target = this.applied.get(p.target.hash);
    const found = !!target && target.opId === p.target.opId;
    if (found && target.scope === env.scope) ctx.revertTarget = revertTargetOf(target);
    const a = domain.authorize({ type: REVERT, payload: p }, ctx);
    if (!a.ok) throw new Reject('unauthorized', a.reason);
    if (!target || !found) throw new Reject('invalid-payload', 'revert target is not an applied op before this op');
    if (target.scope !== env.scope) throw new Reject('invalid-payload', 'revert must be in the scope of its target');
    for (const t of target.itemTypes) if (t !== REVERT && !(hasOp(domain.catalog, t) && domain.catalog[t].revertible)) throw new Reject('invalid-payload', `${t} cannot be reverted`);
    const inv = computeInverse(target, ctx, domain);
    if ('superseded' in inv) {
      entry.notes.push(supersededNote(0, REVERT, inv));
      return this.finish(entry, []);
    }
    if (canonicalize(payloadInverse(inv)) !== canonicalize(p.inverse)) throw new Reject('invalid-payload', 'inverse does not match the writes of the target');
    const res = this.applyChecked(inv.writes, ctx, journal);
    if (!Array.isArray(res)) {
      entry.notes.push(supersededNote(0, REVERT, res));
      return this.finish(entry, []);
    }
    this.finish(entry, res);
  }
}

function replayOnce(sorted: VerifiedOp[], opts: ReplayOptions, cutoffs: Map<string, Cutoff>): Replayer {
  const r = new Replayer(opts, cutoffs);
  for (const op of sorted) r.apply(op);
  return r;
}
