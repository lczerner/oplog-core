// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// The Domain interface: everything that the generic replay and engine need from an app.
//
// Rules for all functions of a Domain:
// - Pure and deterministic. No Date.now(), no randomness, no locale-dependent
//   logic, no dependence on the iteration order of a Map or an object.
// - They read the state, but never change it. The replay applies the writes.
// - Read the state with own-property checks (ctx.get, ctx.getIn, ctx.list do this).
//   A name such as "constructor" must never find a member of Object.prototype.

import type { Hlc } from './hlc';
import type { Storage } from './storage/types';
import type { AppliedWrite, Cutoff, Entity, State, TrustRoot, Write } from './types';
import type { Schema } from './validate';

/** Op types that the generic replay handles itself. */
export const BATCH = 'Batch';
export const REVERT = 'Revert';
export const MAX_BATCH = 500;

/** True if the catalogue has its own entry for this op type (not a prototype member such as "constructor"). */
export const hasOp = (catalog: Record<string, OpDef>, type: string): boolean => Object.prototype.hasOwnProperty.call(catalog, type);

/** The op that the replay applies now, as the domain sees it. */
export interface OpMeta {
  /** Unique only for 1 author key. 2 authors can use the same opId. */
  opId: string;
  scope: string;
  authorKeyId: string;
  /** User of the author key (from Domain.keyOwner). */
  userId: string;
  seq: number;
  hlc: Hlc;
  wallTime: string;
  /** The op type of the envelope (`Batch` for an item of a batch). */
  envType: string;
  /** Index of the item in a Batch, 0 for a plain op. */
  item: number;
}

export interface EffectCtx {
  op: OpMeta;
  state: State;
  /** Entity in the scope of the op. */
  get(e: string, id: string): Entity | undefined;
  /** Entity in another scope. */
  getIn(scope: string, e: string, id: string): Entity | undefined;
  /**
   * All entities of 1 type in a scope (the scope of the op if not given).
   * The order is the insertion order of the state. It is the same on all clients
   * for the same set of ops, but do not give it a meaning. Sort if the order matters.
   */
  list(e: string, scope?: string): Entity[];
  /**
   * True if verify.ts checked that keyId is the hash of publicKey and that publicKey is an acceptable
   * Ed25519 key (the full check, about 1 ms, 1 time for each key). Rule for the app: call it only
   * after authorize accepted the item, so that the cost stays low. The replay does not enforce this.
   */
  isValidKeyBinding(keyId: string, publicKey: string): boolean;
  /**
   * Only for a Revert: the target op, if it is an applied op before the Revert, in the
   * scope of the Revert, with the hash and the opId of the payload. The replay finds the
   * target by its hash, because an opId is unique only for 1 author key. Else undefined
   * (then the replay rejects the Revert after `authorize`). Read-only: a frozen, shallow
   * copy. The values `v` and `before` of the writes are the same objects as in the replay
   * and in the state. The domain must not change them.
   */
  revertTarget?: RevertTarget;
}

/** The target op of a Revert, as `authorize` and the other domain functions see it. */
export interface RevertTarget {
  readonly opId: string;
  readonly hash: string;
  readonly scope: string;
  /** The op type of the envelope (`Batch` for a batch). */
  readonly type: string;
  /** [type] for a plain op; the item types for a Batch. */
  readonly itemTypes: readonly string[];
  /** User of the author key of the target. */
  readonly userId: string;
  readonly writes: readonly Readonly<AppliedWrite>[];
}

/**
 * The op item lost a race: the state changed before it in the order.
 * reason: a text for people. code: an optional machine-readable kind that the replay
 * copies to the audit (`AuditEntry.code`, `ItemNote.code`). The core gives it no meaning.
 */
export interface Superseded {
  superseded: string;
  code?: string;
}

/**
 * writes: apply these writes.
 * noEffect: the op is valid but changes nothing (for example the same value again).
 * superseded: the op lost a race. The state changed before it in the order.
 */
export type EffectResult = { writes: Write[] } | { noEffect: string } | Superseded;

export interface OpDef {
  /**
   * Scopes in which this op type is valid. If the domain has `scopeKind`, these are
   * scope kinds, and the replay compares them with `scopeKind(scope)` of the op.
   */
  scopes: readonly string[];
  schema: Schema;
  /** Extra payload checks that need no state. Return an error text, or null. */
  check?(p: Record<string, unknown>): string | null;
  effects(p: Record<string, any>, ctx: EffectCtx): EffectResult;
  /** false = Revert of this op is not permitted. */
  revertible: boolean;
}

export type AuthResult = { ok: true } | { ok: false; reason: string };

/** An op item: a plain op, 1 item of a Batch, or a Revert. */
export interface OpItem {
  type: string;
  payload: Record<string, any>;
}

/** Writes that remove an entity that the target of a Revert created. */
export type RemoveResult =
  | {
      writes: Write[];
      /** Fields that the replay computes at the point of the Revert. They are not compared with the payload. */
      computed: string[];
    }
  | Superseded;

export interface ScopeScan {
  scopes: string[];
  /** Folders that do not exist or are not readable. */
  missing: string[];
  /** Unexpected entries: path and reason. */
  unknown: { path: string; detail: string }[];
}

export interface Domain {
  /** Folder of a scope, relative to the shared root, or null for an invalid scope. */
  scopeDir(scope: string): string | null;
  /** Scope of a folder, or null. Inverse of scopeDir. */
  scopeFromDir(dir: string): string | null;
  /**
   * Optional. The kind of a valid scope, for scopes that the app makes at run time
   * (for example "team" for the scope "team:a1"). If it is given, the replay compares
   * `OpDef.scopes` with `scopeKind(scope)`. If it is not given, the replay compares
   * `OpDef.scopes` with the scope itself. Called only for a scope for which `scopeDir`
   * is not null. An error rejects the op. A kind that is not in `OpDef.scopes` (also a value
   * that is not a string) rejects the op as not valid in the scope.
   */
  scopeKind?(scope: string): string;
  /**
   * Lists the scopes that exist in the storage. Order matters: a full scan replays 1 time
   * after the first scope, so put the scope with the users and admins first. Then the checkpoints of
   * the later scopes are checked against all admins, not only the root admins.
   */
  discoverScopes(storage: Storage): Promise<ScopeScan>;

  catalog: Record<string, OpDef>;

  /**
   * Initial state from the trust root. Entities with `root: true` are protected:
   * the replay rejects every op that writes to them.
   */
  rootState(trustRoot: TrustRoot | null): State;
  /**
   * User ID of a known key at this point of the order, or null for an unknown key.
   * The replay rejects the op of a key for which the result is not a string.
   * An error during the replay rejects the op. An error during the checkpoint check
   * makes the pack untrusted (the engine reads the op files).
   */
  keyOwner(state: State, keyId: string): string | null;
  /**
   * Keys (keyId and public key) that an op item registers. verify.ts checks the binding.
   * Called for ALL op files before any check: the payload is unsigned and not validated.
   * An error ignores the item. At most MAX_BATCH keys of each op count, in the order of the items.
   * A domain must not register more than MAX_BATCH keys in 1 op: the replay result is then
   * undefined (a later key is valid only if another file registers it).
   */
  keysIn(item: OpItem): { keyId: string; publicKey: string }[];
  /**
   * Revocation cutoffs from the applied ops in the state.
   * An error stops the revocation fixpoint with the cutoffs that it has (in the first
   * round: only those of the trust root) and gives an issue of kind `domain`.
   * This fails OPEN: ops of revoked keys can apply. Never throw here.
   */
  revocations(state: State): Map<string, Cutoff>;
  /**
   * True if the op item can change the revocation cutoffs (then a full replay is necessary).
   * The payload is not validated. An error counts as true.
   */
  isRevocation(item: OpItem): boolean;
  /** True if the user is an admin (checkpoints need an admin signature). An error counts as false. */
  isAdmin(state: State, userId: string): boolean;

  /**
   * authorize(op, state at that point) → ok | reason. The only permission gate.
   * Called for each plain op, each Batch item (with the state after the earlier
   * items) and each Revert. The replay checks keys and cutoffs before.
   * For a Revert, `ctx.revertTarget` is the target op (see EffectCtx).
   */
  authorize(item: OpItem, ctx: EffectCtx): AuthResult;

  /** Writes that the replay applies after the effects of each item (derived fields). */
  normalize?(writes: AppliedWrite[], ctx: EffectCtx): Write[];
  /**
   * Checks the state after an item. A text or a Superseded result = the item is superseded
   * and its writes are undone. null = the state is valid.
   */
  checkState?(writes: AppliedWrite[], ctx: EffectCtx): string | Superseded | null;
  /** Writes that remove an entity, for a Revert of the op that created it. */
  removeWrites(e: string, id: string, ctx: EffectCtx): RemoveResult;
  /**
   * True for a field that only `normalize` writes (a pure derived value, for example a count).
   * A Revert does not write such a field. `normalize` computes it again.
   */
  isDerived?(e: string, f: string): boolean;
}
