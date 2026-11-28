// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Generic types of the op log. The domain (app) defines the entity types and fields.
import type { Hlc } from './hlc';

export const FORMAT_VERSION = 1;

/** The signed op envelope. */
export interface Envelope {
  v: 1;
  opId: string;
  scope: string;
  authorKeyId: string;
  seq: number;
  prevHash: string | null;
  hlc: Hlc;
  wallTime: string;
  type: string;
  payload: Record<string, unknown>;
  enc?: unknown;
  sig: string;
}

export type UnsignedEnvelope = Omit<Envelope, 'sig'>;

/** An op that passed parsing, the path check, the signature check and the chain check. */
export interface VerifiedOp {
  env: Envelope;
  hash: string;
}

export interface Entity {
  id: string;
  [field: string]: unknown;
}

export type EntityTable = Record<string, Entity>;
/** Entity type → ID → entity. */
export type ScopeState = Record<string, EntityTable>;

export interface State {
  scopes: Record<string, ScopeState>;
}

/** 1 field change of 1 entity, in the scope of the op. */
export interface Write {
  e: string;
  id: string;
  f: string;
  v: unknown;
}

/** A write as applied, with the value before. `existed` = the entity existed before this write. */
export interface AppliedWrite extends Write {
  before: unknown;
  existed: boolean;
}

/** Last valid seq for each scope. A scope that is not in the object has the cutoff 0. */
export type Cutoff = Record<string, number>;

export interface RootKey {
  userId: string;
  displayName: string;
  keyId: string;
  alg: 'Ed25519';
  publicKey: string;
  /** Last valid seq per scope. null = no cutoff. */
  cutoffs: Cutoff | null;
}

export interface TrustRoot {
  v: 1;
  roots: RootKey[];
}

export type IssueKind =
  | 'unknown-file' // file name does not match the pattern (for example a OneDrive conflict copy)
  | 'parse-error'
  | 'misplaced' // the envelope does not match its path
  | 'bad-signature'
  | 'unknown-key' // the signing key is not registered (yet)
  | 'chain-gap' // a seq is missing (waiting for sync, or deleted)
  | 'chain-broken' // prevHash does not match, the HLC does not increase, or an earlier op of the chain is bad
  | 'fork' // 2 different ops with the same author, scope and seq
  | 'revoked' // seq is above the revocation cutoff
  | 'unauthorized'
  | 'invalid-payload'
  | 'future-clock'
  | 'bad-checkpoint'
  | 'trust-root' // the trust root is not readable or not valid (the engine uses the last good copy), or it changed
  | 'domain'; // an issue that the domain reports

export interface Issue {
  kind: IssueKind;
  detail: string;
  path?: string;
  opId?: string;
  scope?: string;
  authorKeyId?: string;
  seq?: number;
}

/**
 * applied: the op changed the state.
 * no-effect: valid, but it changed nothing (for example the same value again).
 * superseded: valid and authorized, but the state changed before it in the order (a lost race).
 * rejected: a check failed. The op is an integrity issue.
 */
export type AuditStatus = 'applied' | 'no-effect' | 'superseded' | 'rejected';

/** A note about 1 item of an op. `item` is the index in a Batch, or 0 for a plain op. */
export interface ItemNote {
  item: number;
  type: string;
  status: 'no-effect' | 'superseded';
  reason: string;
  /** For a superseded item: the code of the Superseded result of the domain, if it gave one. */
  code?: string;
}

export interface AuditEntry {
  opId: string;
  hash: string;
  scope: string;
  type: string;
  authorKeyId: string;
  userId: string | null;
  seq: number;
  hlc: Hlc;
  wallTime: string;
  status: AuditStatus;
  reason?: string;
  /**
   * For a superseded op that is not a Batch (a plain op or a Revert): the code of the
   * Superseded result of the domain, if it gave one. For a Batch, see `ItemNote.code`.
   */
  code?: string;
  writes: AppliedWrite[];
  notes: ItemNote[];
  /** For Batch: the item types. For Revert: ['Revert']. */
  itemTypes?: string[];
  /** For Revert: the op ID of the target. An op ID is unique only for 1 author key. Use `revertOfHash` to find the target. */
  revertOf?: string;
  /** For Revert: the hash of the target op. It identifies the target. */
  revertOfHash?: string;
  payload: Record<string, unknown>;
}
