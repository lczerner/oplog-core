// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// A small test domain: users, keys, admins and notes. Synthetic only.
//
// Scopes: "roles" (folder roles/) and "data" (folder data/).
// Rules:
// - Only admins write in roles. Any active user writes notes.
// - Only the author of a note or an admin can edit or delete it.
// - A note with the text "LOCKED" cannot be edited (superseded): a status-like guard.
// - normalize: the field "len" of a note is the length of its text (a derived field).
// - checkState: a note must not have the text "FORBIDDEN" (superseded).
// - Like / Unlike: a like entity "<noteId>/<userId>" with on = true/false. The note field
//   "likeCount" is derived (isDerived): normalize counts it from the changes of "on".

import type { Domain, EffectCtx, OpDef, OpItem } from '../src/domain';
import { BATCH, REVERT } from '../src/domain';
import type { AppliedWrite, Cutoff, State, TrustRoot, Write } from '../src/types';

const ADMIN_ONLY = new Set(['GrantUser', 'RevokeKey', 'SetFlag', 'RenameUser']);

const ok = (writes: Write[]) => ({ writes });

export const catalog: Record<string, OpDef> = {
  GrantUser: {
    scopes: ['roles'],
    schema: { userId: 'id', keyId: 'id', publicKey: 'str', admin: 'bool' },
    effects: (p, ctx) => {
      if (ctx.get('user', p.userId) || ctx.get('key', p.keyId)) return { superseded: 'exists already' };
      if (!ctx.isValidKeyBinding(p.keyId, p.publicKey)) return { noEffect: 'key does not match the public key' };
      return ok([
        { e: 'user', id: p.userId, f: 'admin', v: p.admin },
        { e: 'user', id: p.userId, f: 'status', v: 'active' },
        { e: 'key', id: p.keyId, f: 'userId', v: p.userId },
        { e: 'key', id: p.keyId, f: 'publicKey', v: p.publicKey },
      ]);
    },
    revertible: false,
  },
  RevokeKey: {
    scopes: ['roles'],
    schema: { keyId: 'id', cutoff: { map: 'int', max: 10 } },
    effects: (p, ctx) => (ctx.get('key', p.keyId) ? ok([{ e: 'key', id: p.keyId, f: 'cutoff', v: p.cutoff }]) : { superseded: 'unknown key' }),
    revertible: false,
  },
  SetFlag: {
    scopes: ['roles'],
    schema: { name: 'id', value: 'int' },
    effects: (p) => ok([{ e: 'flag', id: p.name, f: 'value', v: p.value }]),
    revertible: true,
  },
  RenameUser: {
    scopes: ['roles'],
    schema: { userId: 'id', name: { text: 50 } },
    effects: (p, ctx) => (ctx.get('user', p.userId) ? ok([{ e: 'user', id: p.userId, f: 'name', v: p.name }]) : { superseded: 'unknown user' }),
    revertible: true,
  },
  Like: {
    scopes: ['data'],
    schema: { noteId: 'id' },
    effects: (p, ctx) => {
      const id = `${p.noteId}/${ctx.op.userId}`;
      if (!ctx.get('note', p.noteId)) return { superseded: 'no note' };
      return ctx.get('like', id)?.on === true ? { noEffect: 'liked already' } : ok([{ e: 'like', id, f: 'noteId', v: p.noteId }, { e: 'like', id, f: 'on', v: true }]);
    },
    revertible: true,
  },
  Unlike: {
    scopes: ['data'],
    schema: { noteId: 'id' },
    effects: (p, ctx) => {
      const id = `${p.noteId}/${ctx.op.userId}`;
      return ctx.get('like', id)?.on === true ? ok([{ e: 'like', id, f: 'on', v: false }]) : { noEffect: 'not liked' };
    },
    revertible: true,
  },
  CreateNote: {
    scopes: ['data'],
    schema: { id: 'id', text: { text: 100 } },
    effects: (p, ctx) =>
      ctx.get('note', p.id)
        ? { superseded: 'exists already' }
        : ok([
            { e: 'note', id: p.id, f: 'text', v: p.text },
            { e: 'note', id: p.id, f: 'author', v: ctx.op.userId },
            { e: 'note', id: p.id, f: 'status', v: 'active' },
          ]),
    revertible: true,
  },
  EditNote: {
    scopes: ['data'],
    schema: { id: 'id', text: { text: 100 } },
    effects: (p, ctx) => {
      const n = ctx.get('note', p.id);
      if (!n || n.status !== 'active') return { superseded: 'no active note' };
      if (n.text === 'LOCKED') return { superseded: 'note is locked' };
      if (n.text === p.text) return { noEffect: 'same text' };
      return ok([{ e: 'note', id: p.id, f: 'text', v: p.text }]);
    },
    revertible: true,
  },
  DeleteNote: {
    scopes: ['data'],
    schema: { id: 'id' },
    effects: (p, ctx) => {
      const n = ctx.get('note', p.id);
      return n?.status === 'active' ? ok([{ e: 'note', id: p.id, f: 'status', v: 'deleted' }]) : { superseded: 'no active note' };
    },
    revertible: true,
  },
};

const userOf = (state: State, keyId: string): string | null => {
  const k = state.scopes.roles?.key?.[keyId];
  return k ? (k.userId as string) : null;
};

export const notesDomain: Domain = {
  scopeDir: (s) => (s === 'roles' || s === 'data' ? s : null),
  scopeFromDir: (d) => (d === 'roles' || d === 'data' ? d : null),
  async discoverScopes(storage) {
    const missing: string[] = [];
    for (const d of ['roles', 'data']) if ((await storage.list(d)) === null) missing.push(d);
    return { scopes: ['roles', 'data'], missing, unknown: [] };
  },
  catalog,
  rootState(tr: TrustRoot | null): State {
    const state: State = { scopes: { roles: { user: {}, key: {} }, data: {} } };
    for (const r of tr?.roots ?? []) {
      state.scopes.roles.user[r.userId] = { id: r.userId, admin: true, status: 'active', root: true };
      state.scopes.roles.key[r.keyId] = { id: r.keyId, userId: r.userId, publicKey: r.publicKey, root: true };
    }
    return state;
  },
  keyOwner: userOf,
  keysIn: (it: OpItem) => (it.type === 'GrantUser' && typeof it.payload.keyId === 'string' ? [{ keyId: it.payload.keyId, publicKey: String(it.payload.publicKey) }] : []),
  revocations(state) {
    const m = new Map<string, Cutoff>();
    for (const k of Object.values(state.scopes.roles?.key ?? {})) if (k.cutoff) m.set(k.id, k.cutoff as Cutoff);
    return m;
  },
  isRevocation: (it) => it.type === 'RevokeKey',
  isAdmin: (state, userId) => state.scopes.roles?.user?.[userId]?.admin === true,
  authorize(it: OpItem, ctx: EffectCtx) {
    const admin = ctx.state.scopes.roles?.user?.[ctx.op.userId]?.admin === true;
    if (it.type === REVERT) return admin ? { ok: true } : { ok: false, reason: 'only admins can revert' };
    if (it.type === BATCH) return { ok: false, reason: 'internal: Batch is not an item' };
    if (ADMIN_ONLY.has(it.type)) return admin ? { ok: true } : { ok: false, reason: `only admins can issue ${it.type}` };
    if (it.type === 'EditNote' || it.type === 'DeleteNote') {
      const n = ctx.get('note', it.payload.id);
      if (n && n.author !== ctx.op.userId && !admin) return { ok: false, reason: 'not the author of the note' };
    }
    return { ok: true };
  },
  normalize(writes: AppliedWrite[], ctx: EffectCtx): Write[] {
    const out: Write[] = [];
    const delta = new Map<string, number>();
    for (const w of writes)
      if (w.e === 'like' && w.f === 'on') {
        const noteId = ctx.get('like', w.id)!.noteId as string;
        delta.set(noteId, (delta.get(noteId) ?? 0) + (w.v === true ? 1 : 0) - (w.before === true ? 1 : 0));
      }
    for (const [noteId, d] of delta) if (d) out.push({ e: 'note', id: noteId, f: 'likeCount', v: Number(ctx.get('note', noteId)?.likeCount ?? 0) + d });
    for (const w of writes)
      if (w.e === 'note' && w.f === 'text') {
        const len = String(w.v).length;
        if (ctx.get('note', w.id)?.len !== len) out.push({ e: 'note', id: w.id, f: 'len', v: len });
      }
    return out;
  },
  checkState(writes, ctx) {
    for (const w of writes) if (w.e === 'note' && ctx.get('note', w.id)?.text === 'FORBIDDEN') return 'forbidden text';
    return null;
  },
  isDerived: (e, f) => e === 'note' && f === 'likeCount',
  removeWrites(e, id, ctx) {
    if (e === 'like') return { writes: [{ e, id, f: 'on', v: false }], computed: [] };
    if (e !== 'note') return { writes: [], computed: [] };
    if (ctx.get('note', id)?.status === 'deleted') return { superseded: 'note is already deleted' };
    return {
      writes: [
        { e: 'note', id, f: 'status', v: 'deleted' },
        { e: 'note', id, f: 'deletedBy', v: ctx.op.userId },
      ],
      computed: ['deletedBy'],
    };
  },
};
