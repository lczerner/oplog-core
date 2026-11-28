// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Hardening of the replay: opId unique per author key, Revert target by hash,
// maxT only from ops that the replay did not reject, own-property state tables.
import type { Domain, OpMeta } from '../../src/domain';
import { NO_KEY_BINDINGS, Replayer } from '../../src/replay';
import { planRevert } from '../../src/revert';
import type { AuditEntry, Envelope, TrustRoot } from '../../src/types';
import { actor, note, rawOp, world } from '../helpers';
import { catalog, notesDomain } from '../notes-domain';

const T = Date.parse('2026-06-01T00:00:00Z');
/** A string type, so that TypeScript does not read it as the member `Object.prototype.constructor`. */
const CTOR: string = 'constructor';

/** The audit entry of an op (it has the opId and the hash): the target of planRevert. */
const entryOf = (e: { audit: AuditEntry[] }, env: { opId: string; authorKeyId: string }): AuditEntry => e.audit.find((a) => a.opId === env.opId && a.authorKeyId === env.authorKeyId)!;

const revertMeta = (a: { keyId: string; userId: string }, scope = 'data'): OpMeta => ({ opId: 'plan', scope, authorKeyId: a.keyId, userId: a.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 });

describe('opId is unique per author key', () => {
  it('a user cannot cancel the RevokeKey of the own key with a copied opId and an earlier HLC', async () => {
    const { storage, admin, user } = await world();
    const revoke = await rawOp(storage, admin, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 1 } }, { t: T + 10, c: 0 }, undefined, 'revoke-user');
    // The attack: an op in the data scope with the opId of the RevokeKey. It sorts before the RevokeKey.
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'copy' }, { t: T, c: 0 }, undefined, revoke.opId);
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n2', text: 'after cutoff' }, { t: T + 20, c: 0 });
    await admin.engine.scan();
    expect(entryOf(admin.engine, revoke).status).toBe('applied');
    expect(admin.engine.state.scopes.roles.key[user.keyId].cutoff).toEqual({ data: 1 });
    expect(note(admin.engine.state, 'n1')).toBeDefined();
    expect(note(admin.engine.state, 'n2')).toBeUndefined();
    expect(admin.engine.issues.some((i) => i.detail.includes('duplicate opId'))).toBe(false);
    expect(admin.engine.issues.some((i) => i.kind === 'revoked' && i.authorKeyId === user.keyId && i.seq === 2)).toBe(true);
  });

  it('an outsider key (that nobody granted) cannot cancel an op with a copied opId', async () => {
    const { storage, admin, user } = await world();
    const outsider = await actor('outsider', storage);
    const victim = await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'victim' }, { t: T + 10, c: 0 }, undefined, 'victim-op');
    // A self-signed GrantUser makes the key binding of the outsider known, so its ops get into the replay.
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: T, c: 0 });
    const copy = await rawOp(storage, outsider, 'data', 'CreateNote', { id: 'evil', text: 'x' }, { t: T + 1, c: 0 }, undefined, victim.opId);
    await admin.engine.scan();
    expect(entryOf(admin.engine, copy)).toMatchObject({ status: 'rejected', reason: 'unknown key' });
    expect(entryOf(admin.engine, victim).status).toBe('applied');
    expect(note(admin.engine.state, 'n1')).toMatchObject({ text: 'victim' });
    expect(note(admin.engine.state, 'evil')).toBeUndefined();
    expect(admin.engine.issues.some((i) => i.detail.includes('duplicate opId'))).toBe(false);
  });

  it('2 authors with the same opId: both ops apply, and a Revert finds each one by its hash', async () => {
    const { storage, admin, user } = await world();
    const a = await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'user' }, { t: T, c: 0 }, undefined, 'shared-id');
    const b = await rawOp(storage, admin, 'data', 'CreateNote', { id: 'n2', text: 'admin' }, { t: T + 1, c: 0 }, undefined, 'shared-id');
    await admin.engine.scan();
    const ea = entryOf(admin.engine, a);
    const eb = entryOf(admin.engine, b);
    expect([ea.status, eb.status]).toEqual(['applied', 'applied']);
    expect(ea.hash).not.toBe(eb.hash);
    expect([admin.engine.result.applied.get(ea.hash)?.userId, admin.engine.result.applied.get(eb.hash)?.userId]).toEqual([user.userId, admin.userId]);

    // A wrong opId/hash pair: the replay and planRevert reject it.
    const wrong = { opId: 'other-id', hash: ea.hash };
    expect(planRevert(admin.engine.result, wrong, notesDomain, revertMeta(admin), admin.engine.validKeyBindings)).toEqual({ error: 'op was not applied, so it cannot be reverted' });
    const good = planRevert(admin.engine.result, ea, notesDomain, revertMeta(admin), admin.engine.validKeyBindings);
    if ('error' in good) throw new Error(good.error);
    expect(admin.engine.check(admin.keyId, 'data', 'Revert', { ...good.payload, target: wrong })).toMatchObject({ status: 'rejected', reason: 'revert target is not an applied op before this op' });

    for (const t of [ea, eb]) {
      const plan = planRevert(admin.engine.result, t, notesDomain, revertMeta(admin), admin.engine.validKeyBindings);
      if ('error' in plan) throw new Error(plan.error);
      expect(plan.payload.target).toEqual({ opId: 'shared-id', hash: t.hash });
      await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
    }
    expect([note(admin.engine.state, 'n1').status, note(admin.engine.state, 'n2').status]).toEqual(['deleted', 'deleted']);
    // The audit of each Revert names its target by the opId and the hash.
    const reverts = admin.engine.audit.filter((a) => a.type === 'Revert' && a.status === 'applied');
    expect(reverts.map((a) => [a.revertOf, a.revertOfHash])).toEqual([ea, eb].map((t) => ['shared-id', t.hash]));
  });

  it('the same author reuses an opId: the later op is rejected as a duplicate', async () => {
    const { storage, admin, user } = await world();
    const first = await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t: T, c: 0 }, undefined, 'same-op-id');
    const second = await rawOp(storage, user, 'data', 'CreateNote', { id: 'n2', text: 'b' }, { t: T + 1, c: 0 }, undefined, 'same-op-id');
    await admin.engine.scan();
    expect(entryOf(admin.engine, first).status).toBe('applied');
    expect(admin.engine.audit.find((a) => a.authorKeyId === user.keyId && a.seq === second.seq)).toMatchObject({ status: 'rejected', reason: 'duplicate opId' });
    expect(note(admin.engine.state, 'n1')).toBeDefined();
    expect(note(admin.engine.state, 'n2')).toBeUndefined();
  });
});

describe('future-clock check', () => {
  it('an op of an unknown key with a far-future HLC does not move maxT', async () => {
    const { storage, admin, user } = await world();
    const wall = Date.parse('2026-01-01T09:00:00Z');
    const future = wall + 30 * 24 * 3600_000;
    const outsider = await actor('outsider', storage);
    // The op of the outsider is rejected (unknown key). It must not hide the future clock of the next op.
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: future, c: 0 }, new Date(wall).toISOString());
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t: future, c: 1 }, new Date(wall).toISOString());
    await admin.engine.scan();
    expect(admin.engine.audit.find((a) => a.authorKeyId === outsider.keyId)).toMatchObject({ status: 'rejected', reason: 'unknown key' });
    const flagged = admin.engine.issues.filter((i) => i.kind === 'future-clock' && i.detail.includes('after the wall time of the op'));
    expect(flagged.map((i) => i.authorKeyId).sort()).toEqual([outsider.keyId, user.keyId].sort());
  });

  it('an op of a granted user that the replay rejects for another reason does not move maxT', async () => {
    const { storage, admin, user } = await world();
    const wall = Date.parse('2026-01-01T09:00:00Z');
    const future = wall + 30 * 24 * 3600_000;
    // invalid-payload (unknown op type), unauthorized (a user writes an admin op) and a bad payload: none of them moves maxT.
    await rawOp(storage, user, 'data', 'NoSuchOp', {}, { t: future, c: 0 }, new Date(wall).toISOString());
    await rawOp(storage, user, 'roles', 'SetFlag', { name: 'x', value: 1 }, { t: future, c: 1 }, new Date(wall).toISOString());
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n0' }, { t: future, c: 2 }, new Date(wall).toISOString());
    await rawOp(storage, admin, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t: future, c: 3 }, new Date(wall).toISOString());
    await admin.engine.scan();
    const reasons = admin.engine.audit.filter((a) => a.authorKeyId === user.keyId).map((a) => a.status);
    expect(reasons).toEqual(['rejected', 'rejected', 'rejected']);
    const flagged = admin.engine.issues.filter((i) => i.kind === 'future-clock' && i.detail.includes('after the wall time of the op'));
    // No rejected op moved maxT: each op is reported, also the op of the admin (the last op).
    expect(flagged.map((i) => i.authorKeyId)).toEqual([user.keyId, user.keyId, user.keyId, admin.keyId]);
  });

  it('an op that only a revocation cutoff rejects still moves maxT: honest ops that copied its HLC are not flagged', async () => {
    const { storage, admin, user } = await world();
    const wall = new Date(Date.parse('2026-01-01T09:00:00Z')).toISOString();
    const future = Date.parse(wall) + 30 * 24 * 3600_000;
    // The key of the user is compromised: it writes an op with a far-future HLC. Honest clients applied it and copied the HLC.
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'bad' }, { t: future, c: 0 }, wall);
    await rawOp(storage, admin, 'data', 'CreateNote', { id: 'n2', text: 'honest' }, { t: future, c: 1 }, wall);
    // Later the admin revokes all ops of the key. The cutoff rejects the op of the user.
    await rawOp(storage, admin, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 0 } }, { t: future, c: 2 }, wall);
    await admin.engine.scan();
    expect(admin.engine.audit.find((a) => a.authorKeyId === user.keyId && a.scope === 'data')).toMatchObject({ status: 'rejected', reason: expect.stringContaining('key revoked') });
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    const flagged = admin.engine.issues.filter((i) => i.kind === 'future-clock' && i.detail.includes('after the wall time of the op'));
    expect(flagged.map((i) => i.authorKeyId)).toEqual([user.keyId]);
  });
});

describe('a probe has no side effects on opIds and maxT', () => {
  const trustRoot: TrustRoot = { v: 1, roots: [{ userId: 'u-admin', displayName: 'admin', keyId: 'kadmin', alg: 'Ed25519', publicKey: 'pk', cutoffs: null }] };
  const wall = '2026-01-01T09:00:00.000Z';
  const future = Date.parse(wall) + 30 * 24 * 3600_000;
  const env = (opId: string, seq: number, t: number, c: number, id: string): Envelope => ({ v: 1, opId, scope: 'data', authorKeyId: 'kadmin', seq, prevHash: null, hlc: { t, c }, wallTime: wall, type: 'CreateNote', payload: { id, text: 'x' }, sig: '' });
  const replayer = () => new Replayer({ domain: notesDomain, trustRoot, validKeyBindings: NO_KEY_BINDINGS }, new Map());

  it('a probe with a far-future HLC does not hide the future clock of a later op', () => {
    const r = replayer();
    expect(r.probe(env('probe', 1, future, 0, 'n0')).status).toBe('applied');
    expect(r.apply({ env: env('op-1', 1, future, 1, 'n1'), hash: 'h1' }).status).toBe('applied');
    expect(r.issues.filter((i) => i.kind === 'future-clock').map((i) => i.opId)).toEqual(['op-1']);
  });

  it('a probe with an opId does not block a later own op with the same opId', () => {
    const r = replayer();
    const t = Date.parse(wall);
    expect(r.probe(env('same-id', 1, t, 0, 'n0')).status).toBe('applied');
    expect(r.apply({ env: env('same-id', 1, t, 1, 'n1'), hash: 'h1' }).status).toBe('applied');
    expect(r.issues).toEqual([]);
  });
});

describe('own-property state tables', () => {
  // The notes domain with a scope "constructor" and an op that writes any entity type.
  const domain: Domain = {
    ...notesDomain,
    scopeDir: (s) => (s === 'constructor' ? 'ctor' : notesDomain.scopeDir(s)),
    scopeFromDir: (d) => (d === 'ctor' ? 'constructor' : notesDomain.scopeFromDir(d)),
    catalog: {
      ...catalog,
      CreateNote: { ...catalog.CreateNote, scopes: ['data', 'constructor'] },
      Put: { scopes: ['data', 'constructor'], schema: { e: 'id', id: 'id', f: 'id', v: 'int' }, effects: (p) => ({ writes: [{ e: p.e, id: p.id, f: p.f, v: p.v }] }), revertible: true },
    },
  };
  const trustRoot: TrustRoot = { v: 1, roots: [{ userId: 'u-admin', displayName: 'admin', keyId: 'kadmin', alg: 'Ed25519', publicKey: 'pk', cutoffs: null }] };
  let seq = 0;
  const op = (scope: string, type: string, payload: Record<string, unknown>) => {
    seq++;
    const env: Envelope = { v: 1, opId: `op-${seq}`, scope, authorKeyId: 'kadmin', seq, prevHash: null, hlc: { t: T + seq, c: 0 }, wallTime: new Date(T + seq).toISOString(), type, payload, sig: '' };
    return { env, hash: `h${seq}` };
  };

  it('a scope "constructor" and an entity type "toString" get own tables; Object gets no new property', () => {
    const objectKeys = Object.getOwnPropertyNames(Object).sort();
    const toStringKeys = Object.getOwnPropertyNames(Object.prototype.toString).sort();
    const r = new Replayer({ domain, trustRoot, validKeyBindings: NO_KEY_BINDINGS }, new Map());
    const create = r.apply(op('constructor', 'CreateNote', { id: 'n1', text: 'x' }));
    const put = r.apply(op('data', 'Put', { e: 'toString', id: 'a', f: 'v', v: 1 }));
    expect([create.status, put.status]).toEqual(['applied', 'applied']);
    const own = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);
    expect(own(r.state.scopes, 'constructor')).toBe(true);
    expect(own(r.state.scopes[CTOR], 'note')).toBe(true);
    expect(r.state.scopes[CTOR].note.n1).toMatchObject({ text: 'x', author: 'u-admin', status: 'active' });
    expect(own(r.state.scopes.data, 'toString')).toBe(true);
    expect(r.state.scopes.data.toString).toEqual({ a: { id: 'a', v: 1 } });
    expect(Object.getOwnPropertyNames(Object).sort()).toEqual(objectKeys);
    expect(Object.getOwnPropertyNames(Object.prototype.toString).sort()).toEqual(toStringKeys);

    // planRevert reads the same own tables.
    const plan = planRevert(r.result(), create, domain, revertMeta({ keyId: 'kadmin', userId: 'u-admin' }, 'constructor'), NO_KEY_BINDINGS);
    if ('error' in plan) throw new Error(plan.error);
    expect(plan.overwritten).toEqual([]);
    const rev = r.apply(op('constructor', 'Revert', plan.payload));
    expect(rev.status).toBe('applied');
    expect(r.state.scopes[CTOR].note.n1.status).toBe('deleted');
  });

  it('rejects the op of a key for which keyOwner does not return a string (a prototype member, for example)', () => {
    const odd: Domain = { ...domain, keyOwner: (state, keyId) => (keyId === 'kodd' ? (Object as unknown as string) : notesDomain.keyOwner(state, keyId)) };
    const r = new Replayer({ domain: odd, trustRoot, validKeyBindings: NO_KEY_BINDINGS }, new Map());
    const o = op('data', 'CreateNote', { id: 'n1', text: 'x' });
    expect(r.apply({ ...o, env: { ...o.env, authorKeyId: 'kodd' } })).toMatchObject({ status: 'rejected', reason: 'unknown key', userId: null });
    expect(r.apply(op('data', 'CreateNote', { id: 'n2', text: 'y' })).status).toBe('applied');
  });

  it('undo removes an own table that a rejected op made, and Object stays unchanged', () => {
    const objectKeys = Object.getOwnPropertyNames(Object).sort();
    const bad: Domain = { ...domain, checkState: () => { throw new Error('boom'); } };
    const r = new Replayer({ domain: bad, trustRoot, validKeyBindings: NO_KEY_BINDINGS }, new Map());
    expect(r.apply(op('constructor', 'CreateNote', { id: 'n1', text: 'x' })).status).toBe('rejected');
    expect(Object.prototype.hasOwnProperty.call(r.state.scopes, 'constructor')).toBe(false);
    expect(Object.getOwnPropertyNames(Object).sort()).toEqual(objectKeys);
  });
});
