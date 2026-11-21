// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { AuthError, SupersededError } from '../../src/engine';
import { mergeCutoffs } from '../../src/replay';
import { planRevert } from '../../src/revert';
import { actor, note, rawOp, world } from '../helpers';
import { notesDomain } from '../notes-domain';

const last = (e: { audit: { status: string; reason?: string; notes: unknown[] }[] }) => e.audit[e.audit.length - 1];

describe('plain ops', () => {
  it('applies effects and the derived writes of normalize', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'Žluťoučký' });
    expect(note(user.engine.state, 'n1')).toMatchObject({ text: 'Žluťoučký', author: user.userId, status: 'active', len: 9 });
  });

  it('reports no-effect and superseded ops without changes to the state', async () => {
    const { user } = await world();
    const w = (type: string, p: Record<string, unknown>) => user.engine.write(user.signer, 'data', type, p, { allowSuperseded: true });
    await w('CreateNote', { id: 'n1', text: 'a' });
    await w('EditNote', { id: 'n1', text: 'a' });
    expect(last(user.engine)).toMatchObject({ status: 'no-effect', reason: 'same text' });
    await w('EditNote', { id: 'missing', text: 'b' });
    expect(last(user.engine)).toMatchObject({ status: 'superseded', reason: 'no active note' });
  });

  it('write() refuses a superseded op unless the caller permits it, and refuses a rejected op', async () => {
    const { user } = await world();
    await expect(user.engine.write(user.signer, 'data', 'EditNote', { id: 'missing', text: 'b' })).rejects.toBeInstanceOf(SupersededError);
    await expect(user.engine.write(user.signer, 'roles', 'SetFlag', { name: 'x', value: 1 })).rejects.toBeInstanceOf(AuthError);
    await expect(user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a', extra: 1 })).rejects.toThrow('unknown field');
    expect(user.engine.audit.filter((a) => a.authorKeyId === user.keyId)).toHaveLength(0);
  });

  it('undoes an item that fails the state check (superseded)', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'ok' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'FORBIDDEN' }, { allowSuperseded: true });
    expect(last(user.engine)).toMatchObject({ status: 'superseded', reason: 'forbidden text' });
    expect(note(user.engine.state, 'n1')).toMatchObject({ text: 'ok', len: 2 });
  });

  it('rejects an op that changes a trust-root entity', async () => {
    const { admin } = await world({ admin2: true });
    await expect(admin.engine.write(admin.signer, 'roles', 'RenameUser', { userId: admin.userId, name: 'x' })).rejects.toThrow('trust root');
  });

  it('check() does not change the state, the audit log or the seq', async () => {
    const { user } = await world();
    const before = JSON.stringify(user.engine.state);
    const n = user.engine.audit.length;
    expect(user.engine.check(user.keyId, 'data', 'CreateNote', { id: 'n1', text: 'x' }).status).toBe('applied');
    expect(JSON.stringify(user.engine.state)).toBe(before);
    expect(user.engine.audit).toHaveLength(n);
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    expect(env.seq).toBe(1);
  });
});

describe('Batch', () => {
  it('authorizes each item against the state after the earlier items', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'Batch', {
      ops: [
        { type: 'CreateNote', payload: { id: 'n1', text: 'a' } },
        { type: 'EditNote', payload: { id: 'n1', text: 'b' } },
      ],
    });
    expect(note(user.engine.state, 'n1')).toMatchObject({ text: 'b', len: 1 });
  });

  it('rejects an empty batch: it must not skip authorize (no-effect for a user without rights)', async () => {
    const { user } = await world();
    expect(user.engine.check(user.keyId, 'data', 'Batch', { ops: [] })).toMatchObject({ status: 'rejected', reason: expect.stringContaining('at least 1 item') });
    await expect(user.engine.write(user.signer, 'data', 'Batch', { ops: [] })).rejects.toThrow(AuthError);
  });

  it('rejects the full batch if 1 item is not authorized, and undoes the earlier items', async () => {
    const { admin, user } = await world();
    await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'a1', text: 'admin note' });
    await user.engine.scan();
    await expect(
      user.engine.write(user.signer, 'data', 'Batch', {
        ops: [
          { type: 'CreateNote', payload: { id: 'n1', text: 'a' } },
          { type: 'DeleteNote', payload: { id: 'a1' } },
        ],
      }),
    ).rejects.toThrow('item 1 (DeleteNote): not the author of the note');
    expect(note(user.engine.state, 'n1')).toBeUndefined();
  });

  it('skips superseded items and applies the others', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'Batch', {
      ops: [
        { type: 'CreateNote', payload: { id: 'n1', text: 'a' } },
        { type: 'DeleteNote', payload: { id: 'gone' } },
        { type: 'CreateNote', payload: { id: 'n2', text: 'b' } },
      ],
    });
    const e = last(user.engine);
    expect(e.status).toBe('applied');
    expect(e.notes).toEqual([{ item: 1, type: 'DeleteNote', status: 'superseded', reason: 'no active note' }]);
    expect(note(user.engine.state, 'n2')).toBeDefined();
  });

  it('rejects nested Batch and Revert items', async () => {
    const { admin } = await world();
    await expect(admin.engine.write(admin.signer, 'data', 'Batch', { ops: [{ type: 'Batch', payload: { ops: [] } }] })).rejects.toThrow('nested');
  });
});

describe('Revert', () => {
  async function edited() {
    const w = await world();
    const { admin, user } = w;
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'first' });
    const edit = await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'second version' });
    await admin.engine.scan();
    const meta = { opId: 'plan', scope: 'data', authorKeyId: admin.keyId, userId: admin.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
    return { ...w, edit, meta };
  }

  it('writes the before values and the derived fields', async () => {
    const { admin, edit, meta } = await edited();
    const plan = planRevert(admin.engine.result, edit.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    expect(plan.overwritten).toEqual([]);
    await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
    expect(note(admin.engine.state, 'n1')).toMatchObject({ text: 'first', len: 5 });
  });

  it('rejects a Revert whose inverse is not the before values', async () => {
    const { admin, edit, meta } = await edited();
    const plan = planRevert(admin.engine.result, edit.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    const forged = { ...plan.payload, inverse: plan.payload.inverse.map((w) => ({ ...w, v: 'any value' })) };
    await expect(admin.engine.write(admin.signer, 'data', 'Revert', forged)).rejects.toThrow('inverse does not match');
  });

  it('removes a created entity with computed fields that are not in the payload', async () => {
    const { admin, user, meta } = await edited();
    const create = user.engine.audit.find((a) => a.type === 'CreateNote')!;
    const plan = planRevert(admin.engine.result, create.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    expect(plan.payload.inverse).toEqual([{ e: 'note', id: 'n1', f: 'status', v: 'deleted' }]);
    expect(plan.overwritten.map((o) => o.f)).toEqual(['text', 'len']);
    await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
    expect(note(admin.engine.state, 'n1')).toMatchObject({ status: 'deleted', deletedBy: admin.userId });
  });

  it('is superseded when the domain refuses the removal (entity already deleted)', async () => {
    const { admin, user, meta } = await edited();
    const create = user.engine.audit.find((a) => a.type === 'CreateNote')!;
    const plan = planRevert(admin.engine.result, create.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    await user.engine.write(user.signer, 'data', 'DeleteNote', { id: 'n1' });
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload, { allowSuperseded: true });
    expect(last(admin.engine)).toMatchObject({ status: 'superseded', reason: 'note is already deleted' });
  });

  it('can revert a Revert', async () => {
    const { admin, edit, meta } = await edited();
    const plan = planRevert(admin.engine.result, edit.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    const rev = await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
    const plan2 = planRevert(admin.engine.result, rev.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan2) throw new Error(plan2.error);
    await admin.engine.write(admin.signer, 'data', 'Revert', plan2.payload);
    expect(note(admin.engine.state, 'n1')).toMatchObject({ text: 'second version', len: 14 });
  });

  it('rejects a Revert of a non-revertible op, by a non-admin, or in another scope', async () => {
    const { admin, user, edit, meta } = await edited();
    const grant = admin.engine.audit.find((a) => a.type === 'GrantUser')!;
    expect(planRevert(admin.engine.result, grant.opId, notesDomain, { ...meta, scope: 'roles' }, admin.engine.validKeyBindings)).toEqual({ error: 'GrantUser cannot be reverted' });
    const plan = planRevert(admin.engine.result, edit.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    await expect(user.engine.write(user.signer, 'data', 'Revert', plan.payload)).rejects.toThrow('only admins can revert');
    await expect(admin.engine.write(admin.signer, 'roles', 'Revert', plan.payload)).rejects.toThrow('scope of its target');
  });
});

describe('revocation', () => {
  it('applies a cutoff to all ops of the key, also to ops that sort before the revocation', async () => {
    const { storage, admin, user } = await world();
    const t = Date.parse('2026-06-01T00:00:00Z');
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'valid' }, { t, c: 0 });
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n2', text: 'after cutoff' }, { t: t + 1, c: 0 });
    // The revocation sorts after both ops (later HLC). The cutoff still removes seq 2.
    await rawOp(storage, admin, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 1 } }, { t: t + 10, c: 0 });
    await admin.engine.scan();
    expect(note(admin.engine.state, 'n1')).toBeDefined();
    expect(note(admin.engine.state, 'n2')).toBeUndefined();
    expect(admin.engine.issues.some((i) => i.kind === 'revoked' && i.seq === 2)).toBe(true);
  });

  it('uses the lowest cutoff of each scope, and 0 for a scope that a cutoff does not list', () => {
    const a = new Map([['k1', { data: 5, roles: 2 }]]);
    const b = new Map([['k1', { data: 3 }], ['k2', { data: 1 }]]);
    expect(Object.fromEntries(mergeCutoffs(a, b))).toEqual({ k1: { data: 3, roles: 0 }, k2: { data: 1 } });
  });

  it('reports an integrity issue when 2 non-root admins revoke each other', async () => {
    const { storage, admin2 } = await world({ admin2: true });
    const admin3 = await actor('admin3', storage);
    const t = Date.parse('2026-06-01T00:00:00Z');
    // admin2 grants admin3, then both revoke each other at seq 0 (all ops invalid).
    await rawOp(storage, admin2!, 'roles', 'GrantUser', { userId: admin3.userId, keyId: admin3.keyId, publicKey: admin3.publicKey, admin: true }, { t, c: 0 });
    await rawOp(storage, admin3, 'roles', 'RevokeKey', { keyId: admin2!.keyId, cutoff: {} }, { t: t + 1, c: 0 });
    await rawOp(storage, admin2!, 'roles', 'RevokeKey', { keyId: admin3.keyId, cutoff: {} }, { t: t + 2, c: 0 });
    await admin3.engine.scan();
    expect(admin3.engine.issues.some((i) => i.detail.includes('did not become stable'))).toBe(true);
  });
});

describe('order and clocks', () => {
  it('rejects an op of an author whose HLC does not increase along the chain', async () => {
    const { storage, admin, user } = await world();
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t: 5000, c: 0 }, '2026-01-01T08:00:00.000Z');
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n2', text: 'b' }, { t: 5000, c: 0 }, '2026-01-01T08:00:00.000Z');
    await admin.engine.scan();
    expect(admin.engine.issues.some((i) => i.kind === 'chain-broken' && i.seq === 2 && i.detail.includes('HLC'))).toBe(true);
    expect(note(admin.engine.state, 'n2')).toBeUndefined();
  });

  it('flags an HLC far after its own wall time, but not honest ops that copy that HLC', async () => {
    const { storage, admin, user } = await world();
    const wall = Date.parse('2026-01-01T09:00:00Z');
    const future = wall + 30 * 24 * 3600_000;
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t: future, c: 0 }, new Date(wall).toISOString());
    await admin.engine.scan();
    // The admin engine now copies the future HLC. Its own next op has an honest wall time.
    await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    const flagged = admin.engine.issues.filter((i) => i.kind === 'future-clock');
    expect(flagged.map((i) => i.authorKeyId)).toEqual([user.keyId]);
  });

  it('rejects a second op with the same opId', async () => {
    const { storage, admin, user } = await world();
    const t = Date.parse('2026-02-01T00:00:00Z');
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'a' }, { t, c: 0 }, undefined, 'same-op-id');
    await rawOp(storage, admin, 'data', 'CreateNote', { id: 'n2', text: 'b' }, { t: t + 1, c: 0 }, undefined, 'same-op-id');
    await admin.engine.scan();
    expect(note(admin.engine.state, 'n1')).toBeDefined();
    expect(note(admin.engine.state, 'n2')).toBeUndefined();
    expect(admin.engine.issues.some((i) => i.detail.includes('duplicate opId'))).toBe(true);
  });
});
