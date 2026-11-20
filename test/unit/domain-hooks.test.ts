// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Optional Domain hooks: scopeKind, EffectCtx.revertTarget and the code of a superseded result.
import type { Domain, EffectCtx, OpItem, RevertTarget } from '../../src/domain';
import { Engine, SupersededError } from '../../src/engine';
import { MemoryStorage } from '../../src/storage/memory';
import type { AuditEntry } from '../../src/types';
import { canonicalize } from '../../src/canonical';
import { planRevert } from '../../src/revert';
import { signEnvelope } from '../../src/verify';
import { fakeClock, makeKey, note, world, writeTrustRoot } from '../helpers';
import { notesDomain, teamNotesDomain } from '../notes-domain';

const last = (e: Engine): AuditEntry => e.audit[e.audit.length - 1];

/** A root admin and a granted user, with engines of the given domain. */
async function domainWorld(domain: Domain) {
  const storage = new MemoryStorage();
  const clock = fakeClock();
  const a = await makeKey('admin');
  const u = await makeKey('user');
  const admin = { ...a, engine: new Engine(storage, domain, { now: clock.now }) };
  const user = { ...u, engine: new Engine(storage, domain, { now: clock.now }) };
  await writeTrustRoot(storage, [{ ...a, name: 'admin' }]);
  await admin.engine.scan();
  await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: user.userId, keyId: user.keyId, publicKey: user.publicKey, admin: false });
  await user.engine.scan();
  return { storage, clock, admin, user };
}

describe('Domain.scopeKind (scopes made at run time)', () => {
  it('compares OpDef.scopes with the kind of the scope', async () => {
    const { storage, clock, user } = await domainWorld(teamNotesDomain);
    await user.engine.write(user.signer, 'team:a1', 'CreateNote', { id: 'n1', text: 'team note' });
    expect(last(user.engine)).toMatchObject({ status: 'applied', scope: 'team:a1' });
    expect(user.engine.state.scopes['team:a1'].note.n1).toMatchObject({ text: 'team note', author: user.userId });
    expect(storage.files.has(`teams/a1/ops/${user.keyId}/0000000001.json`)).toBe(true);
    // A new engine finds the team scope and gives the same state.
    const fresh = new Engine(storage, teamNotesDomain, { now: clock.now });
    await fresh.scan();
    expect(fresh.state.scopes['team:a1'].note.n1).toMatchObject({ text: 'team note' });
    expect(fresh.issues).toEqual([]);
  });

  it('rejects an op type whose scopes do not contain the kind, also in a Batch', async () => {
    const { user } = await domainWorld(teamNotesDomain);
    await user.engine.write(user.signer, 'team:a1', 'CreateNote', { id: 'n1', text: 'x' });
    await expect(user.engine.write(user.signer, 'team:a1', 'Like', { noteId: 'n1' })).rejects.toThrow('Like: not valid in scope team:a1');
    const batch = { ops: [{ type: 'EditNote', payload: { id: 'n1', text: 'y' } }, { type: 'Like', payload: { noteId: 'n1' } }] };
    await expect(user.engine.write(user.signer, 'team:a1', 'Batch', batch)).rejects.toThrow('item 1 (Like): not valid in scope team:a1');
    // The fixed scopes keep their own kind.
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'd1', text: 'data note' });
    expect(note(user.engine.state, 'd1')).toBeDefined();
  });

  it('without scopeKind, compares OpDef.scopes with the scope itself (as before)', async () => {
    const noKind: Domain = { ...teamNotesDomain, scopeKind: undefined };
    const { user } = await domainWorld(noKind);
    expect(user.engine.check(user.keyId, 'team:a1', 'CreateNote', { id: 'n1', text: 'x' })).toMatchObject({ status: 'rejected', reason: 'CreateNote: not valid in scope team:a1' });
    expect(user.engine.check(user.keyId, 'data', 'CreateNote', { id: 'n1', text: 'x' }).status).toBe('applied');
  });

  it('rejects the op as not valid in the scope if scopeKind returns a non-string', async () => {
    const odd: Domain = { ...teamNotesDomain, scopeKind: (s) => (s === 'team:odd' ? (['team'] as unknown as string) : teamNotesDomain.scopeKind!(s)) };
    const { storage, clock, user } = await domainWorld(odd);
    expect(user.engine.check(user.keyId, 'team:odd', 'CreateNote', { id: 'n1', text: 'x' })).toMatchObject({ status: 'rejected', reason: 'CreateNote: not valid in scope team:odd' });
    await expect(user.engine.write(user.signer, 'team:odd', 'CreateNote', { id: 'n1', text: 'x' })).rejects.toThrow('not valid in scope');
    // The same op as a file: the replay gives an issue of kind invalid-payload.
    const env = await signEnvelope(
      { v: 1, opId: 'odd-1', scope: 'team:odd', authorKeyId: user.keyId, seq: 1, prevHash: null, hlc: { t: Date.parse('2026-06-01T00:00:00Z'), c: 0 }, wallTime: '2026-06-01T00:00:00.000Z', type: 'CreateNote', payload: { id: 'n1', text: 'x' } },
      (b) => user.signer.sign(b),
    );
    await storage.writeNew(`teams/odd/ops/${user.keyId}/0000000001.json`, canonicalize(env));
    const fresh = new Engine(storage, odd, { now: clock.now });
    await fresh.scan();
    expect(fresh.issues.filter((i) => i.opId === 'odd-1' && i.kind !== 'future-clock').map((i) => [i.kind, i.detail])).toEqual([['invalid-payload', 'CreateNote: CreateNote: not valid in scope team:odd']]);
  });

  it('rejects the op if scopeKind throws (issue kind domain)', async () => {
    const bad: Domain = {
      ...teamNotesDomain,
      scopeKind: (s) => {
        if (s === 'team:bad') throw new Error('boom');
        return teamNotesDomain.scopeKind!(s);
      },
    };
    const { user } = await domainWorld(bad);
    expect(user.engine.check(user.keyId, 'team:bad', 'CreateNote', { id: 'n1', text: 'x' })).toMatchObject({ status: 'rejected', reason: 'internal error: boom' });
    expect(user.engine.check(user.keyId, 'team:ok', 'CreateNote', { id: 'n1', text: 'x' }).status).toBe('applied');
  });
});

describe('EffectCtx.revertTarget', () => {
  /** Records the revertTarget that authorize and removeWrites get. */
  function spyDomain() {
    const seen: { fn: string; target: RevertTarget | undefined }[] = [];
    const domain: Domain = {
      ...notesDomain,
      authorize(it: OpItem, ctx: EffectCtx) {
        if (it.type === 'Revert') seen.push({ fn: 'authorize', target: ctx.revertTarget });
        return notesDomain.authorize(it, ctx);
      },
      removeWrites(e, id, ctx) {
        seen.push({ fn: 'removeWrites', target: ctx.revertTarget });
        return notesDomain.removeWrites(e, id, ctx);
      },
    };
    return { domain, seen };
  }

  const metaOf = (u: { keyId: string; userId: string }) => ({ opId: 'plan', scope: 'data', authorKeyId: u.keyId, userId: u.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 });

  it('lets authorize see the target: a user reverts an own CreateNote', async () => {
    const { user } = await world();
    const create = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'mine' });
    const plan = planRevert(user.engine.result, create.opId, notesDomain, metaOf(user), user.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    expect(user.engine.check(user.keyId, 'data', 'Revert', plan.payload).status).toBe('applied');
    await user.engine.write(user.signer, 'data', 'Revert', plan.payload);
    expect(note(user.engine.state, 'n1')).toMatchObject({ status: 'deleted', deletedBy: user.userId });
  });

  it('a user cannot revert an own EditNote or the CreateNote of another user', async () => {
    const { admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const edit = await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'b' });
    const other = await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n2', text: 'admin' });
    await user.engine.scan();
    for (const t of [edit, other]) {
      const plan = planRevert(user.engine.result, t.opId, notesDomain, metaOf(user), user.engine.validKeyBindings);
      if ('error' in plan) throw new Error(plan.error);
      await expect(user.engine.write(user.signer, 'data', 'Revert', plan.payload)).rejects.toThrow('only admins can revert');
    }
  });

  it('gives authorize and removeWrites a read-only copy of the target, in the replay and in check()', async () => {
    const { storage, clock, user } = await world();
    const { domain, seen } = spyDomain();
    const create = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'mine' });
    const e = new Engine(storage, domain, { now: clock.now });
    await e.scan();
    const plan = planRevert(e.result, create.opId, domain, metaOf(user), e.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    expect(seen.map((s) => s.fn)).toEqual(['removeWrites']);
    seen.length = 0;
    expect(e.check(user.keyId, 'data', 'Revert', plan.payload).status).toBe('applied');
    expect(seen.map((s) => s.fn)).toEqual(['authorize', 'removeWrites']);
    const t = seen[0].target!;
    expect(t).toMatchObject({ opId: create.opId, scope: 'data', type: 'CreateNote', itemTypes: ['CreateNote'], userId: user.userId });
    expect(t.hash).toBe(plan.payload.target.hash);
    expect(t.writes.map((w) => w.f)).toEqual(['text', 'author', 'status', 'len']);
    expect(Object.isFrozen(t) && Object.isFrozen(t.itemTypes) && Object.isFrozen(t.writes) && Object.isFrozen(t.writes[0])).toBe(true);
    // The copy does not share arrays with the replay.
    expect(t.writes).not.toBe(e.result.applied.get(create.opId)!.writes);
    expect(seen[1].target).toEqual(t);
  });

  it('gives no target for a missing target, a wrong hash or another scope, and keeps the rejections', async () => {
    const { storage, clock, admin } = await world();
    const { domain, seen } = spyDomain();
    const create = await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const e = new Engine(storage, domain, { now: clock.now });
    await e.scan();
    const hash = e.result.applied.get(create.opId)!.hash;
    const r1 = e.check(admin.keyId, 'data', 'Revert', { target: { opId: 'nope', hash }, inverse: [] });
    const r2 = e.check(admin.keyId, 'data', 'Revert', { target: { opId: create.opId, hash: 'sha256:00' }, inverse: [] });
    const r3 = e.check(admin.keyId, 'roles', 'Revert', { target: { opId: create.opId, hash }, inverse: [] });
    expect([r1, r2, r3].map((r) => [r.status, r.reason])).toEqual([
      ['rejected', 'revert target is not an applied op before this op'],
      ['rejected', 'revert target is not an applied op before this op'],
      ['rejected', 'revert must be in the scope of its target'],
    ]);
    expect(seen.map((s) => [s.fn, s.target])).toEqual([
      ['authorize', undefined],
      ['authorize', undefined],
      ['authorize', undefined],
    ]);
  });

  it('authorize runs before the target checks (the order of the rejections does not change)', async () => {
    const { user } = await world();
    expect(user.engine.check(user.keyId, 'data', 'Revert', { target: { opId: 'nope', hash: 'x' }, inverse: [] })).toMatchObject({ status: 'rejected', reason: 'only admins can revert' });
  });
});

describe('the code of a superseded result', () => {
  it('copies the code of effects() to the audit entry of a plain op', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'LOCKED' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'x' }, { allowSuperseded: true });
    const e = last(user.engine);
    expect(e).toMatchObject({ status: 'superseded', reason: 'note is locked', code: 'locked' });
    expect(e.notes).toEqual([{ item: 0, type: 'EditNote', status: 'superseded', reason: 'note is locked', code: 'locked' }]);
    expect(user.engine.check(user.keyId, 'data', 'EditNote', { id: 'n1', text: 'y' })).toMatchObject({ status: 'superseded', code: 'locked' });
  });

  it('drops a code that is not a string', async () => {
    const odd: Domain = {
      ...notesDomain,
      checkState: (writes, ctx) => (writes.some((w) => w.e === 'note' && ctx.get('note', w.id)?.text === 'ODD') ? { superseded: 'odd text', code: 7 as unknown as string } : null),
    };
    const { user } = await domainWorld(odd);
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'ok' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'ODD' }, { allowSuperseded: true });
    const e = last(user.engine);
    expect(e).toMatchObject({ status: 'superseded', reason: 'odd text' });
    expect('code' in e).toBe(false);
    expect('code' in e.notes[0]).toBe(false);
  });

  it('Engine.write() puts the code in SupersededError and keeps the message', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'LOCKED' });
    const err = await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'x' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(SupersededError);
    expect((err as SupersededError).message).toBe('note is locked');
    expect((err as SupersededError).code).toBe('locked');
    const plain = await user.engine.write(user.signer, 'data', 'EditNote', { id: 'missing', text: 'x' }).catch((e: unknown) => e);
    expect(plain).toBeInstanceOf(SupersededError);
    expect('code' in (plain as object)).toBe(false);
  });

  it('copies the code of checkState, and a text result has no code', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'ok' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'BANNED' }, { allowSuperseded: true });
    expect(last(user.engine)).toMatchObject({ status: 'superseded', reason: 'banned text', code: 'banned' });
    expect(note(user.engine.state, 'n1')).toMatchObject({ text: 'ok' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'FORBIDDEN' }, { allowSuperseded: true });
    const e = last(user.engine);
    expect(e).toMatchObject({ status: 'superseded', reason: 'forbidden text' });
    expect('code' in e).toBe(false);
    expect('code' in e.notes[0]).toBe(false);
  });

  it('puts the code of a Batch item in its note, not in the audit entry', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'LOCKED' });
    await user.engine.write(user.signer, 'data', 'Batch', {
      ops: [
        { type: 'EditNote', payload: { id: 'n1', text: 'x' } },
        { type: 'CreateNote', payload: { id: 'n2', text: 'y' } },
        { type: 'EditNote', payload: { id: 'n2', text: 'BANNED' } },
      ],
    });
    const e = last(user.engine);
    expect(e.status).toBe('applied');
    expect('code' in e).toBe(false);
    expect(e.notes).toEqual([
      { item: 0, type: 'EditNote', status: 'superseded', reason: 'note is locked', code: 'locked' },
      { item: 2, type: 'EditNote', status: 'superseded', reason: 'banned text', code: 'banned' },
    ]);
  });

  it('copies the code of removeWrites to the audit entry of a superseded Revert', async () => {
    const { admin, user } = await world();
    const create = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await admin.engine.scan();
    const meta = { opId: 'plan', scope: 'data', authorKeyId: admin.keyId, userId: admin.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
    const plan = planRevert(admin.engine.result, create.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    await user.engine.write(user.signer, 'data', 'DeleteNote', { id: 'n1' });
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload, { allowSuperseded: true });
    expect(last(admin.engine)).toMatchObject({ status: 'superseded', reason: 'note is already deleted', code: 'already-deleted' });
  });
});
