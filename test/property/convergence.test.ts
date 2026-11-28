// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import fc from 'fast-check';
import { canonicalize } from '../../src/canonical';
import { Engine } from '../../src/engine';
import { HLC_MAX_T } from '../../src/hlc';
import { TRUST_ROOT_PATH } from '../../src/paths';
import { replay } from '../../src/replay';
import { planRevert } from '../../src/revert';
import { MemoryStorage } from '../../src/storage/memory';
import type { DirEntry, Storage } from '../../src/storage/types';
import { actor, fakeClock, rawOp, world } from '../helpers';
import { notesDomain } from '../notes-domain';

/** A storage view that shows only some files (simulates partial OneDrive sync). */
export class PartialView implements Storage {
  visible = new Set<string>([TRUST_ROOT_PATH]);
  constructor(private readonly base: MemoryStorage) {}
  async list(dir: string): Promise<DirEntry[] | null> {
    const v = new MemoryStorage();
    for (const p of this.visible) if (this.base.files.has(p)) v.files.set(p, this.base.files.get(p)!);
    return v.list(dir);
  }
  async read(path: string) {
    return this.visible.has(path) ? this.base.read(path) : null;
  }
  async readBytes(path: string) {
    return this.visible.has(path) ? this.base.readBytes(path) : null;
  }
  async writeNew(): Promise<void> {
    throw new Error('read-only view');
  }
  async writeNewBytes(): Promise<void> {
    throw new Error('read-only view');
  }
  async remove(): Promise<boolean> {
    throw new Error('read-only view');
  }
}

/**
 * Concurrent, partly conflicting ops of 3 writers, with a Batch, a Revert and a revocation.
 * Also: an op that copies the opId of an op of another author (with an earlier HLC), and an
 * outsider key (that nobody granted) with a far-future HLC.
 */
async function buildOpSet() {
  const { storage, admin, user, admin2, clock } = await world({ admin2: true });
  const u2 = await actor('user2', storage, clock.now);
  await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: u2.userId, keyId: u2.keyId, publicKey: u2.publicKey, admin: false });
  await user.engine.scan();
  await u2.engine.scan();
  await admin2!.engine.scan();
  // Each writer does not see the others until the end.
  const first = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'user' });
  await u2.engine.write(u2.signer, 'data', 'CreateNote', { id: 'n1', text: 'user2' }); // same ID: the later one is superseded
  await user.engine.write(user.signer, 'data', 'Batch', { ops: [{ type: 'CreateNote', payload: { id: 'n2', text: 'x' } }, { type: 'EditNote', payload: { id: 'n2', text: 'xy' } }] });
  await u2.engine.write(u2.signer, 'data', 'CreateNote', { id: 'n3', text: 'LOCKED' });
  await admin2!.engine.write(admin2!.signer, 'data', 'CreateNote', { id: 'n4', text: 'a2' });
  await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'user edit' });
  await u2.engine.write(u2.signer, 'data', 'DeleteNote', { id: 'n3' });
  // A non-admin reverts an own CreateNote: authorize permits it only through ctx.revertTarget.
  const own = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n5', text: 'own' });
  const userMeta = { opId: 'plan', scope: 'data', authorKeyId: user.keyId, userId: user.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
  const ownEntry = user.engine.audit.find((x) => x.opId === own.opId && x.authorKeyId === user.keyId)!;
  const ownPlan = planRevert(user.engine.result, ownEntry, notesDomain, userMeta, user.engine.validKeyBindings);
  if ('error' in ownPlan) throw new Error(ownPlan.error);
  await user.engine.write(user.signer, 'data', 'Revert', ownPlan.payload);
  await admin.engine.scan();
  await admin.engine.write(admin.signer, 'data', 'EditNote', { id: 'n2', text: 'admin edit' });
  const target = admin.engine.audit.find((a) => a.type === 'EditNote' && a.status === 'applied' && a.authorKeyId === user.keyId)!;
  const meta = { opId: 'plan', scope: 'data', authorKeyId: admin.keyId, userId: admin.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
  const plan = planRevert(admin.engine.result, target, notesDomain, meta, admin.engine.validKeyBindings);
  if ('error' in plan) throw new Error(plan.error);
  await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
  await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: u2.keyId, cutoff: { data: 2 } });
  await admin2!.engine.write(admin2!.signer, 'data', 'EditNote', { id: 'n4', text: 'FORBIDDEN' }, { allowSuperseded: true });
  await admin2!.engine.write(admin2!.signer, 'data', 'EditNote', { id: 'n4', text: 'BANNED' }, { allowSuperseded: true }); // superseded with a code
  // admin2 copies the opId of the first op of the user, with an earlier HLC. Both ops must apply.
  await rawOp(storage, admin2!, 'roles', 'SetFlag', { name: 'copy', value: 1 }, { t: first.hlc.t - 1, c: 0 }, undefined, first.opId);
  // An outsider registers its key with a self-signed GrantUser and a far-future HLC. The replay rejects it (unknown key).
  // A later op with a far-future HLC and an honest wall time must still be a future-clock op.
  const outsider = await actor('outsider', storage, clock.now);
  const farFuture = Date.parse('2027-01-01T00:00:00Z');
  const honestWall = new Date(clock.now()).toISOString();
  await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: farFuture, c: 0 }, honestWall);
  await rawOp(storage, admin2!, 'roles', 'SetFlag', { name: 'late', value: 2 }, { t: farFuture, c: 1 }, honestWall);
  // A second outsider op with the maximum HLC: it is the last op in the order and it is rejected. An
  // incremental apply takes it back and applies it again after the new ops (Replayer.takeBackRejected).
  await rawOp(storage, outsider, 'roles', 'SetFlag', { name: 'max', value: 3 }, { t: HLC_MAX_T, c: 0 }, honestWall);
  const ref = new Engine(storage, notesDomain, { now: fakeClock().now });
  await ref.scan();
  if (ref.state.scopes.data.note.n5?.status !== 'deleted') throw new Error('the Revert of the own CreateNote did not apply');
  const copied = ref.audit.filter((a) => a.opId === first.opId);
  if (copied.length !== 2 || copied.some((a) => a.status !== 'applied')) throw new Error('the 2 ops with the same opId did not both apply');
  const futureOps = ref.result.issues.filter((i) => i.kind === 'future-clock').map((i) => i.authorKeyId);
  if (canonicalize(futureOps) !== canonicalize([outsider.keyId, admin2!.keyId, outsider.keyId])) throw new Error(`unexpected future-clock issues: ${futureOps.join(', ')}`);
  const opPaths = [...storage.files.keys()].filter((p) => p.includes('/ops/'));
  return { storage, ref, opPaths };
}

describe('convergence (property)', async () => {
  const { storage, ref, opPaths } = await buildOpSet();
  const refState = canonicalize(ref.state);
  const summary = (e: Engine) => canonicalize({ audit: e.audit.map((a) => [a.authorKeyId, a.opId, a.status, a.reason ?? null, a.code ?? null, a.notes.map((n) => n.code ?? null)]), issues: e.result.issues.map((i) => [i.kind, i.authorKeyId ?? null, i.opId ?? null]) });
  const refSummary = summary(ref);
  const verified = ref.audit.map((a) => ({ env: ref.knownOps().find((e) => e.authorKeyId === a.authorKeyId && e.opId === a.opId)!, hash: a.hash }));

  it('the op set has applied, superseded and rejected ops', () => {
    const st = new Set(ref.audit.map((a) => a.status));
    expect([...st].sort()).toEqual(['applied', 'rejected', 'superseded']);
    expect(ref.audit.some((a) => a.type === 'Revert' && a.status === 'applied')).toBe(true);
    expect(ref.audit.some((a) => a.reason === 'unknown key')).toBe(true);
    expect(new Set(verified.map((v) => v.hash)).size).toBe(verified.length);
  });

  it('replay gives the same state for any order of the same ops', () => {
    fc.assert(
      fc.property(fc.shuffledSubarray(verified, { minLength: verified.length, maxLength: verified.length }), (perm) => {
        const r = replay(perm, { domain: notesDomain, trustRoot: ref.trustRoot, validKeyBindings: ref.validKeyBindings });
        expect(canonicalize(r.state)).toBe(refState);
      }),
      { numRuns: 200 },
    );
  });

  it('incremental sync in any partition converges to the same state', async () => {
    let takenBack = 0;
    await fc.assert(
      fc.asyncProperty(
        fc.shuffledSubarray(opPaths, { minLength: opPaths.length, maxLength: opPaths.length }),
        fc.array(fc.integer({ min: 1, max: 8 }), { minLength: 1, maxLength: 10 }),
        async (order, chunks) => {
          const view = new PartialView(storage);
          const e = new Engine(view, notesDomain, { now: fakeClock().now });
          let i = 0;
          for (const n of chunks) {
            for (const p of order.slice(i, i + n)) view.visible.add(p);
            i += n;
            await e.scan(i % 2 ? 'full' : 'quick');
          }
          for (const p of order) view.visible.add(p);
          await e.scan('full');
          takenBack += e.stats.takenBack;
          expect(canonicalize(e.state)).toBe(refState);
          expect(summary(e)).toBe(refSummary);
        },
      ),
      { numRuns: 40 },
    );
    // The runs used the incremental path that takes back rejected ops at the end of the order.
    expect(takenBack).toBeGreaterThan(0);
  });
});
