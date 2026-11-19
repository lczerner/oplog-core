// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import fc from 'fast-check';
import { canonicalize } from '../../src/canonical';
import { Engine } from '../../src/engine';
import { TRUST_ROOT_PATH } from '../../src/paths';
import { replay } from '../../src/replay';
import { planRevert } from '../../src/revert';
import { MemoryStorage } from '../../src/storage/memory';
import type { DirEntry, Storage } from '../../src/storage/types';
import { actor, fakeClock, world } from '../helpers';
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

/** Concurrent, partly conflicting ops of 3 writers, with a Batch, a Revert and a revocation. */
async function buildOpSet() {
  const { storage, admin, user, admin2, clock } = await world({ admin2: true });
  const u2 = await actor('user2', storage, clock.now);
  await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: u2.userId, keyId: u2.keyId, publicKey: u2.publicKey, admin: false });
  await user.engine.scan();
  await u2.engine.scan();
  await admin2!.engine.scan();
  // Each writer does not see the others until the end.
  await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'user' });
  await u2.engine.write(u2.signer, 'data', 'CreateNote', { id: 'n1', text: 'user2' }); // same ID: the later one is superseded
  await user.engine.write(user.signer, 'data', 'Batch', { ops: [{ type: 'CreateNote', payload: { id: 'n2', text: 'x' } }, { type: 'EditNote', payload: { id: 'n2', text: 'xy' } }] });
  await u2.engine.write(u2.signer, 'data', 'CreateNote', { id: 'n3', text: 'LOCKED' });
  await admin2!.engine.write(admin2!.signer, 'data', 'CreateNote', { id: 'n4', text: 'a2' });
  await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'user edit' });
  await u2.engine.write(u2.signer, 'data', 'DeleteNote', { id: 'n3' });
  await admin.engine.scan();
  await admin.engine.write(admin.signer, 'data', 'EditNote', { id: 'n2', text: 'admin edit' });
  const target = admin.engine.audit.find((a) => a.type === 'EditNote' && a.status === 'applied' && a.authorKeyId === user.keyId)!;
  const meta = { opId: 'plan', scope: 'data', authorKeyId: admin.keyId, userId: admin.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
  const plan = planRevert(admin.engine.result, target.opId, notesDomain, meta, admin.engine.validKeyBindings);
  if ('error' in plan) throw new Error(plan.error);
  await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
  await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: u2.keyId, cutoff: { data: 2 } });
  await admin2!.engine.write(admin2!.signer, 'data', 'EditNote', { id: 'n4', text: 'FORBIDDEN' }, { allowSuperseded: true });
  const ref = new Engine(storage, notesDomain, { now: fakeClock().now });
  await ref.scan();
  const opPaths = [...storage.files.keys()].filter((p) => p.includes('/ops/'));
  return { storage, ref, opPaths };
}

describe('convergence (property)', async () => {
  const { storage, ref, opPaths } = await buildOpSet();
  const refState = canonicalize(ref.state);
  const summary = (e: Engine) => canonicalize({ audit: e.audit.map((a) => [a.opId, a.status, a.reason ?? null]), issues: e.result.issues.map((i) => [i.kind, i.opId ?? null]) });
  const refSummary = summary(ref);
  const verified = ref.audit.map((a) => ({ env: ref.knownOps().find((e) => e.opId === a.opId)!, hash: a.hash }));

  it('the op set has applied, superseded and rejected ops', () => {
    const st = new Set(ref.audit.map((a) => a.status));
    expect([...st].sort()).toEqual(['applied', 'rejected', 'superseded']);
    expect(ref.audit.some((a) => a.type === 'Revert' && a.status === 'applied')).toBe(true);
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
          expect(canonicalize(e.state)).toBe(refState);
          expect(summary(e)).toBe(refSummary);
        },
      ),
      { numRuns: 40 },
    );
  });
});
