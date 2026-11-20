// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// The parallel reads of a scan (pool, READ_CONCURRENCY) and the chain cache of recompute.
import { canonicalize } from '../../src/canonical';
import { Engine, pool } from '../../src/engine';
import { filePath, TRUST_ROOT_PATH } from '../../src/paths';
import type { Storage } from '../../src/storage/types';
import { MemoryStorage } from '../../src/storage/memory';
import { actor, fakeClock, note, rawOp, world, writeTrustRoot } from '../helpers';
import { notesDomain } from '../notes-domain';

/** A storage whose reads end in a random order (a seeded random delay for each read). */
function shuffled(storage: Storage, seed: number): Storage {
  let s = seed;
  const rnd = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32);
  const s2 = Object.create(storage) as Storage;
  s2.read = async (p: string) => {
    await new Promise((r) => setTimeout(r, Math.floor(rnd() * 4)));
    return storage.read(p);
  };
  return s2;
}

const summary = (e: Engine) => ({
  state: canonicalize(e.state),
  issues: e.issues.map((i) => canonicalize(i)),
  heads: canonicalize(e.validHeads().sort((a, b) => (a.keyId + a.scope < b.keyId + b.scope ? -1 : 1))),
  audit: e.audit.map((a) => `${a.opId} ${a.status}`),
});

describe('pool', () => {
  it('stops at the first error and rejects only after all running calls have ended', async () => {
    const started: number[] = [];
    let running = 0;
    let after = 0;
    let rejected = false;
    const p = pool([0, 1, 2, 3, 4, 5, 6, 7], 3, async (x) => {
      started.push(x);
      running++;
      await new Promise((r) => setTimeout(r, x === 1 ? 1 : 10));
      running--;
      if (rejected) after++;
      if (x === 1) throw new Error('read failed');
    });
    await expect(p).rejects.toThrow('read failed');
    rejected = true;
    expect(running).toBe(0);
    await new Promise((r) => setTimeout(r, 30));
    expect(after).toBe(0);
    // Calls 0 and 2 were running when call 1 failed; no new call started after the error.
    expect(started.sort()).toEqual([0, 1, 2]);
  });
});

describe('parallel scan', () => {
  it('gives the same state, issues, heads and audit as before, for any order of the reads', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 40; i++) await (i % 3 ? user : admin).engine.write((i % 3 ? user : admin).signer, 'data', 'CreateNote', { id: `n${i}`, text: `t${i}` });
    // 3 parse errors in 1 author folder: a wrong apply order changes the order of the issues.
    for (const n of [97, 98, 99]) await storage.writeNew(filePath('data', 'ops', user.keyId, n), `garbage ${n}`);
    await storage.writeNew(`data/ops/${user.keyId}/0000000003-PC.json`, 'copy'); // a conflict copy
    const ref = new Engine(storage, notesDomain);
    await ref.scan();
    for (const seed of [1, 2, 3]) {
      const e = new Engine(shuffled(storage, seed), notesDomain);
      await e.scan();
      expect(summary(e)).toEqual(summary(ref));
    }
  });

  it('a failed read: the scan rejects, nothing of that folder is applied, and a forged op never shows (review B1)', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 5; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: `t${i}` });
    // A forged op: a correct chain link, but a bad signature.
    const env = await rawOp(storage, user, 'data', 'CreateNote', { id: 'evil', text: 'x' }, { t: Date.parse('2026-06-01T00:00:00Z'), c: 0 });
    const p = filePath('data', 'ops', user.keyId, env.seq);
    await storage.remove(p);
    await storage.writeNew(p, canonicalize({ ...env, payload: { id: 'evil', text: 'forged' } }));
    const bad = filePath('data', 'ops', user.keyId, 99);
    await storage.writeNew(bad, 'garbage');
    let failOnce = true;
    let slow!: () => void;
    const gate = new Promise<void>((r) => (slow = r));
    const s = Object.create(storage) as Storage;
    s.read = async (path: string) => {
      if (path === bad && failOnce) {
        failOnce = false;
        throw new Error('NotReadableError');
      }
      if (path === p) await gate; // the read of the forged op ends late
      return storage.read(path);
    };
    // Open the gate inside the recompute of the next write (the 2nd keysIn call for its op), so
    // that a read of the failed scan that still runs would land between the steps of recompute.
    let a1 = 0;
    const dom = Object.assign(Object.create(Object.getPrototypeOf(notesDomain)), notesDomain, {
      keysIn: (it: { payload?: { id?: string } }) => {
        if (it.payload?.id === 'a1' && ++a1 === 2) slow();
        return notesDomain.keysIn(it as never);
      },
    });
    const e = new Engine(s, dom);
    // A real read always ends: with the fix, the failed scan waits for it (here 50 ms).
    const timer = setTimeout(slow, 50);
    await expect(e.scan()).rejects.toThrow('NotReadableError');
    // The next task of the engine: a write. No read of the failed scan may change the state now.
    await e.write(admin.signer, 'data', 'CreateNote', { id: 'a1', text: 'a' });
    expect(note(e.state, 'evil')).toBeUndefined();
    // Also after a recompute (the state of the reviewer's probe), the forged op is not in the state.
    await new Promise((r) => setTimeout(r, 20));
    await e.recompute();
    expect(note(e.state, 'evil')).toBeUndefined();
    clearTimeout(timer);
    slow();
    await e.scan();
    expect(note(e.state, 'evil')).toBeUndefined();
    expect(e.issues.filter((i) => i.path === p).map((i) => i.kind)).toEqual(['bad-signature']);
  });
});

describe('chain cache', () => {
  it('a gap that closes later and a key that becomes known later are checked again', async () => {
    const storage = new MemoryStorage();
    const clock = fakeClock();
    const admin = await actor('admin', storage, clock.now);
    await writeTrustRoot(storage, [admin]);
    await admin.engine.scan();
    const user = await actor('user', storage, clock.now);
    const t = Date.parse('2026-01-02T00:00:00Z');
    for (let i = 1; i <= 3; i++) await rawOp(storage, user, 'data', 'CreateNote', { id: `g${i}`, text: `${i}` }, { t: t + i * 1000, c: 0 });
    // Another computer: the trust root, op 1 and op 3 of the user, no GrantUser yet.
    const other = new MemoryStorage();
    const copy = async (p: string) => other.writeNew(p, (await storage.read(p))!);
    await copy(TRUST_ROOT_PATH);
    await copy(filePath('data', 'ops', user.keyId, 1));
    await copy(filePath('data', 'ops', user.keyId, 3));
    const e = new Engine(other, notesDomain);
    await e.scan();
    expect(e.issues.map((i) => i.kind)).toContain('unknown-key');
    // The approval arrives: the key is known now.
    await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: user.userId, keyId: user.keyId, publicKey: user.publicKey, admin: false });
    await copy(filePath('roles', 'ops', admin.keyId, 1));
    await e.scan();
    expect(note(e.state, 'g1')).toBeDefined();
    expect(note(e.state, 'g3')).toBeUndefined();
    expect(e.issues.map((i) => i.kind)).toContain('chain-gap');
    // Op 2 arrives: the gap closes.
    await copy(filePath('data', 'ops', user.keyId, 2));
    await e.scan();
    expect(e.issues).toEqual([]);
    expect(['g1', 'g2', 'g3'].every((id) => note(e.state, id))).toBe(true);
  });
});
