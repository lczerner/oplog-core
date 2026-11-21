// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Chain format 2: a file of another person under the next number
// of an author must not block that author. Synthetic data only.
import { canonicalize } from '../../src/canonical';
import { Engine } from '../../src/engine';
import { note, world } from '../helpers';
import { notesDomain } from '../notes-domain';

const kinds = (e: Engine) => e.issues.map((i) => i.kind);

describe('chain format 2', () => {
  it('a garbage file under the next number of an author does not block the author', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    // Another person saves garbage under seq 2 and 3 of the user.
    storage.files.set(`data/ops/${user.keyId}/0000000002.json`, 'garbage');
    storage.files.set(`data/ops/${user.keyId}/0000000003.json`, canonicalize({ v: 1, opId: 'x', scope: 'data', authorKeyId: user.keyId, seq: 3, prevHash: null, hlc: { t: 1, c: 0 }, wallTime: '2026-01-01T00:00:00.000Z', type: 'CreateNote', payload: { id: 'evil', text: 'x' }, sig: 'AAAA' }));
    await user.engine.scan();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    expect(env.seq).toBe(4);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(note(fresh.state, 'n1')).toBeDefined();
    expect(note(fresh.state, 'n2')).toBeDefined();
    expect(note(fresh.state, 'evil')).toBeUndefined();
    expect(kinds(fresh)).toEqual(expect.arrayContaining(['parse-error', 'bad-signature']));
    expect(kinds(fresh)).not.toContain('chain-gap');
    expect(canonicalize(fresh.state)).toBe(canonicalize(user.engine.state));
  });

  it('garbage under seq 1 before the first op: the first op takes seq 2 with prevHash null', async () => {
    const { storage, user } = await world();
    storage.files.set(`data/ops/${user.keyId}/0000000001.json`, 'garbage');
    await user.engine.scan();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(env).toMatchObject({ seq: 2, prevHash: null });
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(note(fresh.state, 'n1')).toBeDefined();
  });

  it('a copy of an own op under the next number is misplaced and skipped', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    storage.files.set(`data/ops/${user.keyId}/0000000002.json`, storage.files.get(`data/ops/${user.keyId}/0000000001.json`)!);
    await user.engine.scan();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    expect(env.seq).toBe(3);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(note(fresh.state, 'n2')).toBeDefined();
    expect(kinds(fresh)).toContain('misplaced');
  });

  it('a deleted valid op is still detected: the next op waits', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    storage.files.delete(`data/ops/${user.keyId}/0000000001.json`);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toContain('chain-gap');
    expect(note(fresh.state, 'n2')).toBeUndefined();
  });

  it('a changed op is still detected: bad signature, and the next op waits', async () => {
    const { storage, user } = await world();
    const e1 = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    storage.files.set(`data/ops/${user.keyId}/0000000001.json`, canonicalize({ ...e1, payload: { id: 'n1', text: 'changed' } }));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toEqual(expect.arrayContaining(['bad-signature', 'chain-gap']));
    expect(note(fresh.state, 'n1')).toBeUndefined();
    expect(note(fresh.state, 'n2')).toBeUndefined();
  });

  it('2 valid ops with prevHash of the same op are a fork, and the chain stops before them', async () => {
    const { user } = await world();
    const { checkChains } = await import('../../src/verify');
    const e1 = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const e2 = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    const h1 = user.engine.audit.find((a) => a.opId === e1.opId)!.hash;
    const other = { ...e2, seq: 3, opId: 'other', payload: { id: 'n3', text: 'c' } };
    const r = checkChains([
      { path: 'p1', env: e1, hash: h1, sig: 'ok' },
      { path: 'p2', env: e2, hash: 'h2', sig: 'ok' },
      { path: 'p3', env: other, hash: 'h3', sig: 'ok' },
    ]);
    expect(r.valid.map((v) => v.env.opId)).toEqual([e1.opId]);
    expect(r.issues.filter((i) => i.kind === 'fork')).toHaveLength(2);
  });

  it('checkChains is fast: 100 000 ops (20 authors) in less than 1.5 seconds', async () => {
    const { checkChains } = await import('../../src/verify');
    const entries = [];
    for (let a = 0; a < 20; a++) {
      let prev: string | null = null;
      for (let i = 1; i <= 5_000; i++) {
        const hash = `sha256:${a}-${i}`;
        entries.push({ path: `p${a}-${i}`, env: { v: 1, opId: `o${a}-${i}`, scope: 'data', authorKeyId: `k${a}`, seq: i, prevHash: prev, hlc: { t: i, c: a }, wallTime: '2026-01-01T00:00:00.000Z', type: 'CreateNote', payload: { id: `n${a}-${i}`, text: 'x'.repeat(200) }, sig: 's'.repeat(86) } as any, hash, sig: 'ok' as const });
        prev = hash;
      }
    }
    const t0 = Date.now();
    const r = checkChains(entries);
    expect(r.valid).toHaveLength(100_000);
    expect(Date.now() - t0).toBeLessThan(1500);
  });

  it('checkChains is linear: 10 000 ops of 1 author in less than 3 seconds', async () => {
    const { checkChains } = await import('../../src/verify');
    const entries = [];
    let prev: string | null = null;
    for (let i = 1; i <= 10_000; i++) {
      const hash = `sha256:${i}`;
      entries.push({ path: `p${i}`, env: { v: 1, opId: `o${i}`, scope: 'data', authorKeyId: 'k', seq: i, prevHash: prev, hlc: { t: i, c: 0 }, wallTime: '', type: 'CreateNote', payload: { id: `n${i}`, text: 'x' }, sig: 's' } as any, hash, sig: 'ok' as const });
      prev = hash;
    }
    const t0 = Date.now();
    const r = checkChains(entries.reverse());
    expect(r.valid).toHaveLength(10_000);
    expect(Date.now() - t0).toBeLessThan(3000);
  });

  it('a quick scan finds new ops after a gap in the numbers and after a bad file with a high number', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await admin.engine.scan();
    // A gap: garbage under 2, the author writes 3, then the garbage is deleted.
    storage.files.set(`data/ops/${user.keyId}/0000000002.json`, 'garbage');
    await user.engine.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    storage.files.delete(`data/ops/${user.keyId}/0000000002.json`);
    // A well-formed file with a bad signature under a high number.
    const e1 = JSON.parse(storage.files.get(`data/ops/${user.keyId}/0000000001.json`) as string);
    storage.files.set(`data/ops/${user.keyId}/0000000050.json`, canonicalize({ ...e1, seq: 50, sig: 'AAAA' }));
    await admin.engine.scan('quick');
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    await user.engine.scan('quick');
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n3', text: 'c' });
    await admin.engine.scan('quick');
    expect(note(admin.engine.state, 'n3')).toBeDefined();
    expect(env.seq).toBe(4);
  });

  it('cutoffs and checkpoint frontiers use the valid chain head, not a bad file with a higher number', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const e1 = JSON.parse(storage.files.get(`data/ops/${user.keyId}/0000000001.json`) as string);
    storage.files.set(`data/ops/${user.keyId}/0000000009.json`, canonicalize({ ...e1, seq: 9, sig: 'AAAA' }));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(fresh.validHeads().find((h) => h.keyId === user.keyId)?.seq).toBe(1);
  });
});
