// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { canonicalize } from '../../src/canonical';
import { Engine } from '../../src/engine';
import { replay } from '../../src/replay';
import { MemoryStorage } from '../../src/storage/memory';
import { note, rawOp, sameUser, world } from '../helpers';
import { notesDomain } from '../notes-domain';

const kinds = (e: Engine) => e.issues.map((i) => i.kind);

describe('integrity', () => {
  it('detects a changed op file (bad signature) and stops the chain there', async () => {
    const { storage, user } = await world();
    const e1 = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    const path = `data/ops/${user.keyId}/0000000001.json`;
    storage.files.set(path, canonicalize({ ...e1, payload: { id: 'n1', text: 'changed' } }));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toEqual(expect.arrayContaining(['bad-signature', 'chain-broken']));
    expect(note(fresh.state, 'n1')).toBeUndefined();
    expect(note(fresh.state, 'n2')).toBeUndefined();
  });

  it('waits at a missing file in a chain (chain-gap)', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    storage.files.delete(`data/ops/${user.keyId}/0000000001.json`);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toContain('chain-gap');
    expect(note(fresh.state, 'n2')).toBeUndefined();
  });

  it('detects a fork in a conflict copy and lists unknown files', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    // The same key on a second computer wrote another op with seq 1. OneDrive saved it as a conflict copy.
    const pc2 = new MemoryStorage();
    await rawOp(pc2, user, 'data', 'CreateNote', { id: 'x1', text: 'other pc' }, { t: Date.parse('2026-03-01T00:00:00Z'), c: 0 });
    storage.files.set(`data/ops/${user.keyId}/0000000001-PC2.json`, pc2.files.get(`data/ops/${user.keyId}/0000000001.json`)!);
    storage.files.set('data/ops/readme.txt', 'x');
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toEqual(expect.arrayContaining(['unknown-file', 'fork']));
    expect(fresh.issues.some((i) => i.path === 'data/ops/readme.txt')).toBe(true);
    expect(note(fresh.state, 'n1')).toBeUndefined();
    expect(note(fresh.state, 'x1')).toBeUndefined();
  });

  it('marks a file whose content does not match its path as misplaced', async () => {
    const { storage, user } = await world();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    storage.files.set(`roles/ops/${user.keyId}/0000000001.json`, canonicalize(env));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(kinds(fresh)).toContain('misplaced');
  });
});

describe('engine', () => {
  it('gives the same state with incremental apply and with a full replay', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 5; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: `t${i}` });
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'data', 'EditNote', { id: 'n1', text: 'admin edit' });
    await user.engine.scan();
    await user.engine.write(user.signer, 'data', 'DeleteNote', { id: 'n2' });
    expect(user.engine.stats.incrementalOps).toBeGreaterThan(0);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(canonicalize(user.engine.state)).toBe(canonicalize(fresh.state));
    expect(canonicalize(admin.engine.state)).not.toBe(canonicalize(fresh.state)); // admin did not scan yet
    await admin.engine.scan();
    expect(canonicalize(admin.engine.state)).toBe(canonicalize(fresh.state));
  });

  it('retries with the next seq when another tab of the same key wrote that seq', async () => {
    const { storage, user } = await world();
    const tab2 = sameUser(user, storage);
    await tab2.engine.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const env = await tab2.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    expect(env.seq).toBe(2);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(fresh.issues).toEqual([]);
    expect(note(fresh.state, 'n2')).toBeDefined();
  });

  it('reads a checkpoint instead of the op files, and checks that an admin signed it', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: `t${i}` });
    await admin.engine.scan();
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    expect(admin.engine.issues).toEqual([]);
    // A storage with the checkpoint, but without the op files of the user.
    const thin = new MemoryStorage();
    for (const [p, v] of storage.files) if (!p.startsWith(`data/ops/${user.keyId}`)) thin.files.set(p, v);
    const fresh = new Engine(thin, notesDomain);
    await fresh.scan();
    expect(canonicalize(fresh.state)).toBe(canonicalize(admin.engine.state));
    // A non-admin cannot write a checkpoint.
    await user.engine.scan();
    await expect(user.engine.createCheckpoint(user.signer, 'data')).rejects.toThrow('only an admin');
    expect(path).toMatch(/^data\/checkpoints\//);
  });

  it('a forged checkpoint of a non-admin does not hide or replace the real op files (review B1)', async () => {
    const { storage, user } = await world();
    const e1 = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'real' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'real 2' });
    // A user (or anybody with folder access) writes a "checkpoint" with a changed copy of op 1.
    const forged = { v: 1, scope: 'data', authorKeyId: user.keyId, seq: 1, hlc: { t: 1, c: 0 }, wallTime: '2026-01-01T00:00:00.000Z', frontier: {}, ops: [{ ...e1, payload: { id: 'n1', text: 'forged' } }], sig: 'x' };
    storage.files.set(`data/checkpoints/${user.keyId}/0000000001.json`, canonicalize(forged));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(note(fresh.state, 'n1')).toMatchObject({ text: 'real' });
    expect(note(fresh.state, 'n2')).toBeDefined();
    expect(fresh.issues.some((i) => i.kind === 'bad-checkpoint')).toBe(true);
  });

  it('restores from the cache with the same state', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const cache = JSON.parse(JSON.stringify(user.engine.exportCache()));
    const fresh = new Engine(storage, notesDomain);
    await fresh.importCache(cache);
    expect(canonicalize(fresh.state)).toBe(canonicalize(user.engine.state));
  });

  it('replay does not depend on the order of the input', async () => {
    const { admin, user } = await world();
    for (let i = 0; i < 4; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: `t${i}` });
    await admin.engine.scan();
    const ops = admin.engine.audit.map((a) => ({ env: admin.engine.knownOps().find((e) => e.opId === a.opId)!, hash: a.hash }));
    const opts = { domain: notesDomain, trustRoot: admin.engine.trustRoot, validKeyBindings: admin.engine.validKeyBindings };
    expect(canonicalize(replay([...ops].reverse(), opts).state)).toBe(canonicalize(replay(ops, opts).state));
  });
});
