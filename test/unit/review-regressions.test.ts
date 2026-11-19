// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Regression tests for the findings of the first expert review of oplog-core.
import { canonicalize } from '../../src/canonical';
import { b64u, fromB64u } from '../../src/encoding';
import { Engine } from '../../src/engine';
import { HLC_MAX_C, HLC_MAX_T, HlcClock } from '../../src/hlc';
import { planRevert } from '../../src/revert';
import { checkChains } from '../../src/verify';
import { MemoryStorage } from '../../src/storage/memory';
import { NodeFsStorage } from '../../src/storage/node-fs';
import { note, rawOp, world } from '../helpers';
import { notesDomain } from '../notes-domain';

describe('review regressions', () => {
  it('B2: an op type or an ID that is a prototype member does not crash the replay', async () => {
    const { storage, admin, user } = await world();
    const t = Date.parse('2026-03-01T00:00:00Z');
    await rawOp(storage, user, 'data', 'constructor', {}, { t, c: 0 });
    await rawOp(storage, user, 'data', 'Batch', { ops: [{ type: 'toString', payload: {} }] }, { t: t + 1, c: 0 });
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'constructor', text: 'proto' }, { t: t + 2, c: 0 });
    await admin.engine.scan();
    expect(admin.engine.audit.filter((a) => a.type === 'constructor' || a.type === 'Batch').map((a) => a.status)).toEqual(['rejected', 'rejected']);
    expect(note(admin.engine.state, 'constructor')).toMatchObject({ text: 'proto' });
  });

  it('B2: an error in domain code rejects only that op', async () => {
    const { storage, user } = await world();
    const broken = { ...notesDomain, catalog: { ...notesDomain.catalog, CreateNote: { ...notesDomain.catalog.CreateNote, effects: () => { throw new Error('bug'); } } } };
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'x' }, { t: Date.parse('2026-03-01T00:00:00Z'), c: 0 });
    await rawOp(storage, user, 'data', 'EditNote', { id: 'n1', text: 'y' }, { t: Date.parse('2026-03-01T00:00:01Z'), c: 0 });
    const e = new Engine(storage, broken);
    await e.scan();
    expect(e.audit.map((a) => [a.type, a.status]).slice(-2)).toEqual([['CreateNote', 'rejected'], ['EditNote', 'superseded']]);
    expect(e.issues.some((i) => i.kind === 'domain' && i.detail.includes('bug'))).toBe(true);
  });

  it('B3: HLC values out of range are invalid, and the clock never makes one', async () => {
    const { storage, admin, user } = await world();
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'x' }, { t: Date.parse('2026-03-01T00:00:00Z'), c: HLC_MAX_C + 1 });
    await admin.engine.scan();
    expect(admin.engine.issues.some((i) => i.kind === 'parse-error' && i.detail.includes('out of range'))).toBe(true);
    await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n2', text: 'still writes' });
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    const c = new HlcClock(() => 1000);
    c.observe({ t: 1000, c: HLC_MAX_C });
    expect(c.tick()).toEqual({ t: 1001, c: 0 });
  });

  it('B4: only the canonical base64url text of a signature is valid', () => {
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const sig = new Uint8Array(64).fill(7);
    const text = b64u(sig);
    expect(fromB64u(text)).toEqual(sig);
    // 64 bytes = 86 characters. The last character carries 2 data bits and 4 unused bits.
    const other = text.slice(0, -1) + A[A.indexOf(text[text.length - 1]) | 1];
    expect(other).not.toBe(text);
    expect(fromB64uLoose(other)).toEqual(sig);
    expect(() => fromB64u(other)).toThrow('non-canonical');
  });

  it('B4: a conflict copy with a non-canonical text of the same signature is not a fork', async () => {
    const { storage, admin, user } = await world();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const alt = env.sig.slice(0, -1) + A[A.indexOf(env.sig[env.sig.length - 1]) | 1];
    expect(alt).not.toBe(env.sig);
    storage.files.set(`data/ops/${user.keyId}/0000000001-copy.json`, canonicalize({ ...env, sig: alt }));
    await admin.engine.scan();
    expect(admin.engine.issues.filter((i) => i.kind === 'fork')).toEqual([]);
    expect(note(admin.engine.state, 'n1')).toBeDefined();
  });

  it('S1: a file with a far-future HLC that is not valid does not move the clock', async () => {
    const { storage, admin } = await world();
    storage.files.set('data/ops/kaaaaaaaaaaaaaaaaaaaaaaaa/0000000001.json', canonicalize({ v: 1, opId: 'x', scope: 'data', authorKeyId: 'kaaaaaaaaaaaaaaaaaaaaaaaa', seq: 1, prevHash: null, hlc: { t: Date.parse('2100-01-01T00:00:00Z'), c: 0 }, wallTime: '2100-01-01T00:00:00.000Z', type: 'CreateNote', payload: {}, sig: 'x' }));
    await admin.engine.scan();
    const env = await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    expect(env.hlc.t).toBeLessThan(Date.parse('2030-01-01T00:00:00Z'));
  });

  it('S2: an entity ID that is a prototype member is a normal ID', async () => {
    const { user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'toString', text: 'x' });
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'toString', text: 'y' });
    expect(note(user.engine.state, 'toString')).toMatchObject({ text: 'y' });
  });

  it('S5: a Revert of a superseded op is rejected', async () => {
    const { admin } = await world();
    const sup = await admin.engine.write(admin.signer, 'data', 'EditNote', { id: 'missing', text: 'x' }, { allowSuperseded: true });
    const hash = admin.engine.audit.find((a) => a.opId === sup.opId)!.hash;
    await expect(admin.engine.write(admin.signer, 'data', 'Revert', { target: { opId: sup.opId, hash }, inverse: [] })).rejects.toThrow('not an applied op');
  });

  it('S5: check() of a rejected Batch and of a Revert leaves no trace in the state', async () => {
    const { admin } = await world();
    const before = canonicalize(admin.engine.state);
    expect(admin.engine.check(admin.keyId, 'data', 'Batch', { ops: [{ type: 'CreateNote', payload: { id: 'n1', text: 'x' } }, { type: 'CreateNote', payload: { bad: 1 } }] }).status).toBe('rejected');
    expect(admin.engine.check(admin.keyId, 'data', 'Revert', { target: { opId: 'nope', hash: 'x' }, inverse: [] }).status).toBe('rejected');
    expect(canonicalize(admin.engine.state)).toBe(before);
  });

  it('S5: the local future-clock check flags a wall time after the local time', async () => {
    const { storage, user } = await world();
    const t = Date.parse('2026-01-01T09:00:00Z');
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'x' }, { t, c: 0 }, '2027-01-01T00:00:00.000Z');
    const e = new Engine(storage, notesDomain, { now: () => Date.parse('2026-01-01T10:00:00Z') });
    await e.scan();
    expect(e.issues.some((i) => i.kind === 'future-clock' && i.detail.includes('this computer'))).toBe(true);
  });

  it('M4: storage paths cannot leave the root', async () => {
    for (const s of [new MemoryStorage(), new NodeFsStorage('/nonexistent-root')])
      for (const bad of ['../x', 'a/../b', 'a//b', '/abs', 'a\\b', 'c:x', './x'])
        await expect(s.read(bad)).rejects.toThrow('invalid storage path');
  });
});

describe('second review regressions', () => {
  const t0 = Date.parse('2026-03-01T00:00:00Z');

  it('F1: an unsigned file with a Batch item type that is not a string does not stop the scan', async () => {
    const { storage, admin } = await world();
    storage.files.set('data/ops/kaaaaaaaaaaaaaaaaaaaaaaaa/0000000001.json', JSON.stringify({ v: 1, opId: 'x', scope: 'data', authorKeyId: 'kaaaaaaaaaaaaaaaaaaaaaaaa', seq: 1, prevHash: null, hlc: { t: t0, c: 0 }, wallTime: '2026-03-01T00:00:00.000Z', type: 'Batch', payload: { ops: [{ type: { toString: 1 }, payload: {} }] }, sig: 'x' }));
    await expect(admin.engine.scan()).resolves.toBeDefined();
    expect(admin.engine.issues.some((i) => i.kind === 'unknown-key')).toBe(true);
  });

  it('F2: a checkpoint file with a wall time that is not a string does not stop the scan', async () => {
    const { storage, admin, user } = await world();
    storage.files.set(`data/checkpoints/${user.keyId}/0000000001.json`, JSON.stringify({ v: 1, scope: 'data', authorKeyId: user.keyId, seq: 1, wallTime: { toString: 1 }, ops: [], sig: 'x' }));
    await expect(admin.engine.scan()).resolves.toBeDefined();
    expect(admin.engine.issues.some((i) => i.kind === 'bad-checkpoint')).toBe(true);
  });

  it('F4: an error in Domain.keysIn ignores the item and does not stop the scan', async () => {
    const { storage, admin } = await world();
    const k = 'kaaaaaaaaaaaaaaaaaaaaaaaa';
    await rawOp(storage, admin, 'roles', 'GrantUser', { userId: 'u-x', keyId: k, publicKey: { toString: 1 }, admin: false }, { t: Date.now() + 1000, c: 0 });
    const e = new Engine(storage, { ...notesDomain, keysIn: () => { throw new Error('bug in keysIn'); } });
    await expect(e.scan()).resolves.toBeDefined();
  });

  it('F5: the ID __proto__ is invalid and cannot change a prototype', async () => {
    const { user } = await world();
    await expect(user.engine.write(user.signer, 'data', 'CreateNote', { id: '__proto__', text: 'x' })).rejects.toThrow('id expected');
    expect(() => canonicalize(user.engine.state)).not.toThrow();
  });

  it('F7: 2 validly signed copies with the same content and different signature texts count as 1 op (checkChains)', async () => {
    const { user } = await world();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    const copy = { ...env, sig: env.sig + 'different-text' };
    const r = checkChains([
      { path: 'a', env, hash: 'h1', sig: 'ok' },
      { path: 'b', env: copy, hash: 'h2', sig: 'ok' },
    ]);
    expect(r.issues).toEqual([]);
    expect(r.valid).toHaveLength(1);
  });

  it('F8: a Revert does not write a derived field; normalize computes it again', async () => {
    const { admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    const like1 = await user.engine.write(user.signer, 'data', 'Like', { noteId: 'n1' });
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'data', 'Like', { noteId: 'n1' });
    expect(note(admin.engine.state, 'n1').likeCount).toBe(2);
    const meta = { opId: 'p', scope: 'data', authorKeyId: admin.keyId, userId: admin.userId, seq: 1, hlc: { t: 0, c: 0 }, wallTime: '', envType: 'Revert', item: 0 };
    const plan = planRevert(admin.engine.result, like1.opId, notesDomain, meta, admin.engine.validKeyBindings);
    if ('error' in plan) throw new Error(plan.error);
    expect(plan.payload.inverse.some((w) => w.f === 'likeCount')).toBe(false);
    await admin.engine.write(admin.signer, 'data', 'Revert', plan.payload);
    expect(note(admin.engine.state, 'n1').likeCount).toBe(1);
  });

  it('F8 / B1: an op with a bad signature in a trusted admin pack is dropped, and the real file is read', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'real' });
    await admin.engine.scan();
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    const cp = JSON.parse(storage.files.get(path) as string);
    cp.ops = cp.ops.map((o: any) => (o.authorKeyId === user.keyId ? { ...o, payload: { ...o.payload, text: 'changed' } } : o));
    const { sig: _s, ...rest } = cp;
    cp.sig = await admin.signer.sign(new TextEncoder().encode(canonicalize(rest)));
    storage.files.set(path, canonicalize(cp));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    await fresh.scan();
    expect(note(fresh.state, 'n1')).toMatchObject({ text: 'real' });
  });

  it('F8 / M8: a checkpoint takes the highest seq + 1, also after a gap', async () => {
    const { storage, admin } = await world();
    storage.files.set(`data/checkpoints/${admin.keyId}/0000000005.json`, '{}');
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    expect(path.endsWith('/0000000006.json')).toBe(true);
  });

  it('F9: the browser adapter writes without the lock if the lock API fails', async () => {
    const { FsaStorage } = await import('../../src/storage/fsa');
    const files = new Map<string, Uint8Array>();
    const dir: any = {
      async getDirectoryHandle() { return dir; },
      async getFileHandle(name: string, o?: { create?: boolean }) {
        if (!files.has(name) && !o?.create) throw new DOMException('not found', 'NotFoundError');
        if (!files.has(name)) files.set(name, new Uint8Array());
        return { async createWritable() { const parts: Uint8Array[] = []; return { async write(b: ArrayBuffer) { parts.push(new Uint8Array(b)); }, async close() { files.set(name, parts[0]); } }; } };
      },
    };
    const nav = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', { configurable: true, value: { locks: { request: async () => { throw new DOMException('opaque origin', 'SecurityError'); } } } });
    try {
      await new FsaStorage(dir).writeNewBytes('data/files/x', new Uint8Array([1, 2]));
      expect(files.get('x')).toEqual(new Uint8Array([1, 2]));
    } finally {
      if (nav) Object.defineProperty(globalThis, 'navigator', nav);
    }
  });

  it('F11: the clock never goes back at the upper limit', () => {
    const c = new HlcClock(() => HLC_MAX_T + 10);
    c.observe({ t: HLC_MAX_T, c: 5 });
    expect(c.tick()).toEqual({ t: HLC_MAX_T, c: 6 });
  });

  it('F15: an op nested deeper than the limit is a parse error on every client', async () => {
    const { storage, admin, user } = await world();
    let deep: unknown = 'x';
    for (let i = 0; i < 40; i++) deep = [deep];
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'x', deep }, { t: t0, c: 0 });
    await admin.engine.scan();
    expect(admin.engine.issues.some((i) => i.kind === 'parse-error' && i.detail.includes('nested deeper'))).toBe(true);
  });
});

describe('third review regressions', () => {
  it('an error in isRevocation makes a full replay; new ops still apply', async () => {
    const { storage, user } = await world();
    const e = new Engine(storage, { ...notesDomain, isRevocation: () => { throw new Error('bug'); } });
    await e.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    await e.scan();
    await user.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'y' });
    await e.scan('quick');
    expect(note(e.state, 'n1')).toMatchObject({ text: 'y' });
  });

  it('an error in revocations gives an issue of kind domain and does not stop the scan', async () => {
    const { storage } = await world();
    const e = new Engine(storage, { ...notesDomain, revocations: () => { throw new Error('bug'); } });
    await expect(e.scan()).resolves.toBeDefined();
    expect(e.issues.some((i) => i.kind === 'domain' && i.detail.includes('revocations'))).toBe(true);
  });

  it('an error in isAdmin during the checkpoint check makes the pack untrusted; the files are read', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    await admin.engine.scan();
    await admin.engine.createCheckpoint(admin.signer, 'data');
    const e = new Engine(storage, { ...notesDomain, isAdmin: () => { throw new Error('bug'); } });
    await expect(e.scan()).resolves.toBeDefined();
    expect(note(e.state, 'n1')).toBeDefined();
    expect(e.issues.some((i) => i.kind === 'bad-checkpoint')).toBe(true);
  });

  it('a domain write with an unsafe key is rejected and does not change any prototype', async () => {
    const { storage, user } = await world();
    const bad = { ...notesDomain, catalog: { ...notesDomain.catalog, CreateNote: { ...notesDomain.catalog.CreateNote, effects: () => ({ writes: [{ e: 'note', id: 'n1', f: '__proto__', v: { polluted: true } }] }) } } };
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n1', text: 'x' }, { t: Date.parse('2026-03-01T00:00:00Z'), c: 0 });
    const e = new Engine(storage, bad);
    await e.scan();
    expect(e.audit.find((a) => a.type === 'CreateNote')).toMatchObject({ status: 'rejected' });
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(() => canonicalize(e.state)).not.toThrow();
  });

  it('the cache keeps the source of pack ops', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    await admin.engine.scan();
    await admin.engine.createCheckpoint(admin.signer, 'data');
    const thin = new MemoryStorage();
    for (const [p, v] of storage.files) if (!p.startsWith(`data/ops/${user.keyId}`)) thin.files.set(p, v);
    const e = new Engine(thin, notesDomain);
    await e.scan();
    const cache = e.exportCache();
    expect(cache.ops.some((o) => o.source === 'checkpoint')).toBe(true);
  });
});

describe('sibling review regressions', () => {
  it('a new client trusts the pack of a non-root admin (the roles scope is replayed first)', async () => {
    const { storage, admin2, user } = await world({ admin2: true });
    for (let i = 0; i < 5; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'x' });
    await admin2!.engine.scan();
    await admin2!.engine.createCheckpoint(admin2!.signer, 'data');
    let reads = 0;
    const counting = Object.assign(Object.create(Object.getPrototypeOf(storage)), storage, { read: async (p: string) => (p.startsWith('data/ops/') && reads++, storage.read(p)) });
    const fresh = new Engine(counting, notesDomain);
    await fresh.scan();
    expect(reads).toBe(0);
    expect(note(fresh.state, 'n4')).toBeDefined();
  });

  it('the pack of a revoked admin key is not trusted', async () => {
    const { storage, admin, admin2, user } = await world({ admin2: true });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    await admin2!.engine.scan();
    await admin2!.engine.createCheckpoint(admin2!.signer, 'data');
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: admin2!.keyId, cutoff: { roles: 100, data: 100 } });
    let reads = 0;
    const counting = Object.assign(Object.create(Object.getPrototypeOf(storage)), storage, { read: async (p: string) => (p.startsWith('data/ops/') && reads++, storage.read(p)) });
    const fresh = new Engine(counting, notesDomain);
    await fresh.scan();
    // The pack is not used: the engine reads the op files.
    expect(reads).toBeGreaterThan(0);
    expect(fresh.issues.some((i) => i.kind === 'bad-checkpoint' && i.detail.includes('revoked'))).toBe(true);
  });

  it('a trusted pack with a bad op gives a bad-checkpoint issue', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'real' });
    await admin.engine.scan();
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    const cp = JSON.parse(storage.files.get(path) as string);
    cp.ops = cp.ops.map((o: any) => (o.authorKeyId === user.keyId ? { ...o, payload: { ...o.payload, text: 'changed' } } : o));
    const { sig: _s, ...rest } = cp;
    cp.sig = await admin.signer.sign(new TextEncoder().encode(canonicalize(rest)));
    storage.files.set(path, canonicalize(cp));
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(note(fresh.state, 'n1')).toMatchObject({ text: 'real' });
    expect(fresh.issues.some((i) => i.kind === 'bad-checkpoint' && i.detail.includes('bad signature'))).toBe(true);
  });

  it('a conflict copy with a name that the storage refuses is listed, not read, and does not stop the scan', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'x' });
    storage.files.set(`data/ops/${user.keyId}/0000000001-a:b.json`, 'x');
    await expect(admin.engine.scan()).resolves.toBeDefined();
    expect(admin.engine.issues.some((i) => i.kind === 'unknown-file' && i.path!.includes('a:b'))).toBe(true);
  });
});

/** Decoder without the canonical check, for the test only. */
function fromB64uLoose(s: string): Uint8Array {
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of s) {
    acc = (acc << 6) | A.indexOf(ch);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}
