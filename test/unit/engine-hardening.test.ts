// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Engine hardening: the probe opId, the clock, the trust root, the write check, file size
// limits, quick-scan reads of parse errors, recompute in the queue. Synthetic data only.
import { canonicalize } from '../../src/canonical';
import type { Domain } from '../../src/domain';
import { Engine, MAX_CHECKPOINT_BYTES, MAX_OP_FILE_BYTES, MAX_TRUST_ROOT_BYTES, PROBE_OP_ID, trustRootError, AuthError, UNKNOWN_KEY_PACK_MAX_WAIT_MS, type EngineCache } from '../../src/engine';
import { HLC_MAX_C, HLC_MAX_T } from '../../src/hlc';
import { orderKey, replayFull, sortOps } from '../../src/replay';
import type { VerifiedOp } from '../../src/types';
import { filePath, TRUST_ROOT_PATH } from '../../src/paths';
import { hashCanonical } from '../../src/crypto';
import { MemoryStorage } from '../../src/storage/memory';
import { FileExistsError, FileTooLargeError, type ReadOptions, type Storage } from '../../src/storage/types';
import { actor, note, rawOp, sameUser, world } from '../helpers';
import { notesDomain, teamNotesDomain } from '../notes-domain';
import { KeyMap, verifySignature } from '../../src/verify';
import { utf8 } from '../../src/encoding';
import type { Envelope } from '../../src/types';

const kinds = (e: Engine) => e.issues.map((i) => i.kind);
const trIssue = (e: Engine) => e.issues.find((i) => i.kind === 'trust-root');

/**
 * A storage that throws FileTooLargeError for the paths in `big` (only if the caller gives
 * maxBytes, as an adapter does), and records the maxBytes of each read.
 */
function limited(storage: MemoryStorage, big: Set<string>) {
  const maxBytes = new Map<string, number | undefined>();
  const s = Object.create(storage) as Storage;
  s.read = async (p: string, opts?: ReadOptions) => {
    maxBytes.set(p, opts?.maxBytes);
    if (big.has(p) && opts?.maxBytes !== undefined) throw new FileTooLargeError(p, opts.maxBytes);
    return storage.read(p);
  };
  return { s, maxBytes };
}

describe('probe opId', () => {
  it('an op of the same key whose opId is the old probe opId and whose HLC is the highest does not block check() and write()', async () => {
    const { storage, user, clock } = await world();
    const t = clock.now() + 10 * 60_000; // in the future, but less than FUTURE_CLOCK_MS: the clock observes it
    // The old probe opId was `check-<t>-<c>` of the clock. An opId is unique for each author key, thus
    // the attack needs an op of the same key: for example of another tab or PC of the user.
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'x', text: 'x' }, { t, c: 0 }, undefined, `check-${t}-0`);
    await user.engine.scan();
    expect(note(user.engine.state, 'x')).toBeDefined();
    expect(user.engine.clock.peek()).toEqual({ t, c: 0 });
    const r = user.engine.check(user.keyId, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(r).toMatchObject({ opId: PROBE_OP_ID, status: 'applied' });
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(note(user.engine.state, 'n1')).toBeDefined();
  });

  it('no op file can have the probe opId', async () => {
    const { storage, user } = await world();
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'x', text: 'x' }, { t: Date.parse('2026-06-01T00:00:00Z'), c: 0 }, undefined, PROBE_OP_ID);
    const fresh = new Engine(storage, notesDomain);
    await fresh.scan();
    expect(fresh.issues).toEqual([expect.objectContaining({ kind: 'parse-error', detail: 'envelope.opId: id expected' })]);
  });
});

describe('clock', () => {
  it('the op of a key that nobody granted does not move the clock', async () => {
    const { storage, user } = await world();
    const outsider = await actor('outsider', storage);
    // A self-signed GrantUser: the key binding is valid, thus the chain is valid. The replay rejects it.
    const env = await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: HLC_MAX_T, c: 0 });
    const before = user.engine.clock.peek();
    await user.engine.scan();
    expect(user.engine.audit.find((a) => a.opId === env.opId)?.status).toBe('rejected');
    expect(user.engine.clock.peek()).toEqual(before);
    const own = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(own.hlc.t).toBeLessThan(Date.parse('2027-01-01T00:00:00Z'));
  });

  it('the ops of a granted user move the clock: applied, superseded and no-effect', async () => {
    const { storage, admin, user, clock } = await world();
    const t = clock.now() + 10 * 60_000;
    const cases: [string, Record<string, unknown>, string][] = [
      ['CreateNote', { id: 'x', text: 'x' }, 'applied'],
      ['EditNote', { id: 'missing', text: 'y' }, 'superseded'],
      ['Unlike', { noteId: 'x' }, 'no-effect'],
    ];
    for (let i = 0; i < cases.length; i++) {
      const [type, payload, status] = cases[i];
      const env = await rawOp(storage, user, 'data', type, payload, { t: t + i, c: 5 });
      await admin.engine.scan();
      expect(admin.engine.audit.find((a) => a.opId === env.opId)?.status).toBe(status);
      expect(admin.engine.clock.peek()).toEqual({ t: t + i, c: 5 });
    }
    const env = await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(env.hlc).toEqual({ t: t + 2, c: 6 });
  });

  it('a superseded op of a granted user with the maximum HLC does not move the clock: the admin can still revoke the key', async () => {
    const { storage, admin, user } = await world();
    const env = await rawOp(storage, user, 'data', 'EditNote', { id: 'missing', text: 'y' }, { t: HLC_MAX_T, c: HLC_MAX_C });
    const before = admin.engine.clock.peek();
    await admin.engine.scan();
    expect(admin.engine.audit.find((a) => a.opId === env.opId)?.status).toBe('superseded');
    expect(admin.engine.issues.some((i) => i.kind === 'future-clock' && i.opId === env.opId)).toBe(true);
    expect(admin.engine.clock.peek()).toEqual(before);
    await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 0 } });
    expect(admin.engine.result.cutoffs.get(user.keyId)).toEqual({ data: 0 });
    // A new engine (a restart) can write too.
    const pc2 = sameUser(admin, storage);
    await pc2.engine.scan();
    await pc2.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
  });
});

describe('trust root', () => {
  async function withNote() {
    const w = await world();
    await w.user.engine.write(w.user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await w.admin.engine.scan();
    return w;
  }

  it.each([
    ['deleted', (s: MemoryStorage) => void s.files.delete(TRUST_ROOT_PATH), 'the file is missing or not readable'],
    ['not valid JSON', (s: MemoryStorage) => void s.files.set(TRUST_ROOT_PATH, '{"v":1,"roots":['), 'not valid JSON'],
    ['a bad root', (s: MemoryStorage) => void s.files.set(TRUST_ROOT_PATH, JSON.stringify({ v: 1, roots: [{ userId: 'u', keyId: 'bad' }] })), 'roots[0].keyId'],
    ['not canonicalizable', (s: MemoryStorage) => void s.files.set(TRUST_ROOT_PATH, s.files.get(TRUST_ROOT_PATH)!.toString().replace('"v": 1', '"v": 1, "x": 1e400')), 'not canonicalizable'],
  ])('a trust root that is %s: the engine keeps the last good copy and the users', async (_, change, detail) => {
    const { storage, admin, user } = await withNote();
    const good = canonicalize(admin.engine.trustRoot);
    const state = canonicalize(admin.engine.state);
    change(storage);
    await admin.engine.scan();
    expect(canonicalize(admin.engine.trustRoot)).toBe(good);
    expect(canonicalize(admin.engine.state)).toBe(state);
    expect(trIssue(admin.engine)).toMatchObject({ path: TRUST_ROOT_PATH, detail: expect.stringContaining(detail) });
    expect(trIssue(admin.engine)!.detail).toContain('last good copy');
    expect(kinds(admin.engine).filter((k) => k !== 'trust-root')).toEqual([]);
    // The users can still write.
    await user.engine.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    await admin.engine.scan('quick');
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    // reverifyAll() also keeps the last good copy.
    await admin.engine.reverifyAll();
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    expect(trIssue(admin.engine)).toBeDefined();
  });

  it('a trust root that is too large: the engine keeps the last good copy and does not read it', async () => {
    const { storage, admin } = await withNote();
    const state = canonicalize(admin.engine.state);
    const big = new Set<string>();
    const { s, maxBytes } = limited(storage, big);
    const e = new Engine(s, notesDomain);
    await e.scan();
    expect(maxBytes.get(TRUST_ROOT_PATH)).toBe(MAX_TRUST_ROOT_BYTES);
    expect(canonicalize(e.state)).toBe(state);
    big.add(TRUST_ROOT_PATH);
    await e.scan();
    expect(canonicalize(e.state)).toBe(state);
    expect(trIssue(e)?.detail).toContain(`file is larger than ${MAX_TRUST_ROOT_BYTES} bytes`);
  });

  it('the issue goes away when the trust root is good again', async () => {
    const { storage, admin } = await withNote();
    const text = storage.files.get(TRUST_ROOT_PATH)!;
    storage.files.delete(TRUST_ROOT_PATH);
    await admin.engine.scan();
    expect(trIssue(admin.engine)).toBeDefined();
    storage.files.set(TRUST_ROOT_PATH, text);
    await admin.engine.scan();
    expect(trIssue(admin.engine)).toBeUndefined();
    expect(admin.engine.issues).toEqual([]);
  });

  /** The trust root of the storage with a second root admin. */
  async function withAdmin2(storage: MemoryStorage) {
    const admin2 = await actor('admin2', storage);
    const a = storage.files.get(TRUST_ROOT_PATH) as string;
    const tr = JSON.parse(a);
    tr.roots.push({ userId: admin2.userId, displayName: 'admin2', keyId: admin2.keyId, alg: 'Ed25519', publicKey: admin2.publicKey, cutoffs: null });
    return { admin2, a, b: JSON.stringify(tr) };
  }

  it('a changed trust root is used, scan() returns true, and the issue stays until acknowledgeTrustRoot()', async () => {
    const { storage, admin } = await withNote();
    const { admin2, b } = await withAdmin2(storage);
    storage.files.set(TRUST_ROOT_PATH, b);
    expect(await admin.engine.scan()).toBe(true); // only the trust root changed
    expect(admin.engine.trustRoot!.roots.map((r) => r.keyId)).toEqual([admin.keyId, admin2.keyId]);
    expect(trIssue(admin.engine)?.detail).toContain('trust root changed');
    await admin.engine.scan('quick');
    await admin.engine.scan();
    expect(trIssue(admin.engine)).toBeDefined(); // also after the next full scan
    // The new root admin can write.
    await admin2.engine.scan();
    await admin2.engine.write(admin2.signer, 'roles', 'SetFlag', { name: 'f', value: 1 });
    await admin.engine.scan();
    expect(admin.engine.state.scopes.roles.flag?.f).toBeDefined();
    await admin.engine.acknowledgeTrustRoot(admin.engine.trustRootHash!);
    expect(admin.engine.issues).toEqual([]);
    expect(await admin.engine.scan()).toBe(false); // nothing changed
    expect(admin.engine.issues).toEqual([]);
  });

  it('trustRootHash is the hash of the canonical trust root, and acknowledgeTrustRoot() refuses another hash', async () => {
    const { storage, admin } = await withNote();
    const { a, b } = await withAdmin2(storage);
    const e = admin.engine;
    expect(e.trustRootHash).toBe(await hashCanonical(JSON.parse(a)));
    expect(e.trustRootHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(e.trustRootChanged).toBe(false);
    storage.files.set(TRUST_ROOT_PATH, b);
    await e.scan();
    expect(e.trustRootChanged).toBe(true);
    // The admin compares the fingerprints of B. Before the click, a scan reads another change (C).
    const compared = e.trustRootHash!;
    expect(compared).toBe(await hashCanonical(JSON.parse(b)));
    const c = JSON.parse(b);
    c.roots[1].displayName = 'admin2 (renamed)';
    storage.files.set(TRUST_ROOT_PATH, JSON.stringify(c));
    await e.scan();
    await expect(e.acknowledgeTrustRoot(compared)).rejects.toThrow('the trust root changed after the check');
    expect(e.trustRootChanged).toBe(true);
    expect(trIssue(e)?.detail).toContain('trust root changed');
    // The correct hash: the issue goes.
    await e.acknowledgeTrustRoot(e.trustRootHash!);
    expect(e.trustRootChanged).toBe(false);
    expect(e.issues).toEqual([]);
    expect(canonicalize(e.exportCache().trustRoot)).toBe(canonicalize(c));
  });

  it('A → B → A: an issue for each change until the app acknowledges it', async () => {
    const { storage, admin } = await withNote();
    const { a, b } = await withAdmin2(storage);
    const e = admin.engine;
    storage.files.set(TRUST_ROOT_PATH, b);
    await e.scan();
    expect(trIssue(e)).toBeDefined();
    storage.files.set(TRUST_ROOT_PATH, a);
    expect(await e.scan()).toBe(true);
    // Back to the known trust root: the issue stays, with a short text.
    expect(trIssue(e)?.detail).toBe('the trust root changed and then changed back to the known trust root. Acknowledge it after a check.');
    expect(e.trustRootChanged).toBe(true);
    await e.acknowledgeTrustRoot(e.trustRootHash!);
    expect(e.trustRootChanged).toBe(false);
    expect(trIssue(e)).toBeUndefined();
    storage.files.set(TRUST_ROOT_PATH, b);
    await e.scan();
    expect(trIssue(e)).toBeDefined();
    await e.acknowledgeTrustRoot(e.trustRootHash!);
    expect(trIssue(e)).toBeUndefined();
    storage.files.set(TRUST_ROOT_PATH, a);
    await e.scan();
    expect(trIssue(e)?.detail).toContain('trust root changed');
    await e.acknowledgeTrustRoot(e.trustRootHash!);
    expect(e.issues).toEqual([]);
  });

  it('first start: a missing trust root is an issue only if op files exist, an invalid trust root is an issue', async () => {
    const { storage } = await withNote();
    const text = storage.files.get(TRUST_ROOT_PATH)!;
    const empty = new Engine(new MemoryStorage(), notesDomain);
    await empty.scan();
    expect(empty.issues).toEqual([]);
    storage.files.delete(TRUST_ROOT_PATH);
    const e = new Engine(storage, notesDomain);
    await e.scan();
    expect(e.trustRoot).toBeNull();
    expect(trIssue(e)?.detail).toContain('the file is missing, but op files exist');
    storage.files.set(TRUST_ROOT_PATH, 'garbage');
    const e2 = new Engine(storage, notesDomain);
    await e2.scan();
    expect(e2.trustRoot).toBeNull();
    expect(e2.issues.filter((i) => i.kind === 'trust-root')).toEqual([expect.objectContaining({ detail: 'trust root: not valid JSON' })]);
    // A quick scan that finds the first good trust root replays with it and returns true.
    storage.files.set(TRUST_ROOT_PATH, text);
    expect(await e.scan('quick')).toBe(true);
    expect(e.trustRoot).not.toBeNull();
    expect(note(e.state, 'n1')).toBeDefined();
    expect(e.issues).toEqual([]);
  });

  it('the cache (v 3) keeps the known trust root: a change or a deletion while the app was closed gives the issue', async () => {
    const { storage, admin } = await withNote();
    const { admin2, a, b } = await withAdmin2(storage);
    const cache: EngineCache = JSON.parse(JSON.stringify(admin.engine.exportCache()));
    expect(cache.v).toBe(3);
    expect(canonicalize(cache.trustRoot)).toBe(canonicalize(JSON.parse(a)));
    // Changed while the app was closed.
    storage.files.set(TRUST_ROOT_PATH, b);
    const e = new Engine(storage, notesDomain);
    await e.importCache(cache);
    expect(trIssue(e)?.detail).toContain('trust root changed');
    await e.scan();
    expect(e.trustRoot!.roots.map((r) => r.keyId)).toContain(admin2.keyId);
    expect(trIssue(e)).toBeDefined();
    // Deleted while the app was closed: the engine uses the cached copy.
    storage.files.delete(TRUST_ROOT_PATH);
    const e2 = new Engine(storage, notesDomain);
    await e2.importCache(cache);
    await e2.scan();
    expect(canonicalize(e2.trustRoot)).toBe(canonicalize(JSON.parse(a)));
    expect(trIssue(e2)?.detail).toContain('last good copy');
    expect(note(e2.state, 'n1')).toBeDefined();
    // After the acknowledgment, the cache contains the new trust root.
    storage.files.set(TRUST_ROOT_PATH, b);
    await e.acknowledgeTrustRoot(e.trustRootHash!);
    expect(canonicalize(e.exportCache().trustRoot)).toBe(canonicalize(JSON.parse(b)));
  });

  it('a cache of version 2 is ignored', async () => {
    const { storage, admin } = await withNote();
    const old = { ...admin.engine.exportCache(), v: 2 } as unknown as EngineCache;
    const e = new Engine(storage, notesDomain);
    await e.importCache(old);
    expect(e.knownOps()).toEqual([]);
    expect(e.trustRoot).toBeNull();
  });

  it('trustRootError checks the structure', () => {
    const root = { userId: 'u-a', displayName: 'A', keyId: 'k' + 'a'.repeat(24), alg: 'Ed25519', publicKey: 'x', cutoffs: null };
    const tr = (r: Record<string, unknown>) => ({ v: 1, roots: [{ ...root, ...r }] });
    expect(trustRootError(tr({}))).toBeNull();
    expect(trustRootError(tr({ cutoffs: { data: 0, 'team:a': 3 } }))).toBeNull();
    expect(trustRootError({ v: 1, roots: [] })).toBeNull();
    expect(trustRootError(null)).not.toBeNull();
    expect(trustRootError({ v: 2, roots: [] })).not.toBeNull();
    expect(trustRootError({ v: 1, roots: {} })).not.toBeNull();
    expect(trustRootError({ v: 1, roots: [null] })).not.toBeNull();
    for (const bad of [
      { userId: '' },
      { userId: '__proto__' },
      { keyId: 'K' + 'a'.repeat(24) },
      { alg: 'RSA' },
      { publicKey: 1 },
      { displayName: null },
      { cutoffs: undefined },
      { cutoffs: [] },
      { cutoffs: { data: -1 } },
      { cutoffs: { data: 1.5 } },
      { cutoffs: { data: '1' } },
      { cutoffs: JSON.parse('{"__proto__": 1}') },
    ])
      expect(trustRootError(tr(bad))).not.toBeNull();
  });
});

describe('write() checks the op after it reads the new own files', () => {
  it('the check uses the ops that another engine with the same key wrote', async () => {
    const { storage, user } = await world();
    const pc2 = sameUser(user, storage);
    await pc2.engine.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    // pc2 does not know n1 yet. An old check would say "superseded: no active note".
    const env = await pc2.engine.write(user.signer, 'data', 'EditNote', { id: 'n1', text: 'b' });
    expect(env.seq).toBe(2);
    expect(note(pc2.engine.state, 'n1')).toMatchObject({ text: 'b' });
  });

  it('the check uses the seq that the write takes (a revocation cutoff)', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    // Another person writes garbage under seq 2 of the user. The admin revokes the key after seq 2.
    storage.files.set(filePath('data', 'ops', user.keyId, 2), 'garbage');
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 2 } });
    await user.engine.scan();
    // The public check uses the next seq (2): applied. The write takes seq 3: rejected.
    expect(user.engine.check(user.keyId, 'data', 'CreateNote', { id: 'n2', text: 'b' }).status).toBe('applied');
    await expect(user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' })).rejects.toThrow(AuthError);
    expect(storage.files.has(filePath('data', 'ops', user.keyId, 3))).toBe(false);
  });
});

describe('validHeads', () => {
  it('splits at the last "|": a scope can contain "|"', async () => {
    const PIPE = 'd|x';
    const domain: Domain = {
      ...teamNotesDomain,
      scopeDir: (s) => (s === PIPE ? 'pipe' : notesDomain.scopeDir(s)),
      scopeFromDir: (d) => (d === 'pipe' ? PIPE : notesDomain.scopeFromDir(d)),
      scopeKind: (s) => (s === PIPE ? 'team' : s),
      async discoverScopes(storage) {
        const base = await notesDomain.discoverScopes(storage);
        return { ...base, scopes: [...base.scopes, PIPE] };
      },
    };
    const { storage, user, clock } = await world();
    const e = new Engine(storage, domain, { now: clock.now });
    await e.scan();
    await e.write(user.signer, PIPE, 'CreateNote', { id: 'n1', text: 'a' });
    expect(e.state.scopes[PIPE]?.note?.n1).toBeDefined();
    expect(e.validHeads()).toContainEqual(expect.objectContaining({ scope: PIPE, keyId: user.keyId, seq: 1 }));
    for (const h of e.validHeads()) expect(h.keyId).toMatch(/^k[a-z2-7]{24}$/);
  });
});

describe('recompute() runs in the queue', () => {
  it('waits for a running scan', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    let open!: () => void;
    const gate = new Promise<void>((r) => (open = r));
    const s = Object.create(storage) as Storage;
    s.read = async (p: string, o?: ReadOptions) => {
      await gate;
      return storage.read(p, o);
    };
    const e = new Engine(s, notesDomain);
    const order: string[] = [];
    const scan = e.scan().then(() => order.push('scan'));
    const re = e.recompute().then(() => order.push('recompute'));
    await new Promise((r) => setTimeout(r, 10));
    expect(order).toEqual([]);
    open();
    await Promise.all([scan, re]);
    expect(order).toEqual(['scan', 'recompute']);
    expect(note(e.state, 'n1')).toBeDefined();
  });
});

describe('size limits', () => {
  it('a too large op file is a parse error, the scan goes on, and each read has a limit', async () => {
    const { storage, user } = await world();
    for (let i = 1; i <= 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    const big = filePath('data', 'ops', user.keyId, 4);
    await storage.writeNew(big, 'x');
    const { s, maxBytes } = limited(storage, new Set([big]));
    const e = new Engine(s, notesDomain);
    await e.scan();
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'parse-error', path: big, detail: `file is larger than ${MAX_OP_FILE_BYTES} bytes` })]);
    expect(note(e.state, 'n3')).toBeDefined();
    expect(maxBytes.get(filePath('data', 'ops', user.keyId, 1))).toBe(MAX_OP_FILE_BYTES);
    // A quick scan and a write (the own folder) also read with the limit, and do not fail.
    await e.scan('quick');
    const pc2 = sameUser(user, s);
    await pc2.engine.scan();
    const env = await pc2.engine.write(user.signer, 'data', 'CreateNote', { id: 'n5', text: 'a' });
    expect(env.seq).toBe(5);
    expect([...maxBytes.values()].every((m) => m !== undefined)).toBe(true);
    await e.scan('quick');
    expect(note(e.state, 'n5')).toBeDefined();
  });

  it('a too large conflict copy is only an unknown file', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const copy = `data/ops/${user.keyId}/0000000001-PC2.json`;
    await storage.writeNew(copy, 'x');
    const { s, maxBytes } = limited(storage, new Set([copy]));
    const e = new Engine(s, notesDomain);
    await e.scan();
    expect(maxBytes.get(copy)).toBe(MAX_OP_FILE_BYTES);
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'unknown-file', path: copy })]);
    expect(note(e.state, 'n1')).toBeDefined();
  });

  it('a too large checkpoint is a bad checkpoint, and the engine reads the op files', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    await admin.engine.scan();
    const cp = await admin.engine.createCheckpoint(admin.signer, 'data');
    const { s, maxBytes } = limited(storage, new Set([cp]));
    const e = new Engine(s, notesDomain);
    await e.scan();
    expect(maxBytes.get(cp)).toBe(MAX_CHECKPOINT_BYTES);
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'bad-checkpoint', path: cp, detail: `file is larger than ${MAX_CHECKPOINT_BYTES} bytes` })]);
    expect(canonicalize(e.state)).toBe(canonicalize(admin.engine.state));
  });
});

describe('quick scan reads a parse error again', () => {
  it('a file that was partial in the last scan is applied when it is complete', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    await admin.engine.scan();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    const p = filePath('data', 'ops', user.keyId, 2);
    const full = storage.files.get(p) as string;
    storage.files.set(p, full.slice(0, 40)); // the sync tool wrote only a part of the file
    await admin.engine.scan('quick');
    expect(kinds(admin.engine)).toContain('parse-error');
    storage.files.set(p, full);
    expect(await admin.engine.scan('quick')).toBe(true);
    expect(note(admin.engine.state, 'n2')).toBeDefined();
    expect(admin.engine.issues).toEqual([]);
  });
});

describe('small fixes', () => {
  it('the engine does not change the missing list of the domain', async () => {
    const missing = Object.freeze([] as string[]) as string[];
    const domain: Domain = { ...notesDomain, discoverScopes: async () => ({ scopes: ['roles', 'data'], missing, unknown: [] }) };
    const e = new Engine(new MemoryStorage(), domain);
    await e.scan();
    await e.scan();
    expect(missing).toEqual([]);
    expect(e.missing).toEqual(['roles', 'data']);
  });

  it('createCheckpoint retries with the next number when another tab wrote that number', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const s = Object.create(storage) as Storage;
    let race = true;
    s.writeNew = async (p: string, data: string) => {
      // Another tab writes the same checkpoint number between the list and the write.
      if (race && p.includes('/checkpoints/')) (race = false), await storage.writeNew(p, 'other tab');
      return storage.writeNew(p, data);
    };
    const e = new Engine(s, notesDomain);
    await e.scan();
    const path = await e.createCheckpoint(admin.signer, 'data');
    expect(path).toBe(filePath('data', 'checkpoints', admin.keyId, 2));
    expect(race).toBe(false);
    await expect(storage.writeNew(path, 'x')).rejects.toThrow(FileExistsError);
  });
});

describe('rejected ops at the end of the order (review: incremental take-back)', () => {
  const summary = (e: Engine) => ({
    state: canonicalize(e.state),
    audit: e.audit.map((a) => `${a.authorKeyId} ${a.seq} ${a.status} ${a.reason ?? ''}`),
    issues: e.issues.map((i) => canonicalize(i)),
  });

  it('an outsider op with the maximum HLC does not make each write a full replay', async () => {
    const { storage, user } = await world();
    const outsider = await actor('outsider', storage);
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: HLC_MAX_T, c: 0 });
    await user.engine.scan();
    const full = user.engine.stats.fullReplays;
    for (let i = 0; i < 5; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    expect(user.engine.stats.fullReplays).toBe(full);
    expect(user.engine.stats.takenBack).toBe(5);
    const ref = new Engine(storage, notesDomain);
    await ref.scan();
    expect(summary(user.engine)).toEqual(summary(ref));
  });

  it('an applied far-future op still makes a full replay (a new op sorts before it)', async () => {
    const { storage, admin, user, clock } = await world();
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'x', text: 'x' }, { t: clock.now() + 2 * 3600_000, c: 0 }, new Date(clock.now()).toISOString());
    await admin.engine.scan();
    expect(admin.engine.issues.map((i) => i.kind)).toEqual(['future-clock']);
    const full = admin.engine.stats.fullReplays;
    await admin.engine.write(admin.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    expect(admin.engine.stats.fullReplays).toBe(full + 1);
  });

  it('takeBackRejected + apply gives the same result as a full replay (revoked, unknown key, duplicate opId)', async () => {
    const { storage, admin, admin2, user, clock } = await world({ admin2: true });
    const wall = () => new Date(clock.now()).toISOString();
    const base = clock.now();
    const T1 = base + 10 * 3600_000;
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'u1', text: 'a' });
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 1 } });
    // The tail: a revoked op (it moves maxT), an op of an unknown key, an op with a duplicate opId.
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'rv', text: 'r' }, { t: T1, c: 0 }, wall());
    const outsider = await actor('outsider', storage);
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: T1 + 10, c: 0 }, wall(), 'dup');
    await rawOp(storage, outsider, 'roles', 'SetFlag', { name: 'o', value: 1 }, { t: T1 + 30, c: 0 }, wall(), 'dup');
    // Late ops: a normal op, a far-future op (its future-clock issue depends on maxT), an op between 2 tail ops.
    const A = await rawOp(storage, admin, 'data', 'CreateNote', { id: 'a', text: 'a' }, { t: base + 60_000, c: 0 }, wall());
    const F = await rawOp(storage, admin2!, 'data', 'CreateNote', { id: 'f', text: 'f' }, { t: base + 5 * 3600_000, c: 0 }, wall());
    const M = await rawOp(storage, admin2!, 'data', 'CreateNote', { id: 'm', text: 'm' }, { t: T1 + 20, c: 0 }, wall());
    const ref = new Engine(storage, notesDomain);
    await ref.scan();
    expect(ref.audit.slice(-6).map((a) => `${a.status} ${a.reason ?? ''}`)).toEqual([
      'applied ',
      'applied ',
      'rejected key revoked after seq 1 in data',
      'rejected unknown key',
      'applied ',
      'rejected duplicate opId',
    ]);
    const all: VerifiedOp[] = ref.audit.map((a) => ({ env: ref.knownOps().find((e) => e.authorKeyId === a.authorKeyId && e.seq === a.seq && e.scope === a.scope)!, hash: a.hash }));
    const opts = { domain: notesDomain, trustRoot: ref.trustRoot, validKeyBindings: ref.validKeyBindings };
    const full = replayFull(all, opts);
    const result = (r: ReturnType<typeof replayFull>) => canonicalize({ state: r.state, audit: r.audit, issues: r.issues, applied: [...r.applied.keys()], last: r.last, cutoffs: [...r.cutoffs] });
    for (const [late, back] of [
      [[A, F, M], 3],
      [[M], 1],
      [[F, M], 3],
    ] as const) {
      const isLate = (v: VerifiedOp) => late.some((l) => l.authorKeyId === v.env.authorKeyId && l.seq === v.env.seq && l.scope === v.env.scope);
      const r = replayFull(all.filter((v) => !isLate(v)), opts);
      const tail = r.rejectedTail();
      expect(tail.length).toBe(3);
      const lateOps = sortOps(all.filter(isLate));
      expect(tail.filter((t) => orderKey(t.op.env, lateOps[0].env) > 0).length).toBe(back);
      const again = r.takeBackRejected(back);
      for (const v of sortOps([...lateOps, ...again])) r.apply(v);
      expect(result(r)).toBe(result(full));
      // The next op gets the same result and the same issues (the opIds and maxT are the same).
      const next = { env: { ...F, opId: 'next', hlc: { t: T1 + 40, c: 0 }, seq: 99 }, hash: 'next' };
      const ref2 = replayFull(all, opts);
      expect(canonicalize(r.apply(next))).toBe(canonicalize(ref2.apply(next)));
      expect(canonicalize(r.issues)).toBe(canonicalize(ref2.issues));
    }
    expect(() => full.takeBackRejected(4)).toThrow();
  });
});

describe('checkpoint numbers and partial checkpoints (review)', () => {
  it('a bad file with the highest number does not move the checkpoint numbers after a full scan', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const big = filePath('data', 'checkpoints', admin.keyId, 9_999_999_999);
    await storage.writeNew(big, 'garbage');
    // The engine does not know the file yet: the next number would have 11 digits.
    await expect(admin.engine.createCheckpoint(admin.signer, 'data')).rejects.toThrow('no free checkpoint number');
    await admin.engine.scan();
    expect(admin.engine.issues.find((i) => i.path === big)?.kind).toBe('bad-checkpoint');
    expect(await admin.engine.createCheckpoint(admin.signer, 'data')).toBe(filePath('data', 'checkpoints', admin.keyId, 1));
    expect(await admin.engine.createCheckpoint(admin.signer, 'data')).toBe(filePath('data', 'checkpoints', admin.keyId, 2));
  });

  it('a partial checkpoint file is read again in the next full scan', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    await admin.engine.scan();
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    const text = storage.files.get(path) as string;
    storage.files.set(path, text.slice(0, 100));
    const e = new Engine(storage, notesDomain);
    await e.scan();
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'bad-checkpoint', path, detail: 'not valid JSON' })]);
    storage.files.set(path, text);
    expect(await e.scan()).toBe(true);
    expect(e.issues).toEqual([]);
    expect(e.checkpointStats(['data'])[0].checkpoints).toBe(1);
  });
});

describe('read budget of files that are not valid JSON (review)', () => {
  /** A storage that counts the reads of each path. */
  function counting(storage: MemoryStorage) {
    const reads = new Map<string, number>();
    const s = Object.create(storage) as Storage;
    s.read = async (p: string, o?: ReadOptions) => {
      reads.set(p, (reads.get(p) ?? 0) + 1);
      return storage.read(p, o);
    };
    return { s, reads };
  }

  /** A clock that changes only when the test sets it. */
  const manual = () => {
    let t = Date.parse('2026-01-01T09:00:00Z');
    return { now: () => t, add: (ms: number) => void (t += ms) };
  };

  it('a static op file that is not valid JSON: 3 reads, then a read only after the wait (5 s × 2^n), and reverifyAll() resets it', async () => {
    const { storage, user } = await world();
    for (let i = 0; i < 2; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    const bad = filePath('data', 'ops', user.keyId, 3);
    await storage.writeNew(bad, 'garbage');
    const { s, reads } = counting(storage);
    const clock = manual();
    const e = new Engine(s, notesDomain, { now: clock.now });
    for (let i = 0; i < 3; i++) await e.scan();
    for (let i = 0; i < 3; i++) await e.scan('quick');
    expect(reads.get(bad)).toBe(3);
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'parse-error', path: bad, detail: 'not valid JSON' })]);
    clock.add(4_999);
    await e.scan();
    expect(reads.get(bad)).toBe(3);
    clock.add(1);
    await e.scan();
    await e.scan('quick');
    expect(reads.get(bad)).toBe(4); // 1 read, then the next wait (10 s)
    clock.add(9_999);
    await e.scan('quick');
    expect(reads.get(bad)).toBe(4);
    clock.add(1);
    await e.scan('quick');
    expect(reads.get(bad)).toBe(5);
    await e.reverifyAll();
    expect(reads.get(bad)).toBe(6);
    await e.scan();
    expect(reads.get(bad)).toBe(7); // the budget starts again
  });

  it('the wait is at most 10 minutes', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n0', text: 'a' });
    const bad = filePath('data', 'ops', user.keyId, 2);
    await storage.writeNew(bad, 'garbage');
    const { s, reads } = counting(storage);
    const clock = manual();
    const e = new Engine(s, notesDomain, { now: clock.now });
    for (let i = 0; i < 20; i++) {
      await e.scan();
      clock.add(600_000);
    }
    expect(reads.get(bad)).toBe(20);
  });

  it('a clock that goes back ends the wait', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n0', text: 'a' });
    const bad = filePath('data', 'ops', user.keyId, 2);
    await storage.writeNew(bad, 'garbage');
    const { s, reads } = counting(storage);
    const clock = manual();
    const e = new Engine(s, notesDomain, { now: clock.now });
    for (let i = 0; i < 4; i++) await e.scan();
    expect(reads.get(bad)).toBe(3);
    clock.add(-3_600_000); // for example an NTP correction of a clock that was 1 hour ahead
    await e.scan();
    expect(reads.get(bad)).toBe(4);
  });

  it('a partial op file with the same content in 4 scans is applied after the wait when it is complete', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const clock = manual();
    const e = new Engine(storage, notesDomain, { now: clock.now });
    await e.scan();
    const env = await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    const p2 = filePath('data', 'ops', user.keyId, env.seq);
    const full = storage.files.get(p2) as string;
    storage.files.set(p2, full.slice(0, 30)); // the sync stopped in the middle of the file
    for (let i = 0; i < 4; i++) await e.scan();
    storage.files.set(p2, full);
    await e.scan();
    expect(note(e.state, 'n2')).toBeUndefined(); // the wait did not end yet
    clock.add(5_000);
    await e.scan();
    expect(note(e.state, 'n2')).toMatchObject({ text: 'b' });
    expect(e.issues).toEqual([]);
  });

  it('a large op file that syncs slowly (partial in more than 3 scans) is applied when it is complete', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const clock = manual();
    const e = new Engine(storage, notesDomain, { now: clock.now });
    await e.scan();
    const envs = [];
    for (const id of ['n2', 'n3']) envs.push(await user.engine.write(user.signer, 'data', 'CreateNote', { id, text: 'x'.repeat(90) }));
    const p2 = filePath('data', 'ops', user.keyId, envs[0].seq);
    const full = storage.files.get(p2) as string;
    for (const [i, n] of [10, 40, 80, 120, 160].entries()) {
      storage.files.set(p2, full.slice(0, n));
      await e.scan(i % 2 ? 'quick' : 'full');
      expect(e.issues.find((x) => x.path === p2)?.detail).toBe('not valid JSON');
    }
    storage.files.set(p2, full);
    await e.scan('quick');
    expect(note(e.state, 'n2')).toBeDefined();
    expect(note(e.state, 'n3')).toBeDefined();
    expect(e.issues).toEqual([]);
  });

  it('a static checkpoint that is not valid JSON: 3 reads, then a read after the wait; a changing checkpoint is read at each full scan', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    await admin.engine.scan();
    const bad = filePath('data', 'checkpoints', admin.keyId, 1);
    await storage.writeNew(bad, 'garbage');
    const { s, reads } = counting(storage);
    const clock = manual();
    const e = new Engine(s, notesDomain, { now: clock.now });
    for (let i = 0; i < 5; i++) await e.scan();
    expect(reads.get(bad)).toBe(3);
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'bad-checkpoint', path: bad, detail: 'not valid JSON' })]);
    clock.add(5_000);
    await e.scan();
    expect(reads.get(bad)).toBe(4);
    await e.reverifyAll();
    expect(reads.get(bad)).toBe(5);
    // A checkpoint that another admin PC still writes: partial in 5 full scans, then complete.
    const path = await admin.engine.createCheckpoint(admin.signer, 'data');
    const text = storage.files.get(path) as string;
    for (const n of [10, 40, 80, 120, 160]) {
      storage.files.set(path, text.slice(0, n));
      await e.scan();
    }
    expect(reads.get(path)).toBe(5);
    storage.files.set(path, text);
    await e.scan();
    expect(e.issues.filter((i) => i.path === path)).toEqual([]);
    expect(e.checkpointStats(['data'])[0].checkpoints).toBe(1);
  });
});

describe('an issue after the last op of a full replay (review)', () => {
  it('the engine does a full replay, so the order of the issues is the same as in a full replay', async () => {
    const broken: Domain = {
      ...notesDomain,
      revocations: () => {
        throw new Error('boom');
      },
    };
    const { storage, user, clock } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const e = new Engine(storage, broken, { now: clock.now });
    await e.scan();
    expect(e.issues.at(-1)).toMatchObject({ kind: 'domain', detail: 'revocations: internal error: boom' });
    const full = e.stats.fullReplays;
    expect(await e.scan('quick')).toBe(false); // nothing new: no replay
    expect(e.stats.fullReplays).toBe(full);
    // A new op with an issue (future-clock): a full replay puts its issue before the domain issue.
    await rawOp(storage, user, 'data', 'CreateNote', { id: 'n2', text: 'b' }, { t: clock.now() + 2 * 3600_000, c: 0 }, new Date(clock.now()).toISOString());
    await e.scan('quick');
    expect(e.stats.fullReplays).toBe(full + 1);
    const ref = new Engine(storage, broken, { now: clock.now });
    await ref.scan();
    expect(e.result.issues.map((i) => canonicalize(i))).toEqual(ref.result.issues.map((i) => canonicalize(i)));
    expect(e.result.issues.map((i) => i.kind)).toEqual(['future-clock', 'domain']);
  });
});

describe('third review', () => {
  /** A storage that counts the reads of each path. */
  function counting(storage: MemoryStorage) {
    const reads = new Map<string, number>();
    const s = Object.create(storage) as Storage;
    s.read = async (p: string, o?: ReadOptions) => {
      reads.set(p, (reads.get(p) ?? 0) + 1);
      return storage.read(p, o);
    };
    return { s, reads };
  }

  it('verifySignature does not compute the signing bytes for an unknown key', async () => {
    // An op that JCS refuses: a computation of the signing bytes throws.
    const env = { v: 1, opId: 'x', scope: 'data', authorKeyId: 'k' + 'a'.repeat(24), seq: 1, prevHash: null, hlc: { t: 1, c: 0 }, wallTime: '', type: 'CreateNote', payload: { x: Infinity }, sig: 'AAAA' } as unknown as Envelope;
    expect(await verifySignature(env, new KeyMap())).toBe('unknown-key');
    let called = 0;
    expect(await new KeyMap().verify('k' + 'a'.repeat(24), 'AAAA', () => (called++, new Uint8Array()))).toBe('unknown-key');
    expect(called).toBe(0);
  });

  /** A clock that changes only when the test sets it. */
  const manualClock = () => {
    let t = Date.parse('2026-01-01T09:00:00Z');
    return { now: () => t, add: (ms: number) => void (t += ms) };
  };

  /** Writes a checkpoint of the data scope, signed by `a`, with the given ops. */
  async function writePack(storage: MemoryStorage, a: { keyId: string; signer: { sign(b: Uint8Array): Promise<string> } }, ops: unknown[]) {
    const rest = { v: 1, scope: 'data', authorKeyId: a.keyId, seq: 1, hlc: { t: 1, c: 0 }, wallTime: '2026-01-01T00:00:00.000Z', frontier: {}, ops };
    const path = filePath('data', 'checkpoints', a.keyId, 1);
    await storage.writeNew(path, canonicalize({ ...rest, sig: await a.signer.sign(utf8(canonicalize(rest))) }));
    return path;
  }

  it('a checkpoint of an unknown key: the engine keeps nothing of it, and reads it again only after the wait', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const outsider = await actor('outsider', storage);
    const cpPath = await writePack(storage, outsider, [JSON.parse(storage.files.get(filePath('data', 'ops', user.keyId, 1)) as string)]);
    const { s, reads } = counting(storage);
    const clock = manualClock();
    const e = new Engine(s, notesDomain, { now: clock.now });
    const keys = (e as unknown as { keys: KeyMap }).keys;
    const orig = keys.verify.bind(keys);
    let calls = 0;
    // Count the pack checks only (the signed bytes of a pack are a Uint8Array, of an op a function).
    keys.verify = (k, sig, data) => (k === outsider.keyId && data instanceof Uint8Array && calls++, orig(k, sig, data));
    const internals = e as unknown as { pendingCheckpoints: { path: string }[]; checkpointInfo: Map<string, unknown> };
    await e.scan();
    expect(reads.get(cpPath)).toBe(1);
    expect(internals.pendingCheckpoints.some((x) => x.path === cpPath)).toBe(false);
    expect(internals.checkpointInfo.has(cpPath)).toBe(false);
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'bad-checkpoint', path: cpPath, detail: 'the key of the checkpoint author is not known (yet): the engine reads the pack again later' })]);
    expect(e.checkpointStats(['data'])[0].checkpoints).toBe(0);
    await e.scan();
    await e.recompute();
    expect(reads.get(cpPath)).toBe(1);
    clock.add(4_999);
    await e.scan();
    expect(reads.get(cpPath)).toBe(1);
    clock.add(1);
    await e.scan();
    expect(reads.get(cpPath)).toBe(2); // the next wait is 10 s
    clock.add(9_999);
    await e.scan();
    expect(reads.get(cpPath)).toBe(2);
    clock.add(1);
    await e.scan();
    expect(reads.get(cpPath)).toBe(3);
    expect(calls).toBe(0);
    // The key becomes known (a self-signed GrantUser): the next full scan reads the pack at once
    // (no wait) and checks it 1 time.
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: Date.parse('2026-01-02T00:00:00Z'), c: 0 });
    await e.scan();
    expect(reads.get(cpPath)).toBe(4);
    expect(calls).toBe(1);
    expect(internals.pendingCheckpoints.filter((x) => x.path === cpPath)).toEqual([{ path: cpPath, authorKeyId: outsider.keyId }]);
    expect(e.issues.find((i) => i.path === cpPath)?.detail).toBe('checkpoint author is not an admin');
    // The pack is not used: the engine keeps no list of its op paths.
    expect(internals.checkpointInfo.has(cpPath)).toBe(false);
    clock.add(600_000);
    await e.scan();
    expect(reads.get(cpPath)).toBe(4); // seen: not read again
    expect(note(e.state, 'n1')).toBeDefined();
  });

  it('a pack whose key becomes known later is checked and used after the next read', async () => {
    const { storage, admin, user } = await world();
    for (let i = 0; i < 3; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    const a2 = await actor('a2', storage);
    const userOps = [1, 2, 3].map((n) => JSON.parse(storage.files.get(filePath('data', 'ops', user.keyId, n)) as string));
    const cpPath = await writePack(storage, a2, userOps);
    const clock = manualClock();
    const e = new Engine(storage, notesDomain, { now: clock.now });
    await e.scan();
    expect(e.issues.map((i) => i.path)).toEqual([cpPath]);
    expect(e.checkpointStats(['data'])[0].checkpoints).toBe(0);
    // The admin grants a2 admin rights. The next full scan (no wait: the key is known) checks and uses the pack.
    await admin.engine.scan();
    await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: a2.userId, keyId: a2.keyId, publicKey: a2.publicKey, admin: true });
    await e.scan();
    expect(e.issues).toEqual([]);
    expect(e.checkpointStats(['data'])[0]).toMatchObject({ checkpoints: 1, notInCheckpoint: 0 });
  });

  it('a checkpoint that JCS refuses (1e400 in an op) does not stop the scan', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const cpPath = filePath('data', 'checkpoints', admin.keyId, 1);
    await storage.writeNew(cpPath, `{"v":1,"scope":"data","authorKeyId":"${admin.keyId}","seq":1,"hlc":{"t":1,"c":0},"wallTime":"2026-01-01T00:00:00.000Z","frontier":{},"ops":[{"x":1e400}],"sig":"AAAA"}`);
    const e = new Engine(storage, notesDomain);
    await e.scan();
    expect(note(e.state, 'n1')).toBeDefined();
    expect(e.issues).toEqual([expect.objectContaining({ kind: 'bad-checkpoint', path: cpPath, detail: 'checkpoint signature is not valid' })]);
  });

  it('a rejected revocation op with the maximum HLC does not make each write a full replay', async () => {
    const { storage, user } = await world();
    const outsider = await actor('outsider', storage);
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: HLC_MAX_T - 1, c: 0 });
    await rawOp(storage, outsider, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 0 } }, { t: HLC_MAX_T, c: 0 });
    await user.engine.scan();
    expect(user.engine.audit.slice(-2).map((a) => a.status)).toEqual(['rejected', 'rejected']);
    const full = user.engine.stats.fullReplays;
    for (let i = 0; i < 5; i++) await user.engine.write(user.signer, 'data', 'CreateNote', { id: `n${i}`, text: 'a' });
    expect(user.engine.stats.fullReplays).toBe(full);
    expect(user.engine.stats.takenBack).toBe(10);
    const ref = new Engine(storage, notesDomain);
    await ref.scan();
    expect(canonicalize(user.engine.state)).toBe(canonicalize(ref.state));
    expect(user.engine.audit.map((a) => `${a.hash} ${a.status}`)).toEqual(ref.audit.map((a) => `${a.hash} ${a.status}`));
    expect(user.engine.issues.map((i) => canonicalize(i))).toEqual(ref.issues.map((i) => canonicalize(i)));
  });

  it('a rejected revocation op in the tail that applies after a new op: a full replay with the new cutoffs', async () => {
    const { storage, admin, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const a2 = await actor('a2', storage);
    // a2 (not granted yet) revokes the key of the user, with a far-future HLC: rejected (unknown key).
    const far = Date.parse('2026-06-01T00:00:00Z');
    await rawOp(storage, a2, 'roles', 'GrantUser', { userId: a2.userId, keyId: a2.keyId, publicKey: a2.publicKey, admin: true }, { t: far, c: 0 });
    await rawOp(storage, a2, 'roles', 'RevokeKey', { keyId: user.keyId, cutoff: { data: 0 } }, { t: far + 1, c: 0 });
    await admin.engine.scan();
    expect(admin.engine.result.cutoffs.has(user.keyId)).toBe(false);
    const full = admin.engine.stats.fullReplays;
    // The admin grants a2 (it sorts before the tail). The RevokeKey of a2 applies now.
    const { incrementalOps, takenBack } = admin.engine.stats;
    await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: a2.userId, keyId: a2.keyId, publicKey: a2.publicKey, admin: true });
    expect(admin.engine.stats.fullReplays).toBe(full + 1);
    // The full replay replaced the incremental run: the counters do not count it.
    expect(admin.engine.stats).toMatchObject({ incrementalOps, takenBack });
    expect(admin.engine.result.cutoffs.get(user.keyId)).toEqual({ data: 0 });
    expect(note(admin.engine.state, 'n1')).toBeUndefined();
    const ref = new Engine(storage, notesDomain);
    await ref.scan();
    expect(canonicalize(admin.engine.state)).toBe(canonicalize(ref.state));
    expect(admin.engine.audit.map((a) => `${a.hash} ${a.status}`)).toEqual(ref.audit.map((a) => `${a.hash} ${a.status}`));
  });

  it('write() refuses an op that is larger than the op file limit, and writes no file', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const limit = (storage.files.get(filePath('data', 'ops', user.keyId, 1)) as string).length + 20;
    (user.engine as unknown as { maxOpFileBytes: number }).maxOpFileBytes = limit;
    await expect(user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'x'.repeat(100) })).rejects.toThrow(`the maximum is ${limit} bytes`);
    expect(storage.files.has(filePath('data', 'ops', user.keyId, 2))).toBe(false);
  });

  it('write() reads again only "not valid JSON" files in the 16 numbers above the own last op', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const p = (n: number) => filePath('data', 'ops', user.keyId, n);
    await storage.writeNew(p(2), '{}'); // a schema error: it does not change
    for (let n = 3; n <= 22; n++) await storage.writeNew(p(n), `garbage ${n}`);
    const { s, reads } = counting(storage);
    const pc = sameUser(user, s);
    await pc.engine.scan();
    reads.clear();
    const env = await pc.engine.write(user.signer, 'data', 'CreateNote', { id: 'n2', text: 'b' });
    expect(env.seq).toBe(23);
    expect(reads.has(p(2))).toBe(false);
    expect([...reads.keys()].filter((k) => k.startsWith(`data/ops/${user.keyId}/`)).sort()).toEqual([...Array(15).keys()].map((i) => p(3 + i)));
  });

  it('a full scan does not read files with a known static issue again (also conflict copies), until reverifyAll()', async () => {
    const { storage, user } = await world();
    await user.engine.write(user.signer, 'data', 'CreateNote', { id: 'n1', text: 'a' });
    const p = (n: number) => filePath('data', 'ops', user.keyId, n);
    const statics = [p(2), p(3), `data/ops/${user.keyId}/0000000001-PC.json`];
    await storage.writeNew(statics[0], '{}'); // schema error
    await storage.writeNew(statics[1], storage.files.get(p(1)) as string); // misplaced
    await storage.writeNew(statics[2], '{}'); // a conflict copy that is not an op
    const { s, reads } = counting(storage);
    const e = new Engine(s, notesDomain);
    await e.scan();
    expect(statics.map((x) => reads.get(x))).toEqual([1, 1, 1]);
    const issues = canonicalize(e.issues);
    await e.scan();
    await e.scan();
    expect(statics.map((x) => reads.get(x))).toEqual([1, 1, 1]);
    expect(canonicalize(e.issues)).toBe(issues);
    await e.reverifyAll();
    expect(statics.map((x) => reads.get(x))).toEqual([2, 2, 2]);
    expect(canonicalize(e.issues)).toBe(issues);
  });

  it('isAdminKey and createCheckpoint use the owner test of the replay (a string)', async () => {
    const { storage } = await world();
    const outsider = await actor('outsider', storage);
    // A careless domain: keyOwner gives undefined for an unknown key, and isAdmin(undefined) is true.
    const domain: Domain = {
      ...notesDomain,
      keyOwner: (st, k) => (notesDomain.keyOwner(st, k) ?? undefined) as string | null,
      isAdmin: (st, u) => (u === undefined ? true : notesDomain.isAdmin(st, u)),
    };
    const e = new Engine(storage, domain);
    await e.scan();
    await expect(e.createCheckpoint(outsider.signer, 'data')).rejects.toThrow('only an admin can write a checkpoint');
    // A pack of the outsider (its key binding comes from a self-signed GrantUser) is not trusted.
    await rawOp(storage, outsider, 'roles', 'GrantUser', { userId: outsider.userId, keyId: outsider.keyId, publicKey: outsider.publicKey, admin: true }, { t: Date.parse('2026-01-02T00:00:00Z'), c: 0 });
    const rest = { v: 1, scope: 'data', authorKeyId: outsider.keyId, seq: 1, hlc: { t: 1, c: 0 }, wallTime: '2026-01-01T00:00:00.000Z', frontier: {}, ops: [] };
    const cpPath = filePath('data', 'checkpoints', outsider.keyId, 1);
    await storage.writeNew(cpPath, canonicalize({ ...rest, sig: await outsider.signer.sign(utf8(canonicalize(rest))) }));
    const e2 = new Engine(storage, domain);
    await e2.scan();
    expect(e2.issues.find((i) => i.path === cpPath)?.detail).toBe('checkpoint author is not an admin');
    expect(e2.checkpointStats(['data'])[0].checkpoints).toBe(0);
  });

  it('knownTrustRoot is a frozen copy of the known trust root', async () => {
    const { storage, admin } = await world();
    const a = JSON.parse(storage.files.get(TRUST_ROOT_PATH) as string);
    const k = admin.engine.knownTrustRoot!;
    expect(canonicalize(k)).toBe(canonicalize(a));
    expect(Object.isFrozen(k) && Object.isFrozen(k.roots) && Object.isFrozen(k.roots[0])).toBe(true);
    expect(k).not.toBe(admin.engine.trustRoot);
    const b = { ...a, roots: [{ ...a.roots[0], displayName: 'renamed' }] };
    storage.files.set(TRUST_ROOT_PATH, JSON.stringify(b));
    await admin.engine.scan();
    expect(canonicalize(admin.engine.knownTrustRoot)).toBe(canonicalize(a));
    await admin.engine.acknowledgeTrustRoot(admin.engine.trustRootHash!);
    expect(canonicalize(admin.engine.knownTrustRoot)).toBe(canonicalize(b));
  });

  it('the app never sees a new trust root with the old hash', async () => {
    const { storage, admin } = await world();
    const a = JSON.parse(storage.files.get(TRUST_ROOT_PATH) as string);
    const b = { ...a, roots: [{ ...a.roots[0], displayName: 'renamed' }] };
    const hashes = new Map([
      [canonicalize(a), await hashCanonical(a)],
      [canonicalize(b), await hashCanonical(b)],
    ]);
    storage.files.set(TRUST_ROOT_PATH, JSON.stringify(b));
    let done = false;
    let bad = 0;
    let checks = 0;
    const scan = admin.engine.scan().finally(() => (done = true));
    while (!done) {
      checks++;
      if (hashes.get(canonicalize(admin.engine.trustRoot)) !== admin.engine.trustRootHash) bad++;
      await new Promise((r) => setImmediate(r));
    }
    await scan;
    expect(checks).toBeGreaterThan(1);
    expect(bad).toBe(0);
    expect(admin.engine.trustRootHash).toBe(hashes.get(canonicalize(b)));
  });

  it('trustRootError refuses a key that is in the trust root 2 times, and accepts 2 keys of 1 user', () => {
    const root = { userId: 'u-a', displayName: 'A', keyId: 'k' + 'a'.repeat(24), alg: 'Ed25519', publicKey: 'x', cutoffs: null };
    expect(trustRootError({ v: 1, roots: [root, { ...root, userId: 'u-b', cutoffs: { data: 5 } }] })).toBe('roots[1].keyId: the key is in the trust root 2 times');
    expect(trustRootError({ v: 1, roots: [root, root] })).toBe('roots[1].keyId: the key is in the trust root 2 times');
    expect(trustRootError({ v: 1, roots: [root, { ...root, keyId: 'k' + 'b'.repeat(24), publicKey: 'y' }] })).toBeNull();
  });

  it('the wait for a pack of an unknown key grows to 6 hours (not 10 minutes)', async () => {
    const { storage } = await world();
    const outsider = await actor('outsider', storage);
    const cpPath = await writePack(storage, outsider, []);
    const { s, reads } = counting(storage);
    const clock = manualClock();
    const e = new Engine(s, notesDomain, { now: clock.now });
    await e.scan();
    // Waits: 5 s × 2^n after the reads 1, 2, …: 5 s, 10 s, …, 5 s × 2^11 = 2.8 h, 5 s × 2^12 = 5.7 h, then 6 h.
    for (let i = 0; i < 14; i++) {
      clock.add(UNKNOWN_KEY_PACK_MAX_WAIT_MS);
      await e.scan();
    }
    expect(reads.get(cpPath)).toBe(15);
    clock.add(UNKNOWN_KEY_PACK_MAX_WAIT_MS - 1);
    await e.scan();
    expect(reads.get(cpPath)).toBe(15);
    clock.add(1);
    await e.scan();
    expect(reads.get(cpPath)).toBe(16);
    expect(UNKNOWN_KEY_PACK_MAX_WAIT_MS).toBe(6 * 3600_000);
  });

  it('trustRootError refuses a trust root that JCS refuses', () => {
    expect(trustRootError({ v: 1, roots: [], x: Infinity })).toBe('not canonicalizable');
    expect(trustRootError({ v: 1, roots: [] })).toBeNull();
  });
});
