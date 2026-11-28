// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Deterministic Ed25519 checks before WebCrypto, and the limits of the key file KDF.
import {
  deriveKek, generateSigningKey, importPublicKey, isAcceptableEd25519PublicKey, isAcceptableKdf, isCanonicalEd25519Signature, keyIdFromPublicKey,
  newKdfParams, PBKDF2_MAX_ITERATIONS, PBKDF2_MIN_ITERATIONS, signBytes, unwrapSigningKey, verifyBytes, wrapSigningKey, WrongPassphraseError, type KeyFile,
} from '../../src/crypto';
import { createHash, randomBytes } from 'node:crypto';
import { canonicalize } from '../../src/canonical';
import { MAX_BATCH } from '../../src/domain';
import { b64u, fromB64u, utf8 } from '../../src/encoding';
import { Engine } from '../../src/engine';
import { filePath } from '../../src/paths';
import { MemoryStorage } from '../../src/storage/memory';
import { KeyMap } from '../../src/verify';
import { actor, fakeClock, note, rawOp, writeTrustRoot } from '../helpers';
import { notesDomain } from '../notes-domain';

const P = 2n ** 255n - 19n;
const L = 2n ** 252n + 27742317777372353535851937790883648493n;

const leBytes = (n: bigint, len = 32): Uint8Array => {
  const b = new Uint8Array(len);
  for (let i = 0; i < len; i++, n >>= 8n) b[i] = Number(n & 255n);
  return b;
};
const leInt = (b: Uint8Array): bigint => b.reduceRight((n, x) => (n << 8n) | BigInt(x), 0n);
const fromHex = (h: string): Uint8Array => Uint8Array.from(Buffer.from(h, 'hex'));
const withSign = (b: Uint8Array): Uint8Array => {
  const c = b.slice();
  c[31] |= 0x80;
  return c;
};

// An independent on-curve check: the point decoding of RFC 8032 §5.1.3 (square root with (p+3)/8).
function pow(b: bigint, e: bigint): bigint {
  let r = 1n;
  for (b %= P; e > 0n; e >>= 1n, b = (b * b) % P) if (e & 1n) r = (r * b) % P;
  return r;
}
const D = (((-121665n * pow(121666n, P - 2n)) % P) + P) % P;
function rfcDecodes(y: bigint): boolean {
  const u = (y * y - 1n + P) % P;
  const v = (D * y * y + 1n) % P;
  const x = (u * pow(v, 3n) * pow(u * pow(v, 7n), (P - 5n) / 8n)) % P;
  const vx2 = (v * x * x) % P;
  return vx2 === u || vx2 === (P - u) % P;
}
// Independent affine point arithmetic for the tests (not the extended coordinates of src/crypto.ts).
type Pt = [bigint, bigint];
const md = (a: bigint): bigint => ((a % P) + P) % P;
const inv = (a: bigint): bigint => pow(md(a), P - 2n);
function decode(b: Uint8Array): Pt {
  const y = leInt(b) & ((1n << 255n) - 1n);
  const u = md(y * y - 1n);
  const v = md(D * y * y + 1n);
  let x = md(u * inv(v));
  x = pow(x, (P + 3n) / 8n);
  if (md(x * x - u * inv(v)) !== 0n) x = md(x * pow(2n, (P - 1n) / 4n));
  if (md(x * x - u * inv(v)) !== 0n) throw new Error('not on the curve');
  if (Number(x & 1n) !== b[31] >> 7) x = md(-x);
  return [x, y];
}
function addAffine([x1, y1]: Pt, [x2, y2]: Pt): Pt {
  const t = md(D * x1 * x2 * y1 * y2);
  return [md((x1 * y2 + y1 * x2) * inv(1n + t)), md((y1 * y2 + x1 * x2) * inv(1n - t))];
}
function mulAffine(p: Pt, k: bigint): Pt {
  let r: Pt = [0n, 1n];
  for (; k > 0n; k >>= 1n, p = addAffine(p, p)) if (k & 1n) r = addAffine(r, p);
  return r;
}
const encode = ([x, y]: Pt): Uint8Array => leBytes(y | ((x & 1n) << 255n));

// Small-order points (libsodium ge25519_has_small_order). The y values; the sign bit is 0.
const ORDER8_A = '26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05';
const ORDER8_B = 'c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a';
const SMALL_ORDER: [string, Uint8Array][] = [
  ['identity (y = 1)', leBytes(1n)],
  ['order 2 (y = p - 1)', leBytes(P - 1n)],
  ['order 4 (y = 0)', leBytes(0n)],
  ['order 8 (a)', fromHex(ORDER8_A)],
  ['order 8 (b)', fromHex(ORDER8_B)],
];

describe('Ed25519 public key checks', () => {
  it('has a correct list of small-order points', () => {
    expect(leInt(fromHex(ORDER8_A)) + leInt(fromHex(ORDER8_B))).toBe(P);
    expect(leInt(fromHex(ORDER8_A))).toBe(2707385501144840649318225287225658788936804267575313519463743609750303402022n);
    for (const [, b] of SMALL_ORDER) expect(rfcDecodes(leInt(b))).toBe(true);
  });

  it('accepts honest generated keys and the base point', async () => {
    for (let i = 0; i < 20; i++) {
      const k = await generateSigningKey();
      expect(isAcceptableEd25519PublicKey(fromB64u(k.publicKey))).toBe(true);
    }
    expect(isAcceptableEd25519PublicKey(fromHex('5866666666666666666666666666666666666666666666666666666666666666'))).toBe(true);
    // RFC 8032 test 1 public key.
    expect(isAcceptableEd25519PublicKey(fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'))).toBe(true);
  });

  it('refuses small-order keys with both signs, in importPublicKey and in KeyMap.add', async () => {
    for (const [name, raw] of SMALL_ORDER)
      for (const b of [raw, withSign(raw)]) {
        expect([name, isAcceptableEd25519PublicKey(b)]).toEqual([name, false]);
        await expect(importPublicKey(b64u(b))).rejects.toThrow('unacceptable Ed25519 public key');
        const km = new KeyMap();
        expect(await km.add(await keyIdFromPublicKey(b64u(b)), b64u(b))).toBe(false);
        expect(km.has(await keyIdFromPublicKey(b64u(b)))).toBe(false);
      }
  });

  it('refuses a non-canonical y (y >= p), also when y - p is on the curve', async () => {
    let found = 0;
    for (let k = 2n; k < 19n; k++) {
      expect(isAcceptableEd25519PublicKey(leBytes(P + k))).toBe(false);
      expect(isAcceptableEd25519PublicKey(withSign(leBytes(P + k)))).toBe(false);
      const nc = b64u(leBytes(P + k));
      expect(await new KeyMap().add(await keyIdFromPublicKey(nc), nc)).toBe(false);
      if (rfcDecodes(k)) found++;
    }
    expect(found).toBeGreaterThan(0);
    expect(isAcceptableEd25519PublicKey(leBytes(P))).toBe(false);
    expect(isAcceptableEd25519PublicKey(leBytes(2n ** 255n - 1n))).toBe(false);
  });

  it('accepts a key only if it is on the curve and [L]A is the identity (independent affine check)', () => {
    let off = 0;
    let on = 0;
    for (let y = 2n; y < 60n; y++)
      for (const b of [leBytes(y), withSign(leBytes(y))]) {
        if (!rfcDecodes(y)) {
          off++;
          expect([y, isAcceptableEd25519PublicKey(b)]).toEqual([y, false]);
        } else if (on < 12) {
          on++;
          const lp = mulAffine(decode(b), L);
          expect([y, isAcceptableEd25519PublicKey(b)]).toEqual([y, lp[0] === 0n && lp[1] === 1n]);
        }
      }
    expect(off).toBeGreaterThan(20);
    expect(on).toBe(12);
  });

  it('refuses a mixed-order key (an honest key point plus a small-order point)', async () => {
    const torsion: [string, Pt][] = [
      ['order 2', [0n, P - 1n]],
      ['order 4', decode(leBytes(0n))],
      ['order 8 (a)', decode(fromHex(ORDER8_A))],
      ['order 8 (b)', decode(withSign(fromHex(ORDER8_B)))],
    ];
    for (let i = 0; i < 3; i++) {
      const k = await generateSigningKey();
      const a = decode(fromB64u(k.publicKey));
      expect(encode(a)).toEqual(fromB64u(k.publicKey));
      for (const [name, t] of torsion) {
        const mixed = encode(addAffine(a, t));
        // The point is on the curve, canonical and not small-order: only the subgroup check refuses it.
        expect(rfcDecodes(leInt(mixed) & ((1n << 255n) - 1n))).toBe(true);
        expect(leInt(mixed) & ((1n << 255n) - 1n)).toBeLessThan(P);
        expect([name, isAcceptableEd25519PublicKey(mixed)]).toEqual([name, false]);
        await expect(importPublicKey(b64u(mixed))).rejects.toThrow('unacceptable Ed25519 public key');
        // KeyMap.add does only the cheap checks; the lazy full check refuses the binding.
        const km = new KeyMap();
        const kid = await keyIdFromPublicKey(b64u(mixed));
        expect(await km.add(kid, b64u(mixed))).toBe(true);
        expect(km.isValid(kid, b64u(mixed))).toBe(false);
      }
      // A prime-order point that is not a generated key (2A) passes.
      expect(isAcceptableEd25519PublicKey(encode(addAffine(a, a)))).toBe(true);
    }
  });

  it('checks a key in a few milliseconds', async () => {
    const keys = await Promise.all(Array.from({ length: 30 }, async () => fromB64u((await generateSigningKey()).publicKey)));
    const t0 = performance.now();
    for (const k of keys) expect(isAcceptableEd25519PublicKey(k)).toBe(true);
    const ms = (performance.now() - t0) / keys.length;
    expect(ms).toBeLessThan(20);
  });

  it('refuses a key with a wrong length', async () => {
    expect(isAcceptableEd25519PublicKey(new Uint8Array(31))).toBe(false);
    expect(isAcceptableEd25519PublicKey(new Uint8Array(33))).toBe(false);
    const k = await generateSigningKey();
    await expect(importPublicKey(b64u(fromB64u(k.publicKey).subarray(0, 31)))).rejects.toThrow();
  });
});

describe('Ed25519 signature checks', () => {
  it('honest signatures verify; the RFC 8032 test vector signature is canonical', async () => {
    for (let i = 0; i < 20; i++) {
      const k = await generateSigningKey();
      const data = utf8(`data ${i}`);
      const sig = await signBytes(k.privateKey, data);
      expect(isCanonicalEd25519Signature(fromB64u(sig))).toBe(true);
      expect(await verifyBytes(await importPublicKey(k.publicKey), sig, data)).toBe(true);
    }
    const rfc = fromHex('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
    expect(isCanonicalEd25519Signature(rfc)).toBe(true);
    // RFC 8032 section 7.1, test 1: the empty message.
    const rfcKey = await importPublicKey(b64u(fromHex('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a')));
    expect(await verifyBytes(rfcKey, b64u(rfc), new Uint8Array(0))).toBe(true);
    expect(await verifyBytes(rfcKey, b64u(rfc), new Uint8Array(1))).toBe(false);
  });

  it('refuses a signature with S + L (malleability) and S >= L', async () => {
    const k = await generateSigningKey();
    const pub = await importPublicKey(k.publicKey);
    const data = utf8('x');
    const sig = fromB64u(await signBytes(k.privateKey, data));
    const s = leInt(sig.subarray(32));
    expect(s < L).toBe(true);
    const mal = sig.slice();
    mal.set(leBytes(s + L), 32);
    expect(isCanonicalEd25519Signature(mal)).toBe(false);
    expect(await verifyBytes(pub, b64u(mal), data)).toBe(false);
    for (const bad of [L, 2n ** 256n - 1n]) {
      const t = sig.slice();
      t.set(leBytes(bad), 32);
      expect(await verifyBytes(pub, b64u(t), data)).toBe(false);
    }
  });

  it('the form check of R refuses y >= p but accepts the same point with y < p', () => {
    const sig = new Uint8Array(64);
    for (let k = 2n; k < 19n; k++) {
      if (!rfcDecodes(k)) continue;
      sig.set(leBytes(k), 0);
      expect(isCanonicalEd25519Signature(sig)).toBe(true);
      sig.set(leBytes(P + k), 0);
      expect(isCanonicalEd25519Signature(sig)).toBe(false);
    }
  });

  it('refuses a non-canonical R and a small-order R', async () => {
    const k = await generateSigningKey();
    const pub = await importPublicKey(k.publicKey);
    const data = utf8('x');
    const sig = fromB64u(await signBytes(k.privateKey, data));
    for (const r of [leBytes(P + 2n), withSign(leBytes(P + 3n)), leBytes(2n ** 255n - 1n), ...SMALL_ORDER.map(([, b]) => b), ...SMALL_ORDER.map(([, b]) => withSign(b))]) {
      const t = sig.slice();
      t.set(r, 0);
      expect(isCanonicalEd25519Signature(t)).toBe(false);
      expect(await verifyBytes(pub, b64u(t), data)).toBe(false);
    }
  });

  it('reads only WebCrypto rejection errors as false, and throws other errors again', async () => {
    const k = await generateSigningKey();
    const pub = await importPublicKey(k.publicKey);
    const sig = await signBytes(k.privateKey, utf8('x'));
    const spy = vi.spyOn(globalThis.crypto.subtle, 'verify');
    try {
      for (const name of ['OperationError', 'InvalidAccessError', 'DataError']) {
        spy.mockRejectedValueOnce(new DOMException('x', name));
        expect(await verifyBytes(pub, sig, utf8('x'))).toBe(false);
      }
      spy.mockRejectedValueOnce(new DOMException('x', 'NotSupportedError'));
      await expect(verifyBytes(pub, sig, utf8('x'))).rejects.toThrow();
      spy.mockRejectedValueOnce(new TypeError('environment'));
      await expect(verifyBytes(pub, sig, utf8('x'))).rejects.toBeInstanceOf(TypeError);
      spy.mockRejectedValueOnce(new Error('OperationError'));
      await expect(verifyBytes(pub, sig, utf8('x'))).rejects.toThrow();
    } finally {
      spy.mockRestore();
    }
    expect(await verifyBytes(pub, sig, utf8('x'))).toBe(true);
  });

  it('refuses a signature with a wrong length or bad base64url', async () => {
    const k = await generateSigningKey();
    const pub = await importPublicKey(k.publicKey);
    const sig = fromB64u(await signBytes(k.privateKey, utf8('x')));
    expect(await verifyBytes(pub, b64u(sig.subarray(0, 63)), utf8('x'))).toBe(false);
    expect(await verifyBytes(pub, b64u(Uint8Array.from([...sig, 0])), utf8('x'))).toBe(false);
    expect(await verifyBytes(pub, b64u(sig) + '=', utf8('x'))).toBe(false);
  });
});

describe('key file KDF limits', () => {
  let file: KeyFile;
  beforeAll(async () => {
    file = await wrapSigningKey(await generateSigningKey(), 'heslo', 'n', new Date('2026-01-01T00:00:00Z'), 'test-key', PBKDF2_MIN_ITERATIONS);
  });

  it('wrapSigningKey refuses a display name that the enrollment refuses', async () => {
    const k = await generateSigningKey();
    for (const name of ['', '   ', '\u200b\u2800\u3164', 'A\u202eB', 'A\nB', 'x'.repeat(201)])
      await expect(wrapSigningKey(k, 'p', name, new Date(), 'test-key', PBKDF2_MIN_ITERATIONS)).rejects.toThrow('invalid display name');
  });

  it('wrapSigningKey refuses an iteration count out of range', async () => {
    const k = await generateSigningKey();
    for (const it of [0, 1000, PBKDF2_MIN_ITERATIONS - 1, PBKDF2_MAX_ITERATIONS + 1, 1e12, 100_000.5, NaN, Infinity])
      await expect(wrapSigningKey(k, 'p', 'n', new Date(), 'test-key', it)).rejects.toBeInstanceOf(RangeError);
  });

  it('unwrapSigningKey refuses bad KDF parameters at once, without the slow derivation', async () => {
    const salt8 = b64u(new Uint8Array(8));
    const salt300 = b64u(new Uint8Array(300));
    const bad: unknown[] = [
      { ...file.kdf, iterations: 1e12 },
      { ...file.kdf, iterations: 2 ** 53 },
      { ...file.kdf, iterations: 1000 },
      { ...file.kdf, iterations: PBKDF2_MIN_ITERATIONS - 1 },
      { ...file.kdf, iterations: PBKDF2_MAX_ITERATIONS + 1 },
      { ...file.kdf, iterations: 600_000.5 },
      { ...file.kdf, iterations: '600000' },
      { ...file.kdf, iterations: -600_000 },
      { ...file.kdf, name: 'scrypt' },
      { ...file.kdf, hash: 'SHA-1' },
      { ...file.kdf, salt: salt8 },
      { ...file.kdf, salt: salt300 },
      { ...file.kdf, salt: 'not base64!' },
      { ...file.kdf, salt: 5 },
      null,
      'PBKDF2',
    ];
    const t0 = Date.now();
    for (const kdf of bad) await expect(unwrapSigningKey({ ...file, kdf } as KeyFile, 'heslo', 'test-key')).rejects.toThrow('unsupported key file');
    await expect(unwrapSigningKey({ ...file, wrap: { ...file.wrap, name: 'AES-CBC' } } as never, 'heslo', 'test-key')).rejects.toThrow('unsupported key file');
    await expect(unwrapSigningKey(null as never, 'heslo', 'test-key')).rejects.toThrow('unsupported key file');
    // A bad public key or a wrong keyId: refused before the key derivation.
    const other = await generateSigningKey();
    const smallOrder = b64u(leBytes(1n));
    for (const f of [
      { ...file, publicKey: smallOrder, keyId: await keyIdFromPublicKey(smallOrder) },
      { ...file, publicKey: 'not base64!' },
      { ...file, publicKey: 5 },
      { ...file, keyId: other.keyId },
      { ...file, publicKey: other.publicKey },
    ])
      await expect(unwrapSigningKey(f as KeyFile, 'heslo', 'test-key')).rejects.toThrow('unsupported key file');
    expect(Date.now() - t0).toBeLessThan(5000);
  });

  it('accepts the limits and unwraps a key file at the minimum count', async () => {
    expect(isAcceptableKdf(file.kdf)).toBe(true);
    expect(isAcceptableKdf({ ...file.kdf, iterations: PBKDF2_MAX_ITERATIONS })).toBe(true);
    expect(isAcceptableKdf({ ...file.kdf, salt: b64u(new Uint8Array(256)) })).toBe(true);
    expect(isAcceptableKdf(newKdfParams())).toBe(true);
    const { privateKey } = await unwrapSigningKey(file, 'heslo', 'test-key');
    expect(privateKey.extractable).toBe(false);
    await expect(unwrapSigningKey(file, 'spatne', 'test-key')).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('deriveKek refuses bad KDF parameters', async () => {
    await expect(deriveKek('p', newKdfParams(1000))).rejects.toBeInstanceOf(RangeError);
    await expect(deriveKek('p', { ...newKdfParams(), iterations: 1e12 })).rejects.toBeInstanceOf(RangeError);
  });
});

// ---- KeyMap: cheap add, lazy full check, 1 central signature check ----------------------------

const B_PT = (): Pt => decode(fromHex('5866666666666666666666666666666666666666666666666666666666666666'));
const sha512 = (...parts: Uint8Array[]): Uint8Array => Uint8Array.from(createHash('sha512').update(Buffer.concat(parts)).digest());

/**
 * A key whose public point is A + T (T of order 2), with a signer that makes signatures that a
 * cofactorless verifier (OpenSSL in Node) accepts: k = H(R || A' || M) must be even, so [k]T = 0.
 */
function mixedOrderSigner() {
  const h = sha512(Uint8Array.from(randomBytes(32)));
  h[0] &= 248;
  h[31] &= 127;
  h[31] |= 64;
  const a = leInt(h.subarray(0, 32));
  const [x, y] = mulAffine(B_PT(), a);
  const pub = encode([md(-x), md(-y)]); // A + (0, -1)
  const sign = (m: Uint8Array): Uint8Array => {
    for (let i = 0; ; i++) {
      const r = leInt(sha512(h.subarray(32), m, Uint8Array.of(i))) % L;
      const rEnc = encode(mulAffine(B_PT(), r));
      const k = leInt(sha512(rEnc, pub, m)) % L;
      if (k % 2n !== 0n) continue;
      const sig = new Uint8Array(64);
      sig.set(rEnc, 0);
      sig.set(leBytes((r + k * a) % L), 32);
      return sig;
    }
  };
  return { pub, publicKey: b64u(pub), sign };
}

describe('KeyMap', () => {
  it('add does only cheap checks: many keys cost little', async () => {
    const ks = await Promise.all(Array.from({ length: 2000 }, () => generateSigningKey()));
    const env = { type: 'Batch', payload: { ops: [] } } as never;
    const envs = ks.map((k, i) => ({ type: 'GrantUser', payload: { userId: `u${i}`, keyId: k.keyId, publicKey: k.publicKey, admin: false } })) as never[];
    const km = new KeyMap();
    const t0 = performance.now();
    await km.addFromOps([env, ...envs], notesDomain);
    const ms = (performance.now() - t0) / ks.length;
    // The full check costs about 1 ms for each key. add() must not do it.
    expect(ms).toBeLessThan(0.3);
    expect(ks.every((k) => km.has(k.keyId))).toBe(true);
  });

  it('reads at most MAX_BATCH items of an op: the first ones, in the order of the Batch', async () => {
    const ks = await Promise.all(Array.from({ length: MAX_BATCH + 1 }, () => generateSigningKey()));
    const grant = (k: { keyId: string; publicKey: string }, i: number) => ({ type: 'GrantUser', payload: { userId: `u${i}`, keyId: k.keyId, publicKey: k.publicKey, admin: false } });
    const km = new KeyMap();
    await km.addFromOps([{ type: 'Batch', payload: { ops: ks.map(grant) } } as never], notesDomain);
    expect(ks.slice(0, MAX_BATCH).every((k) => km.has(k.keyId))).toBe(true);
    expect(km.has(ks[MAX_BATCH].keyId)).toBe(false);
    // A large unsigned Batch (300 000 items) costs only MAX_BATCH items.
    const big = { type: 'Batch', payload: { ops: Array.from({ length: 300_000 }, (_, i) => grant(ks[i % ks.length], i)) } } as never;
    const km2 = new KeyMap();
    const t0 = performance.now();
    await km2.addFromOps([big], notesDomain);
    expect(performance.now() - t0).toBeLessThan(2000);
    expect(km2.has(ks[MAX_BATCH].keyId)).toBe(false);
  });

  it('reads at most MAX_BATCH keys of an op, in the order of the items and of keysIn', async () => {
    const ks = await Promise.all(Array.from({ length: MAX_BATCH + 100 }, () => generateSigningKey()));
    const pairs = ks.map((k) => ({ keyId: k.keyId, publicKey: k.publicKey }));
    // A domain that returns many keys for 1 item (the keys are in the payload).
    const many = { keysIn: (it: { payload: Record<string, unknown> }) => it.payload.keys as never };
    const registered = (km: KeyMap) => ks.map((k) => km.has(k.keyId));
    const expected = (n: number) => ks.map((_, i) => i < n);
    // 1 item with MAX_BATCH + 100 keys.
    const km1 = new KeyMap();
    await km1.addFromOps([{ type: 'X', payload: { keys: pairs } } as never], many);
    expect(registered(km1)).toEqual(expected(MAX_BATCH));
    // A Batch of 2 items with 300 keys each: all 300 of the first item, then 200 of the second.
    const km2 = new KeyMap();
    const batch = { type: 'Batch', payload: { ops: [{ type: 'X', payload: { keys: pairs.slice(0, 300) } }, { type: 'X', payload: { keys: pairs.slice(300, 600) } }] } };
    await km2.addFromOps([batch as never], many);
    expect(registered(km2)).toEqual(expected(MAX_BATCH));
    // Entries that are not valid also count; each op has its own limit.
    const km3 = new KeyMap();
    const junk = Array.from({ length: MAX_BATCH - 1 }, () => ({ keyId: 5, publicKey: null }));
    await km3.addFromOps([{ type: 'X', payload: { keys: [...junk, ...pairs.slice(0, 2)] } } as never, { type: 'X', payload: { keys: pairs.slice(2, 4) } } as never], many);
    expect(registered(km3).slice(0, 5)).toEqual([true, false, true, true, false]);
    // keysIn that returns no array, or null entries: ignored, no exception.
    await new KeyMap().addFromOps([{ type: 'X', payload: { keys: 'x' } } as never, { type: 'X', payload: { keys: [null, 1] } } as never], many);
  });

  it('a mixed-order key with a signature that WebCrypto accepts gives bad, and is not a valid binding', async () => {
    const m = mixedOrderSigner();
    const keyId = await keyIdFromPublicKey(m.publicKey);
    const data = utf8('op');
    const sig = m.sign(data);
    // Node (cofactorless) accepts the signature: only the full check of the key refuses it.
    const raw = await crypto.subtle.importKey('raw', new Uint8Array(m.pub), { name: 'Ed25519' }, false, ['verify']);
    expect(await crypto.subtle.verify({ name: 'Ed25519' }, raw, new Uint8Array(sig), new Uint8Array(data))).toBe(true);
    expect(isCanonicalEd25519Signature(sig)).toBe(true);
    const km = new KeyMap();
    expect(await km.add(keyId, m.publicKey)).toBe(true);
    expect(km.has(keyId)).toBe(true);
    expect(await km.verify(keyId, b64u(sig), data)).toBe('bad');
    expect(km.isValid(keyId, m.publicKey)).toBe(false);
    expect(await km.verify(keyId, b64u(sig), utf8('other'))).toBe('bad');
    // An honest key: 'ok', a valid binding; an unknown key: 'unknown-key'.
    const k = await generateSigningKey();
    await km.add(k.keyId, k.publicKey);
    expect(await km.verify(k.keyId, await signBytes(k.privateKey, data), data)).toBe('ok');
    expect(km.isValid(k.keyId, k.publicKey)).toBe(true);
    expect(km.isValid(k.keyId, m.publicKey)).toBe(false);
    expect(km.isValid('kxxxxxxxxxxxxxxxxxxxxxxxx', k.publicKey)).toBe(false);
    expect(await km.verify((await generateSigningKey()).keyId, b64u(sig), data)).toBe('unknown-key');
  });

  it('an import rejection gives bad; an environment error is thrown and not cached', async () => {
    const k = await generateSigningKey();
    const data = utf8('x');
    const sig = await signBytes(k.privateKey, data);
    const spy = vi.spyOn(globalThis.crypto.subtle, 'importKey');
    try {
      const km = new KeyMap();
      await km.add(k.keyId, k.publicKey);
      spy.mockRejectedValueOnce(new TypeError('environment'));
      await expect(km.verify(k.keyId, sig, data)).rejects.toBeInstanceOf(TypeError);
      expect(await km.verify(k.keyId, sig, data)).toBe('ok');
      const km2 = new KeyMap();
      await km2.add(k.keyId, k.publicKey);
      spy.mockRejectedValueOnce(new DOMException('x', 'DataError'));
      expect(await km2.verify(k.keyId, sig, data)).toBe('bad');
      expect(await km2.verify(k.keyId, sig, data)).toBe('bad');
    } finally {
      spy.mockRestore();
    }
  });

  it('runs the full check before the import: a bad key gives bad, also if the import would throw', async () => {
    let y = 2n;
    while (rfcDecodes(y)) y++;
    const offCurve = b64u(leBytes(y));
    const m = mixedOrderSigner();
    const spy = vi.spyOn(globalThis.crypto.subtle, 'importKey').mockRejectedValue(new TypeError('engine bug'));
    try {
      for (const pk of [offCurve, m.publicKey]) {
        const km = new KeyMap();
        const keyId = await keyIdFromPublicKey(pk);
        expect(await km.add(keyId, pk)).toBe(true);
        const sig = pk === m.publicKey ? b64u(m.sign(utf8('x'))) : b64u(new Uint8Array(64));
        expect(await km.verify(keyId, sig, utf8('x'))).toBe('bad');
        expect(await km.verify(keyId, sig, utf8('x'))).toBe('bad');
      }
      expect(spy).not.toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });

  it('the engine uses the same rule for ops and for checkpoints (mixed-order root admin)', async () => {
    const storage = new MemoryStorage();
    const clock = fakeClock();
    const admin = await actor('admin', storage, clock.now);
    const m = mixedOrderSigner();
    const keyId = await keyIdFromPublicKey(m.publicKey);
    const mixed = { ...admin, name: 'mixed', userId: 'u-mixed', keyId, publicKey: m.publicKey, signer: { keyId, sign: async (b: Uint8Array) => b64u(m.sign(b)) } };
    await writeTrustRoot(storage, [admin, mixed]);
    await rawOp(storage, mixed, 'data', 'CreateNote', { id: 'n-mixed', text: 'x' }, { t: Date.parse('2026-01-01T09:00:00Z'), c: 0 });
    // A checkpoint (empty pack) of each root admin, signed by hand.
    const cp = async (a: { keyId: string; signer: { sign(b: Uint8Array): Promise<string> } }) => {
      const rest = { v: 1, scope: 'data', authorKeyId: a.keyId, seq: 1, hlc: { t: Date.parse('2026-01-01T09:00:00Z'), c: 1 }, wallTime: '2026-01-01T09:00:00.000Z', frontier: {}, ops: [] };
      const path = filePath('data', 'checkpoints', a.keyId, 1);
      await storage.writeNew(path, canonicalize({ ...rest, sig: await a.signer.sign(utf8(canonicalize(rest))) }));
      return path;
    };
    const cpMixed = await cp(mixed);
    const cpAdmin = await cp(admin);
    const e = new Engine(storage, notesDomain, { now: clock.now });
    await e.scan();
    expect(note(e.state, 'n-mixed')).toBeUndefined();
    expect(e.issues.find((i) => i.authorKeyId === keyId && i.seq === 1)?.kind).toBe('bad-signature');
    expect(e.issues.find((i) => i.path === cpMixed)).toMatchObject({ kind: 'bad-checkpoint', detail: expect.stringContaining('signature is not valid') });
    expect(e.issues.find((i) => i.path === cpAdmin)).toBeUndefined();
    expect(e.validKeyBindings.isValid(keyId, m.publicKey)).toBe(false);
    expect(e.validKeyBindings.isValid(admin.keyId, admin.publicKey)).toBe(true);
  });
});
