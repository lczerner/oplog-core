// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// WebCrypto helpers: SHA-256, Ed25519, PBKDF2 key wrapping, AES-GCM.
// Works in the browser and in Node 22 (globalThis.crypto). No DOM access.

import { canonicalize } from './canonical';
import { b64u, base32, fromB64u, hex, utf8 } from './encoding';
import { isValidDisplayName } from './validate';

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto is not available');
  return s;
};

export const SIG_ALG = 'Ed25519' as const;
export const PBKDF2_ITERATIONS = 600_000;
/** The minimum PBKDF2 iteration count that the library accepts in a key file and in deriveKek. */
export const PBKDF2_MIN_ITERATIONS = 100_000;
/** The maximum PBKDF2 iteration count. A larger count in a damaged or forged key file can stop the app for hours. */
export const PBKDF2_MAX_ITERATIONS = 10_000_000;
/** The minimum and maximum length of a PBKDF2 salt in bytes. */
export const PBKDF2_MIN_SALT_BYTES = 16;
export const PBKDF2_MAX_SALT_BYTES = 256;

// WebCrypto wants BufferSource; copy to a fresh ArrayBuffer to satisfy strict typings.
const buf = (b: Uint8Array): ArrayBuffer => b.slice().buffer as ArrayBuffer;

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await subtle().digest('SHA-256', buf(data)));
}

export async function sha256Hex(data: Uint8Array | string): Promise<string> {
  return hex(await sha256(typeof data === 'string' ? utf8(data) : data));
}

/** Hash of a JSON value in canonical form: "sha256:<hex>". */
export async function hashCanonical(value: unknown): Promise<string> {
  return 'sha256:' + (await sha256Hex(canonicalize(value)));
}

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return b;
}

export async function isEd25519Supported(): Promise<boolean> {
  try {
    await subtle().generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
    return true;
  } catch {
    return false;
  }
}

// ---- Keys --------------------------------------------------------------------

/** keyId = "k" + base32(first 15 bytes of SHA-256(raw public key)). 25 characters. */
export async function keyIdFromPublicKey(publicKeyB64u: string): Promise<string> {
  const h = await sha256(fromB64u(publicKeyB64u));
  return 'k' + base32(h.subarray(0, 15));
}

/** Human-comparable fingerprint: 5 groups of 4 characters (100 bits). */
export function fingerprint(keyId: string): string {
  const s = keyId.slice(1, 21).toUpperCase();
  return s.match(/.{4}/g)!.join('-');
}

export interface GeneratedKey {
  privateKey: CryptoKey; // extractable, only so that it can be wrapped one time
  publicKey: string; // raw, base64url
  keyId: string;
}

export async function generateSigningKey(): Promise<GeneratedKey> {
  const kp = (await subtle().generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair;
  const raw = new Uint8Array(await subtle().exportKey('raw', kp.publicKey));
  const publicKey = b64u(raw);
  return { privateKey: kp.privateKey, publicKey, keyId: await keyIdFromPublicKey(publicKey) };
}

// ---- Ed25519 checks before WebCrypto --------------------------------------------
//
// WebCrypto implementations (Chrome, Firefox, Safari, Node) do not all check the same
// properties of Ed25519 keys and signatures. Then 1 client can accept a signature that another
// client rejects, and the replay gives different states. These checks use only BigInt, so all
// clients give the same result. Honest keys and signatures always pass them.
//
// A public key must be in the prime-order subgroup ([L]A = identity). The check does a scalar
// multiplication with BigInt (about 1 ms). KeyMap runs it lazily: 1 time for each public key that
// is used to verify a signature or that the replay asks about (see src/verify.ts).
//
// Residual risk: the check of R in a signature is only a form check (canonical, not small-order).
// It does not refuse a mixed-order R (a prime-order point plus a small-order point), because a full
// check for each signature costs too much time. A cofactored verifier and a cofactorless verifier
// can give different results for such a signature. Only the owner of a valid key can make it.

const P25519 = 2n ** 255n - 19n;
/** The order of the Ed25519 base point: 2^252 + 27742317777372353535851937790883648493. */
const L25519 = 2n ** 252n + 27742317777372353535851937790883648493n;
/** The curve constant d = -121665 / 121666 mod p. */
const D25519 = 37095705934669439343138083508754565189542113879843219016388785533085940283555n;

/** Little-endian bytes to an unsigned integer. */
const leInt = (b: Uint8Array): bigint => {
  let n = 0n;
  for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]);
  return n;
};
/** The y coordinate of a 32-byte point encoding: the top (sign of x) bit is cleared. */
const encodedY = (b: Uint8Array): bigint => leInt(b) & ((1n << 255n) - 1n);

function modPow(b: bigint, e: bigint): bigint {
  let r = 1n;
  b %= P25519;
  for (; e > 0n; e >>= 1n) {
    if (e & 1n) r = (r * b) % P25519;
    b = (b * b) % P25519;
  }
  return r;
}

// The y values of the points with a small order (1, 2, 4 or 8), from libsodium ge25519_has_small_order.
// The sign bit is not part of y, so the list also covers the points with the other sign of x.
const ORDER8_Y = leInt(Uint8Array.from([0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05]));
const SMALL_ORDER_Y: readonly bigint[] = [0n, 1n, P25519 - 1n, ORDER8_Y, P25519 - ORDER8_Y];

/** True if the 32 bytes encode y < p, and y is not the y of a small-order point. */
function canonicalNotSmallOrder(b: Uint8Array): boolean {
  if (b.length !== 32) return false;
  const y = encodedY(b);
  return y < P25519 && !SMALL_ORDER_Y.includes(y);
}

const mod = (a: bigint): bigint => {
  const r = a % P25519;
  return r < 0n ? r + P25519 : r;
};
const SQRT_M1 = modPow(2n, (P25519 - 1n) / 4n);
const D2 = (2n * D25519) % P25519;

/** Decodes a 32-byte point (RFC 8032 section 5.1.3). Returns [x, y], or null if the point is not on the curve. */
function decodePoint(b: Uint8Array): [bigint, bigint] | null {
  const y = encodedY(b);
  if (y >= P25519) return null;
  const sign = b[31] >> 7;
  const y2 = (y * y) % P25519;
  const u = mod(y2 - 1n);
  const v = (D25519 * y2 + 1n) % P25519;
  const v3 = (v * v * v) % P25519;
  // x = u v^3 (u v^7)^((p - 5) / 8)
  let x = (((u * v3) % P25519) * modPow((((u * v3) % P25519) * ((v3 * v) % P25519)) % P25519, (P25519 - 5n) / 8n)) % P25519;
  const vx2 = (((v * x) % P25519) * x) % P25519;
  if (vx2 !== u) {
    if (vx2 !== mod(-u)) return null;
    x = (x * SQRT_M1) % P25519;
  }
  if (x === 0n && sign === 1) return null;
  if (Number(x & 1n) !== sign) x = P25519 - x;
  return [x, y];
}

/** A point in extended coordinates [X, Y, Z, T]: x = X/Z, y = Y/Z, x y = T/Z. */
type ExtPoint = [bigint, bigint, bigint, bigint];

/** Point addition (Hisil et al. 2008, a = -1). The formula is complete: it is also correct for doubling and for the identity. */
function addPoints([X1, Y1, Z1, T1]: ExtPoint, [X2, Y2, Z2, T2]: ExtPoint): ExtPoint {
  const a = mod((Y1 - X1) * (Y2 - X2));
  const b = ((Y1 + X1) * (Y2 + X2)) % P25519;
  const c = (((T1 * D2) % P25519) * T2) % P25519;
  const d = (2n * Z1 * Z2) % P25519;
  const e = mod(b - a);
  const f = mod(d - c);
  const g = (d + c) % P25519;
  const h = (b + a) % P25519;
  return [(e * f) % P25519, (g * h) % P25519, (f * g) % P25519, (e * h) % P25519];
}

/** True if [L]P is the identity, that is, P is in the prime-order subgroup. */
function inPrimeOrderSubgroup([x, y]: [bigint, bigint]): boolean {
  let r: ExtPoint = [0n, 1n, 1n, 0n];
  let q: ExtPoint = [x, y, 1n, (x * y) % P25519];
  for (let k = L25519; k > 0n; k >>= 1n) {
    if (k & 1n) r = addPoints(r, q);
    q = addPoints(q, q);
  }
  return r[0] === 0n && r[1] === r[2];
}

/**
 * The cheap form check of an Ed25519 public key (some microseconds): 32 bytes, a canonical y
 * (y < p), not a point with a small order. It does not check the curve and the subgroup.
 */
export const isWellFormedEd25519PublicKey = (raw: Uint8Array): boolean => canonicalNotSmallOrder(raw);

/**
 * True if `raw` is an acceptable Ed25519 public key: well-formed (isWellFormedEd25519PublicKey),
 * a point on the curve, and a point in the prime-order subgroup (thus not a mixed-order point).
 * Deterministic. About 1 ms.
 */
export function isAcceptableEd25519PublicKey(raw: Uint8Array): boolean {
  if (!canonicalNotSmallOrder(raw)) return false;
  const pt = decodePoint(raw);
  return pt !== null && inPrimeOrderSubgroup(pt);
}

/**
 * True if `sig` has the form of an Ed25519 signature that all WebCrypto implementations treat
 * the same: 64 bytes, R (bytes 0-31) canonical and not a small-order point, S (bytes 32-63) < L.
 */
export function isCanonicalEd25519Signature(sig: Uint8Array): boolean {
  return sig.length === 64 && canonicalNotSmallOrder(sig.subarray(0, 32)) && leInt(sig.subarray(32)) < L25519;
}

/** Imports a raw public key (base64url). Throws if the key is not acceptable (isAcceptableEd25519PublicKey). */
export async function importPublicKey(publicKeyB64u: string): Promise<CryptoKey> {
  const raw = fromB64u(publicKeyB64u);
  if (!isAcceptableEd25519PublicKey(raw)) throw new Error('unacceptable Ed25519 public key');
  return subtle().importKey('raw', buf(raw), { name: 'Ed25519' }, false, ['verify']);
}

/**
 * Imports a raw public key that is only well-formed (isWellFormedEd25519PublicKey), without the
 * slow full check. The caller must do isAcceptableEd25519PublicKey before it accepts a result of
 * the key (KeyMap does this before the import). Throws if the key is not well-formed.
 */
export async function importWellFormedPublicKey(raw: Uint8Array): Promise<CryptoKey> {
  if (!isWellFormedEd25519PublicKey(raw)) throw new Error('unacceptable Ed25519 public key');
  return subtle().importKey('raw', buf(raw), { name: 'Ed25519' }, false, ['verify']);
}

export async function signBytes(privateKey: CryptoKey, data: Uint8Array): Promise<string> {
  return b64u(new Uint8Array(await subtle().sign({ name: 'Ed25519' }, privateKey, buf(data))));
}

/** The names of the WebCrypto errors that mean "the key or the signature is not valid". */
const VERIFY_REJECT_ERRORS: readonly string[] = ['OperationError', 'InvalidAccessError', 'DataError'];

/**
 * True if `e` is a WebCrypto error for a key or a signature that is not valid (a DOMException with
 * the name OperationError, InvalidAccessError or DataError). Other errors (for example of the
 * environment) are not a result for the data: the caller must throw them again.
 */
export const isWebCryptoRejection = (e: unknown): boolean => e instanceof DOMException && VERIFY_REJECT_ERRORS.includes(e.name);

export async function verifyBytes(publicKey: CryptoKey, sigB64u: string, data: Uint8Array): Promise<boolean> {
  let sig: Uint8Array;
  try {
    sig = fromB64u(sigB64u);
  } catch {
    return false;
  }
  if (!isCanonicalEd25519Signature(sig)) return false;
  const s = subtle();
  try {
    return await s.verify({ name: 'Ed25519' }, publicKey, buf(sig), buf(data));
  } catch (e) {
    // Some implementations throw for a signature that others reject with false. Other errors (for
    // example of the environment) are not a result for the signature: throw them again.
    if (isWebCryptoRejection(e)) return false;
    throw e;
  }
}

// ---- Passphrase wrapping (key file and cache key) -----------------------------

export interface KdfParams {
  name: 'PBKDF2';
  hash: 'SHA-256';
  iterations: number;
  salt: string; // base64url
}

/** True if `kdf` is PBKDF2 with SHA-256, an iteration count in the permitted range and a salt of a permitted length. */
export function isAcceptableKdf(kdf: unknown): kdf is KdfParams {
  if (typeof kdf !== 'object' || kdf === null) return false;
  const k = kdf as Record<string, unknown>;
  if (k.name !== 'PBKDF2' || k.hash !== 'SHA-256' || typeof k.salt !== 'string') return false;
  if (!Number.isSafeInteger(k.iterations) || (k.iterations as number) < PBKDF2_MIN_ITERATIONS || (k.iterations as number) > PBKDF2_MAX_ITERATIONS) return false;
  try {
    const n = fromB64u(k.salt).length;
    return n >= PBKDF2_MIN_SALT_BYTES && n <= PBKDF2_MAX_SALT_BYTES;
  } catch {
    return false;
  }
}

/** Derives the key-encryption key. Throws RangeError if `kdf` is not acceptable (isAcceptableKdf). */
export async function deriveKek(passphrase: string, kdf: KdfParams): Promise<CryptoKey> {
  if (!isAcceptableKdf(kdf)) throw new RangeError('unsupported KDF parameters');
  const base = await subtle().importKey('raw', buf(utf8(passphrase.normalize('NFC'))), 'PBKDF2', false, ['deriveKey']);
  return subtle().deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', iterations: kdf.iterations, salt: buf(fromB64u(kdf.salt)) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['wrapKey', 'unwrapKey', 'encrypt', 'decrypt'],
  );
}

export const newKdfParams = (iterations = PBKDF2_ITERATIONS): KdfParams => ({
  name: 'PBKDF2',
  hash: 'SHA-256',
  iterations,
  salt: b64u(randomBytes(16)),
});

/**
 * Key file format v1 (saved by the user in a personal location).
 * `format` names the app (for example "mytasker-key"), so that the key file
 * of 1 app is not accepted by another app.
 */
export interface KeyFile {
  format: string;
  v: 1;
  alg: typeof SIG_ALG;
  keyId: string;
  publicKey: string;
  displayName: string;
  createdAt: string;
  kdf: KdfParams;
  wrap: { name: 'AES-GCM'; iv: string };
  wrappedKey: string; // PKCS#8, AES-GCM encrypted
}

export async function wrapSigningKey(
  key: GeneratedKey,
  passphrase: string,
  displayName: string,
  now: Date,
  format: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<KeyFile> {
  if (!Number.isSafeInteger(iterations) || iterations < PBKDF2_MIN_ITERATIONS || iterations > PBKDF2_MAX_ITERATIONS)
    throw new RangeError(`PBKDF2 iterations must be ${PBKDF2_MIN_ITERATIONS} to ${PBKDF2_MAX_ITERATIONS}`);
  // The enrollment refuses an invalid name, so a key file must not have one.
  if (!isValidDisplayName(displayName)) throw new RangeError('invalid display name');
  const kdf = newKdfParams(iterations);
  const kek = await deriveKek(passphrase, kdf);
  const iv = randomBytes(12);
  const wrapped = new Uint8Array(await subtle().wrapKey('pkcs8', key.privateKey, kek, { name: 'AES-GCM', iv: buf(iv) }));
  return {
    format,
    v: 1,
    alg: SIG_ALG,
    keyId: key.keyId,
    publicKey: key.publicKey,
    displayName,
    createdAt: now.toISOString(),
    kdf,
    wrap: { name: 'AES-GCM', iv: b64u(iv) },
    wrappedKey: b64u(wrapped),
  };
}

export class WrongPassphraseError extends Error {
  constructor() {
    super('wrong passphrase or damaged key file');
  }
}

/**
 * Unwraps the key file into a NON-extractable signing key. Throws Error('unsupported key file'),
 * before the slow key derivation, in these cases: the file is for another format; the KDF parameters
 * are not acceptable (isAcceptableKdf); `wrap.name` is not "AES-GCM"; the public key is not
 * acceptable (isAcceptableEd25519PublicKey); the keyId is not the keyId of the public key.
 */
export async function unwrapSigningKey(file: KeyFile, passphrase: string, format: string): Promise<{ privateKey: CryptoKey; kek: CryptoKey }> {
  if (typeof file !== 'object' || file === null || file.format !== format || file.v !== 1 || file.alg !== SIG_ALG) throw new Error('unsupported key file');
  if (!isAcceptableKdf(file.kdf) || typeof file.wrap !== 'object' || file.wrap === null || file.wrap.name !== 'AES-GCM') throw new Error('unsupported key file');
  let keyOk = false;
  try {
    keyOk = isAcceptableEd25519PublicKey(fromB64u(file.publicKey)) && (await keyIdFromPublicKey(file.publicKey)) === file.keyId;
  } catch {
    /* not base64url: keyOk stays false */
  }
  if (!keyOk) throw new Error('unsupported key file');
  const kek = await deriveKek(passphrase, file.kdf);
  try {
    const privateKey = await subtle().unwrapKey(
      'pkcs8',
      buf(fromB64u(file.wrappedKey)),
      kek,
      { name: 'AES-GCM', iv: buf(fromB64u(file.wrap.iv)) },
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
    // Check that the private key belongs to the public key in the file.
    const probe = utf8('probe:' + file.keyId);
    const ok = await verifyBytes(await importPublicKey(file.publicKey), await signBytes(privateKey, probe), probe);
    if (!ok || (await keyIdFromPublicKey(file.publicKey)) !== file.keyId) throw new Error('key mismatch');
    return { privateKey, kek };
  } catch (e) {
    if (e instanceof Error && e.message === 'key mismatch') throw new Error('key file is inconsistent');
    throw new WrongPassphraseError();
  }
}

// ---- AES-GCM for the local cache ---------------------------------------------

export async function generateAesKey(extractable = true): Promise<CryptoKey> {
  return subtle().generateKey({ name: 'AES-GCM', length: 256 }, extractable, ['encrypt', 'decrypt']);
}

export async function wrapAesKey(key: CryptoKey, kek: CryptoKey): Promise<{ iv: string; wrapped: string }> {
  const iv = randomBytes(12);
  const wrapped = new Uint8Array(await subtle().wrapKey('raw', key, kek, { name: 'AES-GCM', iv: buf(iv) }));
  return { iv: b64u(iv), wrapped: b64u(wrapped) };
}

export async function unwrapAesKey(w: { iv: string; wrapped: string }, kek: CryptoKey): Promise<CryptoKey> {
  return subtle().unwrapKey(
    'raw',
    buf(fromB64u(w.wrapped)),
    kek,
    { name: 'AES-GCM', iv: buf(fromB64u(w.iv)) },
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}

export async function encryptJson(key: CryptoKey, value: unknown): Promise<{ iv: string; ct: string }> {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await subtle().encrypt({ name: 'AES-GCM', iv: buf(iv) }, key, buf(utf8(JSON.stringify(value)))));
  return { iv: b64u(iv), ct: b64u(ct) };
}

export async function decryptJson<T>(key: CryptoKey, box: { iv: string; ct: string }): Promise<T> {
  const pt = new Uint8Array(await subtle().decrypt({ name: 'AES-GCM', iv: buf(fromB64u(box.iv)) }, key, buf(fromB64u(box.ct))));
  return JSON.parse(new TextDecoder().decode(pt)) as T;
}
