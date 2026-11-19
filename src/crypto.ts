// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// WebCrypto helpers: SHA-256, Ed25519, PBKDF2 key wrapping, AES-GCM.
// Works in the browser and in Node 22 (globalThis.crypto). No DOM access.

import { canonicalize } from './canonical';
import { b64u, base32, fromB64u, hex, utf8 } from './encoding';

const subtle = (): SubtleCrypto => {
  const s = globalThis.crypto?.subtle;
  if (!s) throw new Error('WebCrypto is not available');
  return s;
};

export const SIG_ALG = 'Ed25519' as const;
export const PBKDF2_ITERATIONS = 600_000;

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

export async function importPublicKey(publicKeyB64u: string): Promise<CryptoKey> {
  return subtle().importKey('raw', buf(fromB64u(publicKeyB64u)), { name: 'Ed25519' }, false, ['verify']);
}

export async function signBytes(privateKey: CryptoKey, data: Uint8Array): Promise<string> {
  return b64u(new Uint8Array(await subtle().sign({ name: 'Ed25519' }, privateKey, buf(data))));
}

export async function verifyBytes(publicKey: CryptoKey, sigB64u: string, data: Uint8Array): Promise<boolean> {
  let sig: Uint8Array;
  try {
    sig = fromB64u(sigB64u);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  return subtle().verify({ name: 'Ed25519' }, publicKey, buf(sig), buf(data));
}

// ---- Passphrase wrapping (key file and cache key) -----------------------------

export interface KdfParams {
  name: 'PBKDF2';
  hash: 'SHA-256';
  iterations: number;
  salt: string; // base64url
}

export async function deriveKek(passphrase: string, kdf: KdfParams): Promise<CryptoKey> {
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

/** Unwraps the key file into a NON-extractable signing key. */
export async function unwrapSigningKey(file: KeyFile, passphrase: string, format: string): Promise<{ privateKey: CryptoKey; kek: CryptoKey }> {
  if (file.format !== format || file.v !== 1 || file.alg !== SIG_ALG) throw new Error('unsupported key file');
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
