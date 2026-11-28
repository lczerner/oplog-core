// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import {
  decryptJson, encryptJson, fingerprint, generateAesKey, generateSigningKey, importPublicKey, keyIdFromPublicKey,
  signBytes, unwrapAesKey, unwrapSigningKey, verifyBytes, wrapAesKey, wrapSigningKey, WrongPassphraseError, deriveKek, newKdfParams,
  PBKDF2_MIN_ITERATIONS,
} from '../../src/crypto';
import { b64u, base32, fromB64u, utf8 } from '../../src/encoding';
import { nameUuid, uuidv7 } from '../../src/ids';
import { KEY_ID_RE } from '../../src/paths';

describe('encoding', () => {
  it('base64url round-trips all lengths', () => {
    for (let n = 0; n < 40; n++) {
      const b = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 255);
      expect(fromB64u(b64u(b))).toEqual(b);
      expect(b64u(b)).toBe(Buffer.from(b).toString('base64url'));
    }
  });
  it('base32 matches RFC 4648 test vectors (lower case, no padding)', () => {
    const v: [string, string][] = [['', ''], ['f', 'my'], ['fo', 'mzxq'], ['foo', 'mzxw6'], ['foob', 'mzxw6yq'], ['fooba', 'mzxw6ytb'], ['foobar', 'mzxw6ytboi']];
    for (const [i, o] of v) expect(base32(utf8(i))).toBe(o);
  });
});

describe('Ed25519 signatures', () => {
  it('signs and verifies; rejects changed data and wrong keys', async () => {
    const k = await generateSigningKey();
    const other = await generateSigningKey();
    const data = utf8('hello');
    const sig = await signBytes(k.privateKey, data);
    const pub = await importPublicKey(k.publicKey);
    expect(await verifyBytes(pub, sig, data)).toBe(true);
    expect(await verifyBytes(pub, sig, utf8('hellO'))).toBe(false);
    expect(await verifyBytes(await importPublicKey(other.publicKey), sig, data)).toBe(false);
    expect(await verifyBytes(pub, 'not-a-signature', data)).toBe(false);
  });

  it('signatures are deterministic (fixed test vector, RFC 8032 test 1)', async () => {
    const sk = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
    const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), sk]);
    const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
    const sig = Buffer.from(fromB64u(await signBytes(key, new Uint8Array()))).toString('hex');
    expect(sig).toBe('e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b');
  });

  it('key IDs match the pattern and the fingerprint has 5 groups', async () => {
    const k = await generateSigningKey();
    expect(k.keyId).toMatch(KEY_ID_RE);
    expect(await keyIdFromPublicKey(k.publicKey)).toBe(k.keyId);
    expect(fingerprint(k.keyId)).toMatch(/^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$/);
  });
});

describe('key file wrapping', () => {
  it('wraps with a passphrase and unwraps into a non-extractable key', async () => {
    const k = await generateSigningKey();
    const file = await wrapSigningKey(k, 'správné heslo', 'Test User', new Date('2026-01-01T00:00:00Z'), 'test-key', PBKDF2_MIN_ITERATIONS);
    expect(file.kdf.iterations).toBe(PBKDF2_MIN_ITERATIONS);
    expect(JSON.stringify(file)).not.toContain('PRIVATE');
    const { privateKey } = await unwrapSigningKey(file, 'správné heslo', 'test-key');
    expect(privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey('pkcs8', privateKey)).rejects.toThrow();
    const sig = await signBytes(privateKey, utf8('x'));
    expect(await verifyBytes(await importPublicKey(k.publicKey), sig, utf8('x'))).toBe(true);
    await expect(unwrapSigningKey(file, 'wrong', 'test-key')).rejects.toBeInstanceOf(WrongPassphraseError);
  });

  it('does not accept the key file of another app', async () => {
    const k = await generateSigningKey();
    const file = await wrapSigningKey(k, 'p', 'n', new Date(), 'app-a-key', PBKDF2_MIN_ITERATIONS);
    await expect(unwrapSigningKey(file, 'p', 'app-b-key')).rejects.toThrow('unsupported key file');
  });

  it('uses 600 000 PBKDF2 iterations by default', async () => {
    const k = await generateSigningKey();
    const file = await wrapSigningKey(k, 'p', 'n', new Date(), 'test-key');
    expect(file.kdf.iterations).toBe(600_000);
  });

  it('cache key wrap and AES-GCM JSON encryption', async () => {
    const kek = await deriveKek('heslo', newKdfParams(PBKDF2_MIN_ITERATIONS));
    const ck = await generateAesKey();
    const w = await wrapAesKey(ck, kek);
    const ck2 = await unwrapAesKey(w, kek);
    const box = await encryptJson(ck, { a: 'Žluť', n: 1 });
    expect(await decryptJson(ck2, box)).toEqual({ a: 'Žluť', n: 1 });
    const bad = { ...box, ct: box.ct.slice(0, -2) + (box.ct.endsWith('A') ? 'BB' : 'AA') };
    await expect(decryptJson(ck2, bad)).rejects.toThrow();
  });
});

describe('ids', () => {
  it('uuidv7 is time ordered and has version 7', () => {
    const a = uuidv7(1000), b = uuidv7(2000);
    expect(a < b).toBe(true);
    expect(a[14]).toBe('7');
  });
  it('name-based UUID is stable', async () => {
    expect(await nameUuid('person', 'O001')).toBe(await nameUuid('person', 'O001'));
    expect(await nameUuid('person', 'O001')).not.toBe(await nameUuid('course', 'O001'));
    expect((await nameUuid('person', 'O001'))[14]).toBe('8');
  });
});
