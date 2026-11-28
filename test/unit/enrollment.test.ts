// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { generateSigningKey, signBytes } from '../../src/crypto';
import { createEnrollment, enrollmentPath, listEnrollments, slug } from '../../src/enrollment';
import { MemoryStorage } from '../../src/storage/memory';

describe('enrollment requests', () => {
  it('makes a safe file name and a self-signed request that verifies only for its own format', async () => {
    expect(slug('Věra Malá-Nováková')).toBe('vera-mala-novakova');
    expect(slug('../../x')).toBe('x');
    expect(slug('ěščř')).toBe('escr');
    expect(slug('???')).toBe('user');
    const k = await generateSigningKey();
    const r = await createEnrollment('app-enroll', 'Věra Malá', k.keyId, k.publicKey, new Date('2026-11-19T10:00:00Z'), (b) => signBytes(k.privateKey, b));
    const s = new MemoryStorage();
    await s.writeNew(enrollmentPath(r.displayName, r.keyId), JSON.stringify(r));
    await s.writeNew('enroll/forged.json', JSON.stringify({ ...r, displayName: 'Jiné jméno' }));
    await s.writeNew('enroll/garbage.json', 'x');
    const list = await listEnrollments(s, 'app-enroll');
    expect(list.map((e) => [e.path.startsWith('enroll/vera-mala-'), e.valid]).sort()).toEqual([[false, false], [false, false], [true, true]]);
    expect((await listEnrollments(s, 'other-enroll')).some((e) => e.valid)).toBe(false);
  });
});

describe('enrollment validation', () => {
  it('rejects a self-signed request with a bad createdAt or non-string fields', async () => {
    const { canonicalize } = await import('../../src/canonical');
    const { utf8 } = await import('../../src/encoding');
    const { verifyEnrollment } = await import('../../src/enrollment');
    const k = await generateSigningKey();
    const rest = { format: 'app-enroll', v: 1 as const, displayName: 'X', keyId: k.keyId, alg: 'Ed25519' as const, publicKey: k.publicKey, createdAt: 'x' };
    const bad = { ...rest, sig: await signBytes(k.privateKey, utf8(canonicalize(rest))) };
    expect(await verifyEnrollment(bad, 'app-enroll')).toBe(false);
    expect(await verifyEnrollment(5 as never, 'app-enroll')).toBe(false);
  });
});

describe('enrollment display name and file size', () => {
  const selfSigned = async (fields: Record<string, unknown>) => {
    const { canonicalize } = await import('../../src/canonical');
    const { utf8 } = await import('../../src/encoding');
    const k = await generateSigningKey();
    const rest = { format: 'app-enroll', v: 1 as const, displayName: 'X', keyId: k.keyId, alg: 'Ed25519' as const, publicKey: k.publicKey, createdAt: '2026-11-19T10:00:00.000Z', ...fields };
    return { ...rest, sig: await signBytes(k.privateKey, utf8(canonicalize(rest))) };
  };
  const BAD_NAMES = ['', '   ', 'A\nB', 'A\tB', 'A\u0000B', 'A\u007fB', 'A\u0085B', 'Admin\u202eB', 'A\u2066B', 'A\u200fB', 'A\u061cB', 'A\u2028B', 'x'.repeat(201),
    // only white space or invisible characters (fixed lists, not String.prototype.trim)
    '\u200b', '\u2800\u3164', '\u00ad\ufeff', '\u115f\u1160\uffa0', '\u180e', '\u2060\u200c\u200d', ' \u200b\u00a0\u3000', '\ufe0f\u034f', '\u17b4\u17b5',
    // only invisible characters outside the BMP (surrogate pairs)
    '\u{E0041}\u{E0042}', '\u{E0000}\u{E007F}', '\u{E0100}\u{E01EF}', '\u{1D173}\u{1D17A}', '\u{1BCA0}\u{1BCA3}', '\u{E0020} \u200b\u{1D175}'];

  it('rejects a self-signed request with control or bidi characters, an empty name or a long name', async () => {
    const { verifyEnrollment } = await import('../../src/enrollment');
    const { isValidDisplayName } = await import('../../src/validate');
    for (const name of BAD_NAMES) {
      expect([name, isValidDisplayName(name)]).toEqual([name, false]);
      expect([name, await verifyEnrollment((await selfSigned({ displayName: name })) as never, 'app-enroll')]).toEqual([name, false]);
    }
    for (const name of ['Věra Malá', 'x'.repeat(200), ' Jan ', 'جان', '李小龙', 'A\u200bB', '\u2800x', '.', '\u{E0041}\u{E0042}x', 'x\u{1D173}\u{1D17A}', '\u{1BCA0}\u{1BCA3}\u{E0100}y', '\u{1F600}', '\u{1D172}', '\u{1BC9F}', '\u{E0080}', '\u{E01F0}'])
      expect([name, await verifyEnrollment((await selfSigned({ displayName: name })) as never, 'app-enroll')]).toEqual([name, true]);
    expect(await verifyEnrollment((await selfSigned({ displayName: 5 })) as never, 'app-enroll')).toBe(false);
  });

  it('createEnrollment refuses an invalid display name', async () => {
    const k = await generateSigningKey();
    for (const name of BAD_NAMES)
      await expect(createEnrollment('app-enroll', name, k.keyId, k.publicKey, new Date(), (b) => signBytes(k.privateKey, b))).rejects.toThrow('invalid display name');
  });

  it('reads each file with a size limit; a larger file is an invalid entry, not an exception', async () => {
    const { MAX_ENROLLMENT_BYTES } = await import('../../src/enrollment');
    expect(MAX_ENROLLMENT_BYTES).toBe(64 * 1024);
    const s = new MemoryStorage();
    // A valid self-signed request with a large extra field: the signature covers the field.
    const big = await selfSigned({ note: 'x'.repeat(MAX_ENROLLMENT_BYTES) });
    const small = await selfSigned({ note: 'x'.repeat(1000) });
    await s.writeNew('enroll/big.json', JSON.stringify(big));
    await s.writeNew('enroll/small.json', JSON.stringify(small));
    const read = vi.spyOn(s, 'read');
    const list = await listEnrollments(s, 'app-enroll');
    expect(list.map((e) => [e.path, e.valid]).sort()).toEqual([['enroll/big.json', false], ['enroll/small.json', true]]);
    expect(read).toHaveBeenCalledTimes(2);
    for (const c of read.mock.calls) expect(c[1]).toEqual({ maxBytes: MAX_ENROLLMENT_BYTES });
  });
});
