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
