// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { checkObject, checkValue, isUrl } from '../../src/validate';

describe('validator', () => {
  it('checks text length and control characters', () => {
    expect(checkValue('Úkol č. 1', { text: 20 }, 'p')).toBeNull();
    expect(checkValue('x'.repeat(21), { text: 20 }, 'p')).toMatch('longer than 20');
    expect(checkValue('', { text: 20, min: 1 }, 'p')).toMatch('shorter');
    expect(checkValue('a\nb', { text: 20 }, 'p')).toMatch('control');
    expect(checkValue('a\nb\tc', { text: 20, multiline: true }, 'p')).toBeNull();
    expect(checkValue('a\u0007b', { text: 20, multiline: true }, 'p')).toMatch('control');
    expect(checkValue('a b', { text: 20, multiline: true }, 'p')).toMatch('control');
  });

  it('checks URLs by scheme', () => {
    const t = { url: ['http:', 'https:', 'mailto:'], max: 100 } as const;
    expect(checkValue('https://example.invalid/a?b=c', t, 'p')).toBeNull();
    expect(checkValue('mailto:someone@example.invalid', t, 'p')).toBeNull();
    for (const bad of ['javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'data:text/html,x', 'file:///etc/passwd', '/relative', 'https://a b', ' https://x'])
      expect(isUrl(bad, t.url)).toBe(false);
    expect(checkValue('https://' + 'a'.repeat(100), t, 'p')).toMatch('longer');
  });

  it('checks ISO times and SHA-256 hex values', () => {
    expect(checkValue('2026-11-19T13:30:00.000Z', 'iso', 'p')).toBeNull();
    expect(checkValue('2026-11-19T13:30:00Z', 'iso', 'p')).toBeNull();
    expect(checkValue('2026-11-19T13:30:00+01:00', 'iso', 'p')).not.toBeNull();
    expect(checkValue('2026-02-30T00:00:00Z', 'iso', 'p')).not.toBeNull();
    expect(checkValue('2028-02-29T00:00:00Z', 'iso', 'p')).toBeNull();
    expect(checkValue('2100-02-29', 'date', 'p')).not.toBeNull();
    expect(checkValue('a\u202eb', { text: 20 }, 'p')).toMatch('control');
    expect(checkValue(null, 'iso?', 'p')).toBeNull();
    expect(checkValue('a'.repeat(64), 'hex64', 'p')).toBeNull();
    expect(checkValue('A'.repeat(64), 'hex64', 'p')).not.toBeNull();
    expect(checkValue('../' + 'a'.repeat(61), 'hex64', 'p')).not.toBeNull();
  });

  it('rejects unknown fields and accepts optional fields', () => {
    expect(checkObject({ a: 'x' }, { a: 'id', 'b?': 'int' })).toBeNull();
    expect(checkObject({ a: 'x', c: 1 }, { a: 'id' })).toMatch('unknown field');
    expect(checkObject({ o: null }, { o: { object: { x: 'int' }, nullable: true } })).toBeNull();
  });
});
