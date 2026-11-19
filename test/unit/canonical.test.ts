// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { canonicalize, CanonicalError } from '../../src/canonical';

describe('canonicalize (RFC 8785 JCS)', () => {
  it('sorts keys by UTF-16 code units and removes whitespace', () => {
    // RFC 8785 section 3.2.3 sorting example. Keys built from code points (ASCII-only source).
    const k = (...cp: number[]) => String.fromCharCode(...cp);
    const input: Record<string, string> = {};
    input[k(0x20ac)] = 'Euro Sign';
    input[k(0x0d)] = 'Carriage Return';
    input[k(0xfb33)] = 'Hebrew Letter Dalet With Dagesh';
    input['1'] = 'One';
    input[k(0xd83d, 0xde00)] = 'Emoji: Grinning Face';
    input[k(0x80)] = 'Control';
    input[k(0xf6)] = 'Latin Small Letter O With Diaeresis';
    const out = canonicalize(input);
    const order = Object.values(input).sort((x, y) => out.indexOf(x) - out.indexOf(y));
    expect(order).toEqual(['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis', 'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh']);
    expect(canonicalize(input)).not.toMatch(/\s"|":\s/);
  });

  it('serializes numbers like ECMAScript (RFC 8785 §3.2.2.3 examples)', () => {
    expect(canonicalize([333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001])).toBe('[333333333.3333333,1e+30,4.5,0.002,1e-27]');
    expect(canonicalize(-0)).toBe('0');
  });

  it('escapes strings like JSON.stringify (RFC 8785 section 3.2.2.2)', () => {
    const bs = String.fromCharCode(0x5c), q = String.fromCharCode(0x22);
    const str = String.fromCharCode(0x20ac) + '$' + String.fromCharCode(0x0f, 0x0a) + "A'B" + q + bs + bs + q + '/';
    const out = canonicalize({ literals: [null, true, false], string: str });
    const expected = '{"literals":[null,true,false],"string":"' + String.fromCharCode(0x20ac) + '$' + bs + 'u000f' + bs + 'nA' + "'B" + bs + q + bs + bs + bs + bs + bs + q + '/"}';
    expect(out).toBe(expected);
  });

  it('handles nested structures and Czech text', () => {
    expect(canonicalize({ b: [1, { d: 'Žluťoučký kůň', c: null }], a: 'x' })).toBe('{"a":"x","b":[1,{"c":null,"d":"Žluťoučký kůň"}]}');
  });

  it('rejects values that have no canonical form', () => {
    expect(() => canonicalize({ a: undefined })).toThrow(CanonicalError);
    expect(() => canonicalize(NaN)).toThrow(CanonicalError);
    expect(() => canonicalize(new Date())).toThrow(CanonicalError);
    expect(() => canonicalize(1n as unknown)).toThrow(CanonicalError);
  });

  it('gives the same bytes for objects with a different key insertion order', () => {
    expect(canonicalize({ x: 1, y: { b: 2, a: 1 } })).toBe(canonicalize({ y: { a: 1, b: 2 }, x: 1 }));
  });
});
