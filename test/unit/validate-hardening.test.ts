// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// The URL check of the replay (isUrl) and the own-field check of checkObject.
import { checkObject, checkValue, isUrl } from '../../src/validate';

const ALL = ['http:', 'https:', 'ws:', 'wss:', 'ftp:', 'file:', 'mailto:', 'tel:', 'urn:', 'x-app+v1.2:'];
// The characters that isUrl always refuses (control, bidi, white space).
const REFUSED_CHARS = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c\s]/;

const nodeAccepts = (u: string): boolean => {
  try {
    new URL(u);
    return true;
  } catch {
    return false;
  }
};

/** True if the WHATWG parser of Node accepts `u`, and isUrl must also accept it (see the comment of isUrl). */
function mustAccept(u: string, schemes: readonly string[]): boolean {
  if (!nodeAccepts(u) || REFUSED_CHARS.test(u)) return false;
  const m = /^([A-Za-z][A-Za-z0-9+.-]*):/.exec(u);
  return !!m && schemes.includes(m[1].toLowerCase() + ':');
}

const ACCEPT = [
  // ASCII
  'https://example.com',
  'https://example.com/',
  'http://example.com/a/b?c=d&e=f#g',
  'HTTPS://EXAMPLE.COM/PATH',
  'hTtP://Example.Com',
  'http://localhost',
  'http://localhost:3000/x',
  'http://127.0.0.1:8080/',
  'http://0x7f.1/',
  'http://a.b.c.d.e.f.example/',
  'https://example.com./',
  'https://sub_domain.example.com/',
  'https://ex-ample.com/~user/',
  'https://example.com/a;b=c,d!$&\'()*+=:@/',
  'https://example.com/?q=a+b&r=%20x',
  'https://example.com/#a:b/c?d',
  'https://example.com/a%2Fb%zz%',
  'http://ex%41mple.com/',
  'https://example.com?q',
  'https://example.com#frag',
  'https://example.com/{x}|^`"<>',
  'ws://example.com/socket',
  'wss://example.com:443/socket',
  'ftp://ftp.example.com/pub/file.txt',
  // WHATWG accepts 0 or more slashes after a special scheme.
  'http:example.com',
  'http:/example.com',
  'http:///example.com',
  'https:////example.com/x',
  // Ports
  'http://example.com:0/',
  'http://example.com:65535/',
  'http://example.com:0080/',
  'http://example.com:000000000065535/',
  'http://example.com:/',
  'http://example.com:',
  // IPv6
  'http://[::1]/',
  'http://[::1]:8080/',
  'http://[2001:db8::1]/a',
  'http://[2001:DB8:0:0:8:800:200C:417A]/',
  'http://[::ffff:192.168.0.1]/',
  'http://user:pass@[::1]:1/',
  // Userinfo
  'https://user@example.com/',
  'https://user:pass@example.com:8443/x',
  'https://user:p%40ss@example.com/',
  'http://a@b@c/',
  'http://@example.com/',
  'http://:@example.com/',
  'http://example.com:80@evil.example/',
  'http://u[x]@example.com/',
  // Unicode (IDN) hosts and non-ASCII paths, raw and encoded
  'https://příklad.cz/úkol?q=č#ř',
  'https://xn--pklad-zsa96e.cz/%C3%BAkol?q=%C4%8D#%C5%99',
  'https://münchen.de/straße',
  'https://例え.テスト/パス',
  'https://пример.рф/',
  'https://ｅｘａｍｐｌｅ.com/',
  'https://☃.net/',
  'https://example.com/😀?😀#😀',
  'https://عربي.example/',
  // file
  'file:///etc/hosts',
  'file://localhost/etc/hosts',
  'file://host/share/x',
  'file:/x',
  'file:x',
  'file:',
  'file://',
  'FILE:///C:/x',
  // mailto and other non-special schemes
  'mailto:someone@example.com',
  'mailto:someone@example.com?subject=Ahoj%20sv%C4%9Bte&body=x',
  'mailto:jméno@příklad.cz',
  'mailto:a@b,c@d',
  'MAILTO:X@Y',
  'mailto:?to=a@b',
  'tel:+420123456789',
  'urn:isbn:0451450523',
  'x-app+v1.2:anything',
  'mailto://x',
  'mailto:%',
  'mailto:',
  'tel:',
  'mailto:a\\b',
  'x-app+v1.2:\\\\x',
  // A backslash: WHATWG keeps it in the query and the fragment, and reads it as "/" in a special path and authority.
  'https://example.com/?q=a\\b',
  'https://example.com/#a\\b',
  'https://regex101.com/?regex=\\d%2B',
  'https://example.com/a\\b',
  'https:\\\\example.com\\x',
  'http:\\/example.com',
  'http://example.com\\x',
  'file:\\\\server\\x',
  'file:c:\\x',
];

const REFUSE: [string, readonly string[]][] = [
  ['javascript:alert(1)', ALL],
  ['JaVaScRiPt:alert(1)', ALL],
  ['data:text/html,x', ALL],
  ['vbscript:x', ALL],
  ['https://example.com', ['http:', 'mailto:']],
  ['/relative/path', ALL],
  ['//example.com/x', ALL],
  ['example.com', ALL],
  ['', ALL],
  [':', ALL],
  ['1http://x', ALL],
  ['ht tp://x', ALL],
  ['-http://x', ALL],
  ['http//x', ALL],
  // control characters, white space, backslash, bidi
  [' https://example.com', ALL],
  ['https://example.com ', ALL],
  ['https://exa mple.com', ALL],
  ['https://example.com/a b', ALL],
  ['https://example.com/\ta', ALL],
  ['https://example.com/\na', ALL],
  ['https://example.com/\u0000', ALL],
  ['https://example.com/\u007f', ALL],
  ['https://example.com/\u0085', ALL],
  ['https://example.com/\u00a0', ALL],
  ['https://example.com/\u3000', ALL],
  ['https://example.com/\ufeff', ALL],
  ['https://example.com/\u2028', ALL],
  ['https://example.com/\u202e', ALL],
  ['https://example.com/\u2066', ALL],
  ['https://example.com/\u200f', ALL],
  // a backslash ends the authority of a special URL, so the host check applies
  ['https:\\\\', ALL],
  ['https:\\\\\\', ALL],
  ['https:\\\\evil.com:99999', ALL],
  ['http:\\\\a<b/', ALL],
  ['http://user@\\x', ALL],
  // a special scheme without a host
  ['http:', ALL],
  ['http:/', ALL],
  ['http://', ALL],
  ['http:///', ALL],
  ['http://?q', ALL],
  ['http://#f', ALL],
  ['http://user@/', ALL],
  ['http://user@', ALL],
  ['http://:80/', ALL],
  ['http://@/', ALL],
  ['ws://', ALL],
  ['ftp:', ALL],
  // bad ports
  ['http://example.com:65536/', ALL],
  ['http://example.com:99999/', ALL],
  ['http://example.com:123456/', ALL],
  ['http://example.com:8o/', ALL],
  ['http://example.com:-1/', ALL],
  ['http://example.com:+80/', ALL],
  ['http://example.com:80:80/', ALL],
  ['http://example.com:1e3/', ALL],
  // bad hosts
  ['http://exa<mple.com/', ALL],
  ['http://exa>mple.com/', ALL],
  ['http://exa^mple.com/', ALL],
  ['http://exa|mple.com/', ALL],
  ['http://exa[mple.com/', ALL],
  ['http://a]b/', ALL],
  ['http://[::1/', ALL],
  ['http://[::1]x/', ALL],
  ['http://[::1]]/', ALL],
  ['http://[]/', ALL],
  ['http://[1234]/', ALL],
  ['http://[::g]/', ALL],
  ['http://[fe80::1%25eth0]/', ALL],
  ['http://[::1]:65536/', ALL],
];

/** A small deterministic random generator (mulberry32). */
function rng(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

describe('isUrl', () => {
  it('Node accepts each URL of the accept corpus (the corpus is realistic)', () => {
    for (const u of ACCEPT) expect([u, nodeAccepts(u)]).toEqual([u, true]);
  });

  it('accepts each URL of the accept corpus', () => {
    for (const u of ACCEPT) expect([u, isUrl(u, ALL)]).toEqual([u, true]);
  });

  it('refuses each URL of the refuse corpus', () => {
    for (const [u, s] of REFUSE) expect([u, isUrl(u, s)]).toEqual([u, false]);
  });

  it('accepts each URL that Node accepts, if it has no refused character (corpus)', () => {
    for (const u of [...ACCEPT, ...REFUSE.map(([u]) => u)]) if (mustAccept(u, ALL)) expect([u, isUrl(u, ALL)]).toEqual([u, true]);
  });

  it('accepts each URL that Node accepts, if it has no refused character (random URLs)', () => {
    const next = rng(20261128);
    const prefixes = ['http:', 'https:', 'HTTP:', 'ws:', 'wss:', 'ftp:', 'file:', 'mailto:', 'tel:', 'gopher:', 'http://', 'https://', 'http:///', 'ftp://u:p@', 'http://[', 'https://a.b'];
    const parts = ['a', 'b', 'Z', '0', '1', '9', '65535', '65536', ':', '/', '//', '@', '[', ']', '::1', '?', '#', '%', '%41', '%zz', '.', '-', '_', '~', '<', '^', '|', '{', '"', 'é', 'ř', 'ｅ', '例', '😀', '\ud800', 'xn--', '0x7f', '+', ',', ';', '=', '!', '$', '&', "'", '(', '*', '\\', '\\\\'];
    let checked = 0;
    let accepted = 0;
    for (let i = 0; i < 30_000; i++) {
      let u = prefixes[Math.floor(next() * prefixes.length)];
      const n = Math.floor(next() * 10);
      for (let j = 0; j < n; j++) u += parts[Math.floor(next() * parts.length)];
      const schemes = next() < 0.8 ? ALL : ['https:'];
      if (mustAccept(u, schemes)) {
        checked++;
        if (!isUrl(u, schemes)) expect.fail(`isUrl refuses a URL that Node accepts: ${JSON.stringify(u)}`);
      }
      if (isUrl(u, schemes)) accepted++;
    }
    // Make sure that the generator gives a useful number of valid URLs.
    expect(checked).toBeGreaterThan(5000);
    expect(accepted).toBeGreaterThanOrEqual(checked);
  });

  it('needs linear time for long hosts (no backtracking)', () => {
    const n = 100_000;
    const long = [
      'http://[' + '0'.repeat(n) + ']/',
      'http://[' + '0'.repeat(n) + '/',
      'http://[' + ':'.repeat(n) + 'x]/',
      'http://[' + '0'.repeat(n) + ']x',
      'http://' + 'a'.repeat(n) + ':' + '0'.repeat(n) + '1/',
      'http://' + '@'.repeat(n) + 'a/',
      'http://' + '/'.repeat(n) + 'a',
      'http:' + '\\'.repeat(n),
      'a'.repeat(n) + '!',
    ];
    const t0 = performance.now();
    for (const u of long) isUrl(u, ALL);
    // The old IPv6 regex needed about 74 ms for 20 000 characters and grows with n^2 (about 2 s here).
    expect(performance.now() - t0).toBeLessThan(250);
  });

  it('does not use the URL class (the result does not depend on the URL parser of the engine)', () => {
    const saved = globalThis.URL;
    try {
      (globalThis as { URL: unknown }).URL = function () {
        throw new Error('URL must not be used');
      };
      expect(isUrl('https://příklad.cz/úkol', ['https:'])).toBe(true);
      expect(isUrl('https://exa mple.cz/', ['https:'])).toBe(false);
    } finally {
      globalThis.URL = saved;
    }
  });

  it('compares the schemes case-insensitively and needs the colon', () => {
    expect(isUrl('HTTPS://x', ['https:'])).toBe(true);
    expect(isUrl('https://x', ['HTTPS:'])).toBe(true);
    expect(isUrl('https://x', ['https'])).toBe(false);
    expect(isUrl('https://x', [])).toBe(false);
    expect(isUrl(5, ['https:'])).toBe(false);
    expect(isUrl(null, ['https:'])).toBe(false);
  });

  it('checks the maximum length before the URL rules', () => {
    const t = { url: ['https:'], max: 30 } as const;
    expect(checkValue('https://example.com/' + 'a'.repeat(10), t, 'p')).toBeNull();
    expect(checkValue('https://example.com/' + 'a'.repeat(11), t, 'p')).toMatch('longer than 30');
  });
});

describe('checkObject uses own fields only', () => {
  it('does not see an inherited name as a present field', () => {
    for (const k of ['constructor', 'toString', 'hasOwnProperty', 'valueOf', '__proto__', 'isPrototypeOf'])
      expect([k, checkObject({}, { [k]: 'any' })]).toEqual([k, `payload.${k}: missing`]);
    expect(checkObject({}, { 'constructor?': 'str', 'toString?': 'int' })).toBeNull();
  });

  it('checks an own field with an inherited name like any other field', () => {
    expect(checkObject({ constructor: 'x' }, { constructor: 'str' as const })).toBeNull();
    expect(checkObject({ constructor: 5 }, { constructor: 'str' as const })).toMatch('payload.constructor: string expected');
    expect(checkObject(JSON.parse('{"toString":"a"}'), { 'toString?': 'id' })).toBeNull();
    expect(checkObject({ toString: 'a' }, {})).toMatch('unknown field');
  });
});

describe('hasVisibleChar', () => {
  it('ignores invisible characters outside the BMP (surrogate pairs), with exact range limits', async () => {
    const { hasVisibleChar, isValidDisplayName } = await import('../../src/validate');
    const invisible = [0xe0000, 0xe0041, 0xe007f, 0xe0100, 0xe01ef, 0x1d173, 0x1d17a, 0x1bca0, 0x1bca3];
    const outside = [0xdffff, 0xe0080, 0xe00ff, 0xe01f0, 0x1d172, 0x1d17b, 0x1bc9f, 0x1bca4, 0x1f600];
    for (const c of invisible) {
      const s = String.fromCodePoint(c);
      expect([c.toString(16), hasVisibleChar(s + s), isValidDisplayName(s), isValidDisplayName(s + 'a' + s)]).toEqual([c.toString(16), false, false, true]);
    }
    for (const c of outside) expect([c.toString(16), hasVisibleChar(String.fromCodePoint(c))]).toEqual([c.toString(16), true]);
    // A lone surrogate is not removed: it counts as visible (it is not in a list).
    expect(hasVisibleChar('\uDB40')).toBe(true);
  });
});
