// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Small payload validator. Each op payload must match its schema exactly:
// unknown keys are errors, so that 2 clients cannot read an op differently.

export type FieldType =
  | 'str' // string, max 20 000 chars
  | 'id' // non-empty ID string
  | 'id?' // ID or null
  | 'date' // YYYY-MM-DD
  | 'date?'
  | 'iso' // ISO 8601 UTC time: YYYY-MM-DDTHH:MM:SS(.sss)Z
  | 'iso?'
  | 'hex64' // 64 lowercase hex characters (SHA-256)
  | 'int' // safe integer
  | 'int?'
  | 'bool' // true or false
  | { text: number; multiline?: boolean; min?: number } // string with a max length, no control characters (line breaks only if multiline)
  | { url: readonly string[]; max: number } // absolute URL with one of these schemes (for example ['http:', 'https:', 'mailto:'])
  | { enum: readonly string[]; nullable?: boolean } // nullable: null is also permitted
  | { list: FieldType; max: number; min?: number }
  | { object: Schema; nullable?: boolean }
  | { map: FieldType; max: number } // object with any keys, values of 1 type
  | 'any';

export type Schema = Record<string, FieldType>;

const ID_RE = /^[A-Za-z0-9._:|/-]{1,120}$/;
const DATE_RE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/;
const ISO_RE = /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{3})?Z$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
// C0 controls except TAB, LF, CR; DEL; C1 controls; line and paragraph separators;
// bidirectional format characters (they can make a text look different from its content).
const CTRL_ML = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;
const CTRL_SL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\u202a-\u202e\u2066-\u2069\u200e\u200f\u061c]/;
export const MAX_STR = 20_000;

/** Names that change the prototype of a JS object when used as a key. Never valid as an ID. */
export const isUnsafeKey = (k: string): boolean => k === '__proto__';
export const isId = (v: unknown): v is string => typeof v === 'string' && ID_RE.test(v) && !isUnsafeKey(v);
/** True if year-month-day is a real calendar day (no Date object, no locale). */
function calendarOk(s: string): boolean {
  const y = Number(s.slice(0, 4));
  const m = Number(s.slice(5, 7));
  const d = Number(s.slice(8, 10));
  const leap = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
  const days = [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m - 1];
  return d >= 1 && d <= days;
}
export const isDate = (v: unknown): v is string => typeof v === 'string' && DATE_RE.test(v) && calendarOk(v);
export const isIso = (v: unknown): v is string => typeof v === 'string' && ISO_RE.test(v) && calendarOk(v);
export const isHex64 = (v: unknown): v is string => typeof v === 'string' && HEX64_RE.test(v);

// White space that the regex class \s matches, as an explicit list. The result of \s depends on the
// Unicode version of the JS engine. This list does not.
const WS_CHARS = '\\t\\n\\v\\f\\r \\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000\\ufeff';
const WS = new RegExp(`[${WS_CHARS}]`);
// Characters that a text shows as nothing or as an empty space: soft hyphen, combining grapheme joiner,
// Hangul fillers, Khmer vowel inherents, Mongolian selectors and vowel separator, zero-width characters,
// invisible operators, deprecated format characters, variation selectors, Braille blank. A fixed list.
const INVISIBLE_CHARS = '\\u00ad\\u034f\\u115f\\u1160\\u17b4\\u17b5\\u180b-\\u180f\\u200b-\\u200d\\u2060-\\u2064\\u206a-\\u206f\\u2800\\u3164\\ufe00-\\ufe0f\\ufeff\\uffa0';
const VISIBLE = new RegExp(`[^${WS_CHARS}${INVISIBLE_CHARS}]`);
// Invisible characters outside the BMP, as UTF-16 surrogate pairs (no "u" flag, so no Unicode tables):
// tag characters U+E0000-U+E007F, variation selectors supplement U+E0100-U+E01EF,
// musical format characters U+1D173-U+1D17A, shorthand format controls U+1BCA0-U+1BCA3.
const INVISIBLE_ASTRAL = /\uDB40[\uDC00-\uDC7F\uDD00-\uDDEF]|\uD834[\uDD73-\uDD7A]|\uD82F[\uDCA0-\uDCA3]/g;

/** True if `s` has at least 1 character that is not white space and not invisible (fixed lists, no Unicode tables). */
export const hasVisibleChar = (s: string): boolean => VISIBLE.test(s.replace(INVISIBLE_ASTRAL, ''));

/**
 * True if `name` is a valid display name (of a key file or an enrollment request): 1 to 200
 * characters, no control and no bidirectional format characters (the single-line text rule), and at
 * least 1 visible character (hasVisibleChar). An admin sees this name, so it must not look different
 * from its content.
 */
export const isValidDisplayName = (name: unknown): name is string =>
  typeof name === 'string' && checkValue(name, { text: 200, min: 1 }, 'displayName') === null && hasVisibleChar(name);

const SCHEME_RE = /^([A-Za-z][A-Za-z0-9+.-]*):/;
/** The WHATWG special schemes that have a host. "file" is special too, but its host can be empty. */
const HOST_SCHEMES: readonly string[] = ['http', 'https', 'ws', 'wss', 'ftp'];
/** ASCII-only lower case. String.prototype.toLowerCase also maps non-ASCII letters. */
const asciiLower = (s: string): string => s.replace(/[A-Z]+/g, (c) => c.toLowerCase());
// The authority of a special URL: after 0 or more "/" or "\", up to "/", "\", "?" or "#" (WHATWG reads "\" as "/").
const AUTHORITY_RE = /^[/\\]*([^/\\?#]*)/;
// The text of an IPv6 address has only hex digits, ":" and "." (an IPv4 end). The caller also
// requires 1 ":". This form has no nested quantifier, so its time is linear.
const IPV6_RE = /^\[[0-9A-Fa-f:.]*\]$/;
// ASCII characters that WHATWG never permits in a host (forbidden host code points). Percent
// decoding and IDNA mapping do not remove an ASCII character, so a host with 1 of them always fails.
const HOST_BAD = /[<>^|[\]]/;

/**
 * True if `v` is an absolute URL with one of the schemes (for example ['https:', 'mailto:']).
 *
 * The replay calls this function, so it must give the same result on all clients. It does not use
 * the URL class, Intl or normalize(): URL parsers and their IDNA tables differ between browser
 * engines and versions. It uses only fixed regular expressions with linear time on UTF-16 code units.
 *
 * Rules:
 * - No control character, no bidirectional format character (CTRL_SL), no white space.
 * - A scheme `[A-Za-z][A-Za-z0-9+.-]*:`. The comparison with `schemes` is ASCII case-insensitive.
 * - http, https, ws, wss, ftp: 0 or more "/" or "\", then an authority up to "/", "\", "?" or "#".
 *   The authority is [userinfo "@"] host [":" port]. The last "@" ends the userinfo. The host is not
 *   empty. An IPv6 host is "[...]". The port has only digits and is at most 65535 (it can be empty).
 * - file: and other schemes (for example mailto:): no more rules. The rest can be empty ("mailto:").
 *
 * Deliberate differences from WHATWG:
 * - WHATWG removes leading and trailing spaces and controls, removes tabs and line breaks, and
 *   percent-encodes other spaces in a path. This check refuses these characters at all positions.
 *   (The old check, with the URL class, refused them too.)
 * - The check accepts a superset of the other WHATWG URLs:
 *   - It does not do IDNA, percent decoding of the host, or IPv4 parsing. Thus it accepts some hosts
 *     that WHATWG refuses (for example "http://%zz/", "http://a.123/", "http://xn--a/").
 *   - It accepts any IPv6 text of hex digits, ":" and "." (for example "http://[1:::::2]/").
 *   - It accepts any text after the authority, any text after "file:" and after a non-special scheme.
 */
export function isUrl(v: unknown, schemes: readonly string[]): v is string {
  if (typeof v !== 'string' || CTRL_SL.test(v) || WS.test(v)) return false;
  const m = SCHEME_RE.exec(v);
  if (!m) return false;
  const scheme = asciiLower(m[1]);
  if (!schemes.some((s) => asciiLower(s) === scheme + ':')) return false;
  if (!HOST_SCHEMES.includes(scheme)) return true;
  const auth = AUTHORITY_RE.exec(v.slice(m[0].length))![1];
  const hostPort = auth.slice(auth.lastIndexOf('@') + 1);
  let host: string;
  let port: string;
  if (hostPort.startsWith('[')) {
    const end = hostPort.indexOf(']') + 1;
    host = hostPort.slice(0, end);
    const after = hostPort.slice(end);
    if (end === 0 || !IPV6_RE.test(host) || !host.includes(':') || (after !== '' && after[0] !== ':')) return false;
    port = after.slice(1);
  } else {
    const c = hostPort.indexOf(':');
    host = c < 0 ? hostPort : hostPort.slice(0, c);
    port = c < 0 ? '' : hostPort.slice(c + 1);
    if (host === '' || HOST_BAD.test(host)) return false;
  }
  if (!/^[0-9]*$/.test(port)) return false;
  const digits = port.replace(/^0+/, '');
  return digits.length <= 5 && Number(digits || '0') <= 65535;
}

export function checkValue(v: unknown, t: FieldType, path: string): string | null {
  if (t === 'any') return null;
  if (typeof t === 'string') {
    switch (t) {
      case 'str':
        return typeof v === 'string' && v.length <= MAX_STR ? null : `${path}: string expected`;
      case 'id':
        return isId(v) ? null : `${path}: id expected`;
      case 'id?':
        return v === null || isId(v) ? null : `${path}: id or null expected`;
      case 'date':
        return isDate(v) ? null : `${path}: date YYYY-MM-DD expected`;
      case 'date?':
        return v === null || isDate(v) ? null : `${path}: date or null expected`;
      case 'iso':
        return isIso(v) ? null : `${path}: ISO UTC time expected`;
      case 'iso?':
        return v === null || isIso(v) ? null : `${path}: ISO UTC time or null expected`;
      case 'hex64':
        return isHex64(v) ? null : `${path}: 64 lowercase hex characters expected`;
      case 'int':
        return Number.isSafeInteger(v) ? null : `${path}: integer expected`;
      case 'int?':
        return v === null || Number.isSafeInteger(v) ? null : `${path}: integer or null expected`;
      case 'bool':
        return typeof v === 'boolean' ? null : `${path}: boolean expected`;
    }
  }
  if ('text' in t) {
    if (typeof v !== 'string') return `${path}: string expected`;
    if (v.length > t.text) return `${path}: longer than ${t.text} characters`;
    if (v.length < (t.min ?? 0)) return `${path}: shorter than ${t.min} characters`;
    return (t.multiline ? CTRL_ML : CTRL_SL).test(v) ? `${path}: control characters are not permitted` : null;
  }
  if ('url' in t) {
    if (typeof v === 'string' && v.length > t.max) return `${path}: longer than ${t.max} characters`;
    return isUrl(v, t.url) ? null : `${path}: URL with scheme ${t.url.join(', ')} expected`;
  }
  if ('enum' in t) {
    if (v === null && t.nullable) return null;
    return typeof v === 'string' && t.enum.includes(v) ? null : `${path}: one of ${t.enum.join(', ')}${t.nullable ? ' or null' : ''} expected`;
  }
  if ('list' in t) {
    if (!Array.isArray(v)) return `${path}: list expected`;
    if (v.length > t.max) return `${path}: too many items`;
    if (v.length < (t.min ?? 0)) return `${path}: at least ${t.min} item(s) expected`;
    for (let i = 0; i < v.length; i++) {
      const e = checkValue(v[i], t.list, `${path}[${i}]`);
      if (e) return e;
    }
    return null;
  }
  if ('object' in t) {
    if (v === null && t.nullable) return null;
    return checkObject(v, t.object, path, true);
  }
  if ('map' in t) {
    if (!isPlainObject(v)) return `${path}: object expected`;
    const keys = Object.keys(v);
    if (keys.length > t.max) return `${path}: too many keys`;
    for (const k of keys) {
      const e = checkValue(v[k], t.map, `${path}.${k}`);
      if (e) return e;
    }
    return null;
  }
  return `${path}: bad schema`;
}

export const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;

/**
 * Checks an object against a schema. Keys that end with "?" in the schema
 * are optional (the "?" is not part of the key).
 */
export function checkObject(v: unknown, schema: Schema, path = 'payload', exact = true): string | null {
  if (!isPlainObject(v)) return `${path}: object expected`;
  const allowed = new Set<string>();
  for (const [rawKey, t] of Object.entries(schema)) {
    const optional = rawKey.endsWith('?');
    const key = optional ? rawKey.slice(0, -1) : rawKey;
    allowed.add(key);
    // Object.hasOwn: an inherited name (for example "constructor") is not a field of the payload.
    if (!Object.hasOwn(v, key)) {
      if (optional) continue;
      return `${path}.${key}: missing`;
    }
    const e = checkValue(v[key], t, `${path}.${key}`);
    if (e) return e;
  }
  if (exact) for (const k of Object.keys(v)) if (!allowed.has(k)) return `${path}.${k}: unknown field`;
  return null;
}
