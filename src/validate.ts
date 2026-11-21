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

/** True if `v` is an absolute URL with one of the schemes. Uses no network and no DOM. */
export function isUrl(v: unknown, schemes: readonly string[]): v is string {
  if (typeof v !== 'string' || CTRL_SL.test(v) || /\s/.test(v)) return false;
  let u: URL;
  try {
    u = new URL(v);
  } catch {
    return false;
  }
  return schemes.includes(u.protocol);
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
    if (!(key in v)) {
      if (optional) continue;
      return `${path}.${key}: missing`;
    }
    const e = checkValue(v[key], t, `${path}.${key}`);
    if (e) return e;
  }
  if (exact) for (const k of Object.keys(v)) if (!allowed.has(k)) return `${path}.${k}: unknown field`;
  return null;
}
