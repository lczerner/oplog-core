// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// RFC 8785 JSON Canonicalization Scheme (JCS).
//
// - Object keys are sorted by UTF-16 code units (the default JS string order).
// - Strings use the ECMAScript JSON.stringify escaping (as RFC 8785 requires).
// - Numbers use the ECMAScript Number-to-string conversion (as RFC 8785 requires).
//   NaN and Infinity are rejected. The app's payloads use integers only.
// - Object members with the value `undefined` are rejected, so that two
//   different in-memory objects can never give the same bytes by accident.

export class CanonicalError extends Error {}

export function canonicalize(value: unknown): string {
  switch (typeof value) {
    case 'string':
      return JSON.stringify(value);
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new CanonicalError('non-finite number');
      return Object.is(value, -0) ? '0' : String(value);
    case 'object': {
      if (value === null) return 'null';
      if (Array.isArray(value)) return '[' + value.map((v) => canonicalize(v)).join(',') + ']';
      const proto = Object.getPrototypeOf(value);
      if (proto !== Object.prototype && proto !== null) throw new CanonicalError('only plain objects are allowed');
      const keys = Object.keys(value as object).sort();
      const parts: string[] = [];
      for (const k of keys) {
        const v = (value as Record<string, unknown>)[k];
        if (v === undefined) throw new CanonicalError(`undefined value for key "${k}"`);
        parts.push(JSON.stringify(k) + ':' + canonicalize(v));
      }
      return '{' + parts.join(',') + '}';
    }
    default:
      throw new CanonicalError(`unsupported type ${typeof value}`);
  }
}
