// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Enrollment requests: enroll/<name>-<keyIdShort>.json, self-signed by the new key.
// `format` names the app (for example "mytasker-enroll").

import { canonicalize } from './canonical';
import { importPublicKey, keyIdFromPublicKey, verifyBytes } from './crypto';
import { utf8 } from './encoding';
import { ENROLL_DIR } from './paths';
import type { Storage } from './storage/types';
import { isIso, isPlainObject, isValidDisplayName } from './validate';

export interface EnrollmentRequest {
  format: string;
  v: 1;
  displayName: string;
  keyId: string;
  alg: 'Ed25519';
  publicKey: string;
  createdAt: string; // self-reported
  sig: string;
}

/** The name part of the file: no diacritics, lowercase, only a-z and 0-9, "-" between, max 32 characters. */
export const slug = (s: string): string =>
  s
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 32)
    .replace(/-$/, '') || 'user';

export const enrollmentPath = (displayName: string, keyId: string): string => `${ENROLL_DIR}/${slug(displayName)}-${keyId.slice(1, 9)}.json`;

/** The maximum size of an enrollment file in bytes. listEnrollments does not read a larger file. */
export const MAX_ENROLLMENT_BYTES = 64 * 1024;

/** Makes a self-signed request. Throws if the display name is not valid (isValidDisplayName). */
export async function createEnrollment(format: string, displayName: string, keyId: string, publicKey: string, now: Date, sign: (b: Uint8Array) => Promise<string>): Promise<EnrollmentRequest> {
  if (!isValidDisplayName(displayName)) throw new Error('invalid display name');
  const rest = { format, v: 1 as const, displayName, keyId, alg: 'Ed25519' as const, publicKey, createdAt: now.toISOString() };
  return { ...rest, sig: await sign(utf8(canonicalize(rest))) };
}

export async function verifyEnrollment(r: EnrollmentRequest, format: string): Promise<boolean> {
  try {
    if (!isPlainObject(r) || r.format !== format || r.v !== 1 || r.alg !== 'Ed25519') return false;
    if (!isValidDisplayName(r.displayName)) return false;
    if (typeof r.keyId !== 'string' || typeof r.publicKey !== 'string' || typeof r.sig !== 'string' || !isIso(r.createdAt)) return false;
    if ((await keyIdFromPublicKey(r.publicKey)) !== r.keyId) return false;
    const { sig, ...rest } = r;
    return await verifyBytes(await importPublicKey(r.publicKey), sig, utf8(canonicalize(rest)));
  } catch {
    return false;
  }
}

export interface EnrollmentEntry {
  path: string;
  /** The request if it is valid (checked format, fields and self-signature), else null. */
  request: EnrollmentRequest | null;
  valid: boolean;
}

/**
 * All requests in enroll/. Names with characters that the storage refuses are skipped.
 * A file that is larger than MAX_ENROLLMENT_BYTES, or that the storage cannot read, gives an invalid entry.
 */
export async function listEnrollments(storage: Storage, format: string): Promise<EnrollmentEntry[]> {
  const out: EnrollmentEntry[] = [];
  for (const f of (await storage.list(ENROLL_DIR)) ?? []) {
    if (f.kind !== 'file' || !f.name.endsWith('.json') || /[\\:/]/.test(f.name)) continue;
    const path = `${ENROLL_DIR}/${f.name}`;
    let data: unknown = null;
    try {
      data = JSON.parse((await storage.read(path, { maxBytes: MAX_ENROLLMENT_BYTES })) ?? '');
    } catch {
      /* invalid: FileTooLargeError, a read error or bad JSON */
    }
    const valid = await verifyEnrollment(data as EnrollmentRequest, format);
    out.push({ path, request: valid ? (data as EnrollmentRequest) : null, valid });
  }
  return out;
}
