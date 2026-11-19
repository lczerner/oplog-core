// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// File-name rules. The domain maps scopes to folders (Domain.scopeDir, Domain.scopeFromDir).

export const SEQ_DIGITS = 10;
export const KEY_ID_RE = /^k[a-z2-7]{24}$/;
export const OP_FILE_RE = /^(\d{10})\.json$/;
export const TRUST_ROOT_PATH = 'app/trust-root.json';
export const ENROLL_DIR = 'enroll';

export type FileKind = 'ops' | 'checkpoints';

export const seqName = (seq: number): string => String(seq).padStart(SEQ_DIGITS, '0') + '.json';
/** Path of an op or checkpoint file. `dir` is the folder of the scope. */
export const filePath = (dir: string, kind: FileKind, keyId: string, seq: number): string => `${dir}/${kind}/${keyId}/${seqName(seq)}`;

export interface ParsedPath {
  scope: string;
  kind: FileKind;
  keyId: string;
  seq: number;
}

/**
 * Parses "<scopeDir>/<kind>/<keyId>/<seq>.json". `scopeFromDir` maps the folder
 * to a scope, or returns null. Returns null for any other file name.
 */
export function parsePath(path: string, scopeFromDir: (dir: string) => string | null): ParsedPath | null {
  const p = path.split('/');
  if (p.length < 4) return null;
  const [kind, keyId, file] = p.slice(-3);
  const scope = scopeFromDir(p.slice(0, -3).join('/'));
  if (scope === null) return null;
  if ((kind !== 'ops' && kind !== 'checkpoints') || !KEY_ID_RE.test(keyId)) return null;
  const m = OP_FILE_RE.exec(file);
  if (!m) return null;
  const seq = Number(m[1]);
  if (seq < 1) return null;
  return { scope, kind, keyId, seq };
}
