// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Entity IDs.
//  - New entities: UUIDv7 (time-ordered + random).
//  - Name-based IDs: UUID version 8 from SHA-256("<type>|<key>"), for imports of an app.

import { hex } from './encoding';
import { randomBytes, sha256 } from './crypto';
import { utf8 } from './encoding';

function format(b: Uint8Array): string {
  const h = hex(b);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function uuidv7(nowMs: number = Date.now()): string {
  const b = randomBytes(16);
  let t = Math.floor(nowMs);
  for (let i = 5; i >= 0; i--) {
    b[i] = t & 0xff;
    t = Math.floor(t / 256);
  }
  b[6] = (b[6] & 0x0f) | 0x70;
  b[8] = (b[8] & 0x3f) | 0x80;
  return format(b);
}

export async function nameUuid(entityType: string, key: string): Promise<string> {
  const b = (await sha256(utf8(`${entityType}|${key}`))).slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x80;
  b[8] = (b[8] & 0x3f) | 0x80;
  return format(b);
}
