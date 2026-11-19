// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Test helpers. All data here is synthetic.
import { canonicalize } from '../src/canonical';
import { generateSigningKey, hashCanonical, signBytes } from '../src/crypto';
import { Engine, type Signer } from '../src/engine';
import type { Hlc } from '../src/hlc';
import { filePath, TRUST_ROOT_PATH } from '../src/paths';
import { MemoryStorage } from '../src/storage/memory';
import type { Storage } from '../src/storage/types';
import type { Envelope, TrustRoot } from '../src/types';
import { signEnvelope } from '../src/verify';
import { notesDomain } from './notes-domain';

export interface Actor {
  name: string;
  userId: string;
  keyId: string;
  publicKey: string;
  signer: Signer;
  engine: Engine;
}

/** A fake clock. Each call moves 1 second forward. */
export function fakeClock(start = Date.parse('2026-01-01T08:00:00Z')) {
  let t = start;
  const now = () => (t += 1000);
  return { now, set: (v: number) => (t = v) };
}

export async function makeKey(name: string) {
  const k = await generateSigningKey();
  const signer: Signer = { keyId: k.keyId, sign: (b) => signBytes(k.privateKey, b) };
  return { ...k, name, userId: `u-${name}`, signer };
}

export async function actor(name: string, storage: Storage, now = fakeClock().now): Promise<Actor> {
  const k = await makeKey(name);
  return { name, userId: k.userId, keyId: k.keyId, publicKey: k.publicKey, signer: k.signer, engine: new Engine(storage, notesDomain, { now }) };
}

/** The same key with a new engine (another computer of the same user). */
export const sameUser = (a: Actor, storage: Storage, now = fakeClock().now): Actor => ({ ...a, engine: new Engine(storage, notesDomain, { now }) });

export async function writeTrustRoot(storage: Storage, roots: { userId: string; name: string; keyId: string; publicKey: string; cutoffs?: Record<string, number> }[]) {
  const tr: TrustRoot = { v: 1, roots: roots.map((r) => ({ userId: r.userId, displayName: r.name, keyId: r.keyId, alg: 'Ed25519', publicKey: r.publicKey, cutoffs: r.cutoffs ?? null })) };
  await storage.writeNew(TRUST_ROOT_PATH, JSON.stringify(tr, null, 2));
}

/** A root admin and a granted user (and optionally a second admin) on 1 storage. */
export async function world(opts: { admin2?: boolean } = {}) {
  const storage = new MemoryStorage();
  const clock = fakeClock();
  const admin = await actor('admin', storage, clock.now);
  await writeTrustRoot(storage, [admin]);
  await admin.engine.scan();
  const user = await actor('user', storage, clock.now);
  await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: user.userId, keyId: user.keyId, publicKey: user.publicKey, admin: false });
  let admin2: Actor | undefined;
  if (opts.admin2) {
    admin2 = await actor('admin2', storage, clock.now);
    await admin.engine.write(admin.signer, 'roles', 'GrantUser', { userId: admin2.userId, keyId: admin2.keyId, publicKey: admin2.publicKey, admin: true });
    await admin2.engine.scan();
  }
  await user.engine.scan();
  return { storage, clock, admin, user, admin2 };
}

/**
 * Writes a hand-made op file (for tests of order, HLC and integrity).
 * Takes the next seq and the prevHash from the files of the author.
 */
export async function rawOp(storage: Storage, a: Actor, scope: string, type: string, payload: Record<string, unknown>, hlc: Hlc, wallTime = new Date(hlc.t).toISOString(), opId?: string): Promise<Envelope> {
  const dir = `${scope}/ops/${a.keyId}`;
  const names = ((await storage.list(dir)) ?? []).map((f) => f.name).filter((n) => /^\d{10}\.json$/.test(n)).sort();
  const seq = names.length + 1;
  const prev = names.length ? JSON.parse((await storage.read(`${dir}/${names[names.length - 1]}`))!) : null;
  const env = await signEnvelope(
    { v: 1, opId: opId ?? `op-${a.name}-${scope}-${seq}`, scope, authorKeyId: a.keyId, seq, prevHash: prev ? await hashCanonical(prev) : null, hlc, wallTime, type, payload },
    (b) => a.signer.sign(b),
  );
  await storage.writeNew(filePath(scope, 'ops', a.keyId, seq), canonicalize(env));
  return env;
}

export const note = (state: { scopes: Record<string, any> }, id: string) => state.scopes.data?.note?.[id];
