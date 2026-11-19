// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Revert planning for the UI. The replay computes the same inverse again
// (replay.ts computeInverse) and rejects a Revert with a different inverse.

import { canonicalize } from './canonical';
import { hasOp, REVERT, type Domain, type OpMeta } from './domain';
import { computeInverse, makeCtx, payloadInverse, type ReplayResult } from './replay';
import type { Write } from './types';

export interface Overwritten {
  e: string;
  id: string;
  f: string;
  /** Value that the target op wrote. */
  targetValue: unknown;
  /** Value now (written by a later op). */
  currentValue: unknown;
}

export interface RevertPlan {
  payload: { target: { opId: string; hash: string }; inverse: Write[] };
  /** All writes that the Revert will apply now, also the computed fields. */
  writes: Write[];
  /** Later ops changed these fields. The UI must warn before the user confirms. */
  overwritten: Overwritten[];
}

const same = (a: unknown, b: unknown): boolean => canonicalize(a ?? null) === canonicalize(b ?? null);

/**
 * Plans a Revert of an applied op. `meta` describes the Revert op that the
 * user will write (author, scope, time); the domain can use it for computed fields.
 */
export function planRevert(result: ReplayResult, opId: string, domain: Domain, meta: OpMeta, validKeyBindings: Set<string>): RevertPlan | { error: string } {
  const target = result.applied.get(opId);
  if (!target) return { error: 'op was not applied, so it cannot be reverted' };
  if (target.scope !== meta.scope) return { error: 'revert must be in the scope of its target' };
  for (const t of target.itemTypes) if (t !== REVERT && !(hasOp(domain.catalog, t) && domain.catalog[t].revertible)) return { error: `${t} cannot be reverted` };
  const inv = computeInverse(target, makeCtx(result.state, meta, validKeyBindings), domain);
  if ('superseded' in inv) return { error: inv.superseded };

  const last = new Map<string, Write>();
  for (const w of target.writes) if (!domain.isDerived?.(w.e, w.f)) last.set(`${w.e}|${w.id}|${w.f}`, w);
  const overwritten: Overwritten[] = [];
  for (const w of last.values()) {
    const cur = result.state.scopes[target.scope]?.[w.e]?.[w.id]?.[w.f];
    if (!same(cur, w.v)) overwritten.push({ e: w.e, id: w.id, f: w.f, targetValue: w.v, currentValue: cur ?? null });
  }
  return { payload: { target: { opId, hash: target.hash }, inverse: payloadInverse(inv) }, writes: inv.writes, overwritten };
}
