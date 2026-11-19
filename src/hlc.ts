// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Hybrid logical clock. An op is always ordered after all ops that its author had seen.

export interface Hlc {
  t: number; // milliseconds since epoch (from the author's clock, merged with seen ops)
  c: number; // counter for equal t
}

export const compareHlc = (a: Hlc, b: Hlc): number => a.t - b.t || a.c - b.c;

/** Upper limits of a valid HLC: the year 9999 and 2^31 - 1. verify.ts rejects larger values. */
export const HLC_MAX_T = 253_402_300_799_999;
export const HLC_MAX_C = 2_147_483_647;

export const isValidHlc = (h: Hlc): boolean => Number.isSafeInteger(h.t) && Number.isSafeInteger(h.c) && h.t >= 0 && h.c >= 0 && h.t <= HLC_MAX_T && h.c <= HLC_MAX_C;

export class HlcClock {
  private last: Hlc = { t: 0, c: 0 };

  constructor(private readonly now: () => number = () => Date.now()) {}

  /** Moves the clock forward to a seen timestamp. */
  observe(h: Hlc): void {
    if (isValidHlc(h) && compareHlc(h, this.last) > 0) this.last = { t: h.t, c: h.c };
  }

  /** Returns a new timestamp, greater than every timestamp seen before. */
  tick(): Hlc {
    const wall = Math.floor(this.now());
    if (Math.min(wall, HLC_MAX_T) > this.last.t) this.last = { t: Math.min(wall, HLC_MAX_T), c: 0 };
    else if (this.last.c < HLC_MAX_C) this.last = { t: this.last.t, c: this.last.c + 1 };
    else if (this.last.t < HLC_MAX_T) this.last = { t: this.last.t + 1, c: 0 };
    else throw new Error('HLC is at its upper limit');
    return { ...this.last };
  }

  peek(): Hlc {
    return { ...this.last };
  }
}
