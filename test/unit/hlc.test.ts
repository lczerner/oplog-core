// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { compareHlc, HlcClock } from '../../src/hlc';

describe('HlcClock', () => {
  it('is monotonic when the wall clock stands still or goes back', () => {
    let t = 1000;
    const c = new HlcClock(() => t);
    const a = c.tick();
    const b = c.tick();
    t = 500;
    const d = c.tick();
    expect(compareHlc(b, a)).toBeGreaterThan(0);
    expect(compareHlc(d, b)).toBeGreaterThan(0);
    expect(d.t).toBe(1000);
  });
  it('orders after observed remote timestamps', () => {
    const c = new HlcClock(() => 1000);
    c.observe({ t: 5000, c: 3 });
    const x = c.tick();
    expect(x).toEqual({ t: 5000, c: 4 });
  });
  it('uses the wall clock when it is ahead', () => {
    let t = 1000;
    const c = new HlcClock(() => t);
    c.tick();
    t = 2000;
    expect(c.tick()).toEqual({ t: 2000, c: 0 });
  });
});
