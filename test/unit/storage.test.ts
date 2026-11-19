// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MemoryStorage } from '../../src/storage/memory';
import { NodeFsStorage } from '../../src/storage/node-fs';
import { FileExistsError, type Storage } from '../../src/storage/types';

async function contract(s: Storage) {
  const bytes = new Uint8Array([0, 1, 2, 255]);
  await s.writeNewBytes('data/files/abc', bytes);
  expect(await s.readBytes('data/files/abc')).toEqual(bytes);
  await expect(s.writeNewBytes('data/files/abc', bytes)).rejects.toBeInstanceOf(FileExistsError);
  await s.writeNew('data/ops/k/1.json', '{"a":"Žluť"}');
  await expect(s.writeNew('data/ops/k/1.json', 'x')).rejects.toBeInstanceOf(FileExistsError);
  expect(await s.read('data/ops/k/1.json')).toBe('{"a":"Žluť"}');
  expect((await s.list('data'))!.map((e) => e.name).sort()).toEqual(['files', 'ops']);
  expect(await s.remove('data/files/abc')).toBe(true);
  expect(await s.readBytes('data/files/abc')).toBeNull();
  expect(await s.remove('data/files/abc')).toBe(false);
  expect(await s.read('missing')).toBeNull();
}

describe('storage adapters', () => {
  it('memory storage fulfils the contract', () => contract(new MemoryStorage()));
  it('Node fs storage fulfils the contract', async () => {
    const dir = await mkdtemp(join(tmpdir(), 'oplog-core-'));
    try {
      await contract(new NodeFsStorage(dir));
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
