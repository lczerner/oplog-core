// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { checkPath, FileExistsError, type DirEntry, type Storage } from './types';

/** In-memory storage for tests. */
export class MemoryStorage implements Storage {
  readonly files = new Map<string, string | Uint8Array>();

  async list(dir: string): Promise<DirEntry[] | null> {
    checkPath(dir);
    const prefix = dir === '' ? '' : dir.replace(/\/$/, '') + '/';
    const seen = new Map<string, DirEntry['kind']>();
    for (const p of this.files.keys()) {
      if (!p.startsWith(prefix)) continue;
      const rest = p.slice(prefix.length).split('/');
      seen.set(rest[0], rest.length > 1 ? 'dir' : 'file');
    }
    if (seen.size === 0) return null;
    return [...seen].map(([name, kind]) => ({ name, kind }));
  }

  async read(path: string): Promise<string | null> {
    checkPath(path);
    const v = this.files.get(path);
    if (v === undefined) return null;
    return typeof v === 'string' ? v : new TextDecoder().decode(v);
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    checkPath(path);
    const v = this.files.get(path);
    if (v === undefined) return null;
    return typeof v === 'string' ? new TextEncoder().encode(v) : v.slice();
  }

  async writeNewBytes(path: string, data: Uint8Array): Promise<void> {
    checkPath(path);
    if (this.files.has(path)) throw new FileExistsError(path);
    this.files.set(path, data.slice());
  }

  async remove(path: string): Promise<boolean> {
    checkPath(path);
    return this.files.delete(path);
  }

  async writeNew(path: string, data: string): Promise<void> {
    checkPath(path);
    if (this.files.has(path)) throw new FileExistsError(path);
    this.files.set(path, data);
  }
}
