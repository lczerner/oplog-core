// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
import { checkMaxBytes, checkPath, FileExistsError, FileTooLargeError, type DirEntry, type ReadOptions, type Storage } from './types';

/** The size of a stored value in bytes. A string has the length of its UTF-8 form. */
const byteLength = (v: string | Uint8Array) => (typeof v === 'string' ? new TextEncoder().encode(v).length : v.length);

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

  /** Returns the stored value, or null. Throws FileTooLargeError if the value has more than `maxBytes` bytes. */
  private get(path: string, opts?: ReadOptions): string | Uint8Array | null {
    checkPath(path);
    checkMaxBytes(opts?.maxBytes);
    const v = this.files.get(path);
    if (v === undefined) return null;
    if (opts?.maxBytes !== undefined && byteLength(v) > opts.maxBytes) throw new FileTooLargeError(path, opts.maxBytes);
    return v;
  }

  /** Removes a leading U+FEFF (BOM) like the Node and FSA adapters. */
  async read(path: string, opts?: ReadOptions): Promise<string | null> {
    const v = this.get(path, opts);
    if (v === null) return null;
    if (typeof v !== 'string') return new TextDecoder().decode(v);
    return v.charCodeAt(0) === 0xfeff ? v.slice(1) : v;
  }

  async readBytes(path: string, opts?: ReadOptions): Promise<Uint8Array | null> {
    const v = this.get(path, opts);
    if (v === null) return null;
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
