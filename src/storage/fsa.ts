// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// File System Access adapter (browser). Works on the locally synced OneDrive folder.
import { checkPath, FileExistsError, type DirEntry, type Storage } from './types';

type Dir = FileSystemDirectoryHandle;

export class FsaStorage implements Storage {
  constructor(readonly root: Dir) {}

  private async dir(path: string, create = false): Promise<Dir | null> {
    let d = this.root;
    for (const part of path.split('/').filter(Boolean)) {
      try {
        d = await d.getDirectoryHandle(part, { create });
      } catch {
        return null;
      }
    }
    return d;
  }

  async list(dir: string): Promise<DirEntry[] | null> {
    checkPath(dir);
    const d = await this.dir(dir);
    if (!d) return null;
    const out: DirEntry[] = [];
    try {
      for await (const [name, h] of (d as any).entries() as AsyncIterable<[string, FileSystemHandle]>) out.push({ name, kind: h.kind === 'directory' ? 'dir' : 'file' });
    } catch {
      return null;
    }
    return out;
  }

  private async file(path: string): Promise<File | null> {
    const i = path.lastIndexOf('/');
    const d = await this.dir(path.slice(0, Math.max(i, 0)));
    if (!d) return null;
    try {
      return await (await d.getFileHandle(path.slice(i + 1))).getFile();
    } catch {
      return null;
    }
  }

  async read(path: string): Promise<string | null> {
    checkPath(path);
    const f = await this.file(path);
    return f ? f.text() : null;
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    checkPath(path);
    const f = await this.file(path);
    return f ? new Uint8Array(await f.arrayBuffer()) : null;
  }

  async remove(path: string): Promise<boolean> {
    checkPath(path);
    const i = path.lastIndexOf('/');
    const d = await this.dir(path.slice(0, Math.max(i, 0)));
    if (!d) return false;
    try {
      await d.removeEntry(path.slice(i + 1));
      return true;
    } catch {
      return false;
    }
  }

  writeNew(path: string, data: string): Promise<void> {
    return this.writeNewBytes(path, new TextEncoder().encode(data));
  }

  /**
   * Creates a new file. The check "does not exist" and the creation are not atomic in the
   * File System Access API. A Web Lock (shared by all tabs of the origin) prevents 2 tabs
   * from writing the same file at the same time. Other computers write their own copy,
   * and OneDrive keeps both (conflict copy): the engine reports that as a fork.
   */
  async writeNewBytes(path: string, data: Uint8Array): Promise<void> {
    checkPath(path);
    const locks = (globalThis.navigator as Navigator | undefined)?.locks;
    if (!locks) return this.writeUnlocked(path, data);
    let ran = false;
    try {
      return await locks.request(`oplog-core:${path}`, () => {
        ran = true;
        return this.writeUnlocked(path, data);
      });
    } catch (e) {
      // The lock API itself failed (for example SecurityError on an opaque origin): write without the lock.
      if (ran) throw e;
      return this.writeUnlocked(path, data);
    }
  }

  private async writeUnlocked(path: string, data: Uint8Array): Promise<void> {
    const i = path.lastIndexOf('/');
    const d = await this.dir(path.slice(0, Math.max(i, 0)), true);
    if (!d) throw new Error(`cannot create folder for ${path}`);
    const name = path.slice(i + 1);
    try {
      await d.getFileHandle(name);
      throw new FileExistsError(path);
    } catch (e) {
      if (e instanceof FileExistsError) throw e;
      // NotFoundError: good, the file does not exist.
    }
    const fh = await d.getFileHandle(name, { create: true });
    const w = await fh.createWritable({ keepExistingData: false });
    await w.write(data.slice().buffer as ArrayBuffer);
    await w.close();
  }
}
