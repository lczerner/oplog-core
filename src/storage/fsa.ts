// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// File System Access adapter (browser). Works on the locally synced OneDrive folder.
import { checkMaxBytes, checkPath, FileExistsError, FileTooLargeError, type DirEntry, type ReadOptions, type Storage } from './types';

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

  /**
   * Reads the content of a file. A File object is a snapshot: if the file changes after
   * getFile(), arrayBuffer() fails. Thus File.size is the size of the content that the read gives.
   */
  private async readRaw(path: string, opts?: ReadOptions): Promise<Uint8Array | null> {
    checkPath(path);
    checkMaxBytes(opts?.maxBytes);
    const f = await this.file(path);
    if (!f) return null;
    const max = opts?.maxBytes;
    if (max !== undefined && f.size > max) throw new FileTooLargeError(path, max);
    let b: Uint8Array;
    try {
      b = new Uint8Array(await f.arrayBuffer());
    } catch {
      return null;
    }
    if (max !== undefined && b.length > max) throw new FileTooLargeError(path, max);
    return b;
  }

  /** Decodes like File.text(): UTF-8, and the decoder removes a BOM. */
  async read(path: string, opts?: ReadOptions): Promise<string | null> {
    const b = await this.readRaw(path, opts);
    return b && new TextDecoder().decode(b);
  }

  readBytes(path: string, opts?: ReadOptions): Promise<Uint8Array | null> {
    return this.readRaw(path, opts);
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
    // getFileHandle() with `create` makes an empty file at once. If the write fails, the empty
    // file stays. The adapter does not delete it. Between the failure and a delete by path,
    // a different writer can put its op at this path. Examples are OneDrive on a different
    // computer, a second browser profile and a write without the Web Lock. The delete then
    // removes that op. For op and checkpoint files, the engine skips an empty or partial file.
    // For a file at a fixed path, the caller must read the file and check its content.
    const fh = await d.getFileHandle(name, { create: true });
    let w: FileSystemWritableFileStream | undefined;
    try {
      w = await fh.createWritable({ keepExistingData: false });
      await w.write(data.slice().buffer as ArrayBuffer);
      await w.close();
    } catch (e) {
      // abort() discards the data of the writable. Ignore its errors: the original error is more important.
      if (w) await w.abort().catch(() => {});
      throw e;
    }
  }
}
