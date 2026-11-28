// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Node fs adapter (tests, simulation, tools). Not part of the browser bundle.
import { mkdir, open, readdir, unlink, type FileHandle } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { checkMaxBytes, checkPath, FileExistsError, FileTooLargeError, type DirEntry, type ReadOptions, type Storage } from './types';

/**
 * Reads the file to its end. Returns null if the path is not a regular file (for example a folder).
 * Throws FileTooLargeError if the file has more than `max` bytes.
 * The file can grow after the stat, so the loop reads a maximum of `max` + 1 bytes.
 */
async function readMax(fh: FileHandle, path: string, max: number): Promise<Uint8Array | null> {
  const st = await fh.stat();
  if (!st.isFile()) return null;
  const size = st.size;
  if (size > max) throw new FileTooLargeError(path, max);
  let buf = Buffer.alloc(size + 1);
  let n = 0;
  for (;;) {
    if (n === buf.length) {
      if (n > max) throw new FileTooLargeError(path, max);
      const b = Buffer.alloc(Math.min(n * 2, max + 1));
      buf.copy(b, 0, 0, n);
      buf = b;
    }
    const { bytesRead } = await fh.read(buf, n, buf.length - n, n);
    if (bytesRead === 0) break;
    n += bytesRead;
  }
  if (n > max) throw new FileTooLargeError(path, max);
  return new Uint8Array(buf.subarray(0, n));
}

export class NodeFsStorage implements Storage {
  constructor(readonly root: string) {}

  async list(dir: string): Promise<DirEntry[] | null> {
    checkPath(dir);
    try {
      const ents = await readdir(join(this.root, dir), { withFileTypes: true });
      return ents.map((e) => ({ name: e.name, kind: e.isDirectory() ? 'dir' : 'file' }));
    } catch {
      return null;
    }
  }

  /** The stat and the read use the same handle, so a rename between them has no effect. */
  private async readRaw(path: string, opts?: ReadOptions): Promise<Uint8Array | null> {
    checkPath(path);
    checkMaxBytes(opts?.maxBytes);
    let fh: FileHandle;
    try {
      fh = await open(join(this.root, path), 'r');
    } catch {
      return null;
    }
    try {
      return opts?.maxBytes === undefined ? new Uint8Array(await fh.readFile()) : await readMax(fh, path, opts.maxBytes);
    } catch (e) {
      if (e instanceof FileTooLargeError) throw e;
      return null;
    } finally {
      await fh.close().catch(() => {});
    }
  }

  /** Decodes like File.text() in the browser: the decoder removes a UTF-8 BOM. Thus all adapters give the same text. */
  async read(path: string, opts?: ReadOptions): Promise<string | null> {
    const b = await this.readRaw(path, opts);
    return b && new TextDecoder().decode(b);
  }

  readBytes(path: string, opts?: ReadOptions): Promise<Uint8Array | null> {
    return this.readRaw(path, opts);
  }

  async remove(path: string): Promise<boolean> {
    checkPath(path);
    try {
      await unlink(join(this.root, path));
      return true;
    } catch {
      return false;
    }
  }

  writeNew(path: string, data: string): Promise<void> {
    return this.writeNewBytes(path, new TextEncoder().encode(data));
  }

  /**
   * Creates a new file with `wx`. The write is not atomic for a reader: a reader can see
   * a partial file while the write continues. The engine reads a file with a parse error
   * again in a quick scan.
   * If the write fails, an empty or partial file can stay. The adapter does not delete it.
   * Between the failure and a delete by path, a different writer can put its op at this path.
   * The delete then removes that op. For op and checkpoint files, the engine skips such a file.
   * For a file at a fixed path, the caller must read the file and check its content.
   */
  async writeNewBytes(path: string, data: Uint8Array): Promise<void> {
    checkPath(path);
    const full = join(this.root, path);
    await mkdir(dirname(full), { recursive: true });
    let fh: FileHandle;
    try {
      fh = await open(full, 'wx'); // fails if the file exists
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new FileExistsError(path);
      throw e;
    }
    try {
      await fh.writeFile(data);
    } catch (e) {
      await fh.close().catch(() => {});
      throw e;
    }
    await fh.close();
  }
}
