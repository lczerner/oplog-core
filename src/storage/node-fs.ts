// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Node fs adapter (tests, simulation, tools). Not part of the browser bundle.
import { mkdir, open, readdir, readFile, unlink } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { checkPath, FileExistsError, type DirEntry, type Storage } from './types';

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

  async read(path: string): Promise<string | null> {
    checkPath(path);
    try {
      return await readFile(join(this.root, path), 'utf8');
    } catch {
      return null;
    }
  }

  async readBytes(path: string): Promise<Uint8Array | null> {
    checkPath(path);
    try {
      return new Uint8Array(await readFile(join(this.root, path)));
    } catch {
      return null;
    }
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

  async writeNewBytes(path: string, data: Uint8Array): Promise<void> {
    checkPath(path);
    const full = join(this.root, path);
    await mkdir(dirname(full), { recursive: true });
    let fh;
    try {
      fh = await open(full, 'wx'); // fails if the file exists
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'EEXIST') throw new FileExistsError(path);
      throw e;
    }
    try {
      await fh.writeFile(data);
    } finally {
      await fh.close();
    }
  }
}
