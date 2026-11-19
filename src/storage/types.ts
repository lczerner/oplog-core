// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Storage abstraction. Paths are relative to the shared root and use "/".
// Adapters: File System Access (browser), Node fs and in-memory (tests, simulation).

export interface DirEntry {
  name: string;
  kind: 'file' | 'dir';
}

export class FileExistsError extends Error {
  constructor(path: string) {
    super(`file exists: ${path}`);
  }
}

/**
 * Throws for a path that can leave the shared root: an empty segment, ".", "..",
 * a backslash, a drive letter or a leading "/".
 */
export function checkPath(path: string): void {
  if (path === '') return;
  const parts = path.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..' || p.includes('\\') || p.includes(':'))) throw new Error(`invalid storage path: ${path}`);
}

export interface Storage {
  /** Lists a folder. Returns null if the folder does not exist or is not readable. */
  list(dir: string): Promise<DirEntry[] | null>;
  /** Reads a text file. Returns null if it does not exist or is not readable. */
  read(path: string): Promise<string | null>;
  /**
   * Creates a NEW file with this content, and the parent folders if necessary.
   * Throws FileExistsError if the file exists. Never overwrites.
   */
  writeNew(path: string, data: string): Promise<void>;
  /** Reads a binary file. Returns null if it does not exist or is not readable. */
  readBytes(path: string): Promise<Uint8Array | null>;
  /** Creates a NEW binary file. Throws FileExistsError if the file exists. */
  writeNewBytes(path: string, data: Uint8Array): Promise<void>;
  /**
   * Deletes 1 file. Returns false if it did not exist.
   * Only for content-addressed blobs after an admin purge. Never use it for op,
   * checkpoint or trust-root files: they are immutable.
   */
  remove(path: string): Promise<boolean>;
}
