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

/** The file has more bytes than `ReadOptions.maxBytes`. The adapter did not read its content. */
export class FileTooLargeError extends Error {
  constructor(
    readonly path: string,
    readonly maxBytes: number,
  ) {
    super(`file is larger than ${maxBytes} bytes: ${path}`);
  }
}

export interface ReadOptions {
  /**
   * The maximum size of the file in bytes. If the file is larger, the adapter throws
   * FileTooLargeError and does not read the content into memory.
   */
  maxBytes?: number;
}

/** Throws RangeError if the caller gives `v` and `v` is not a non-negative safe integer (for example NaN, -1 or 1.5). */
export function checkMaxBytes(v: number | undefined): void {
  if (v !== undefined && !(Number.isSafeInteger(v) && v >= 0)) throw new RangeError(`invalid maxBytes: ${v}`);
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
  /** Reads a text file. Returns null if it does not exist or is not readable. See ReadOptions. */
  read(path: string, opts?: ReadOptions): Promise<string | null>;
  /**
   * Creates a NEW file with this content, and the parent folders if necessary.
   * Throws FileExistsError if the file exists. Never overwrites.
   * If the write fails, an empty or partial file can stay. The adapter does not delete it.
   * Thus FileExistsError does not mean that the content is complete. The caller of a fixed
   * path (for example the trust root or a blob) must read the file and check its content.
   */
  writeNew(path: string, data: string): Promise<void>;
  /** Reads a binary file. Returns null if it does not exist or is not readable. See ReadOptions. */
  readBytes(path: string, opts?: ReadOptions): Promise<Uint8Array | null>;
  /** Creates a NEW binary file. Throws FileExistsError if the file exists. The rules of writeNew() about a failed write apply. */
  writeNewBytes(path: string, data: Uint8Array): Promise<void>;
  /**
   * Deletes 1 file. Returns false if it did not exist.
   * Only for content-addressed blobs after an admin purge. Never use it for op,
   * checkpoint or trust-root files: they are immutable.
   */
  remove(path: string): Promise<boolean>;
}
