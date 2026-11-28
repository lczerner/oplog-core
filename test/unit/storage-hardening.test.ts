// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Storage adapters: the size limit of a read (ReadOptions.maxBytes), the decode of text and a failed write.
import { mkdir, mkdtemp, open, readdir, readFile, rm, type FileHandle } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FsaStorage } from '../../src/storage/fsa';
import { MemoryStorage } from '../../src/storage/memory';
import { NodeFsStorage } from '../../src/storage/node-fs';
import { checkMaxBytes, FileExistsError, FileTooLargeError, type Storage } from '../../src/storage/types';

// A spy on the module function readFile, so that a test can see a full read through it.
vi.mock('node:fs/promises', async (importOriginal) => {
  const m = await importOriginal<typeof import('node:fs/promises')>();
  return { ...m, readFile: vi.fn(m.readFile) };
});

// --- A small fake of the File System Access API: only the methods that FsaStorage uses. ---

type Step = 'createWritable' | 'write' | 'close';

const notFound = () => Object.assign(new Error('not found'), { name: 'NotFoundError' });

class FakeFileHandle {
  readonly kind = 'file';
  data = new Uint8Array();
  /** The number of calls of arrayBuffer() on the File objects of this handle. */
  reads = 0;
  /** If a test sets it, getFile() gives this size and not the real size (a file that changed after the stat). */
  fakeSize?: number;
  constructor(
    readonly dir: FakeDir,
    readonly name: string,
  ) {}

  async getFile() {
    const data = this.data.slice();
    return {
      size: this.fakeSize ?? data.length,
      arrayBuffer: async () => {
        this.reads++;
        if (this.dir.failRead) throw new Error('NotReadableError');
        return data.buffer;
      },
    };
  }

  async createWritable(opts: { keepExistingData: boolean }) {
    expect(opts.keepExistingData).toBe(false);
    this.dir.hook?.('createWritable', this);
    const chunks: Uint8Array[] = [];
    return {
      write: async (b: ArrayBuffer) => {
        this.dir.hook?.('write', this);
        chunks.push(new Uint8Array(b));
      },
      close: async () => {
        this.dir.hook?.('close', this);
        this.data = new Uint8Array(chunks.flatMap((c) => [...c]));
      },
      abort: async () => {
        this.dir.aborts++;
        if (this.dir.failAbort) throw new Error('abort failed');
      },
    };
  }
}

class FakeDir {
  readonly kind = 'directory';
  readonly dirs = new Map<string, FakeDir>();
  readonly files = new Map<string, FakeFileHandle>();
  /** The fake calls it at each step of a write. A test throws in it to make the step fail. */
  hook?: (step: Step, fh: FakeFileHandle) => void;
  failRead = false;
  failAbort = false;
  /** The number of writables that the adapter aborted. */
  aborts = 0;

  /** All folders share the settings of the root, so that a test can set them at 1 place. */
  constructor(readonly root?: FakeDir) {}

  private get cfg(): FakeDir {
    return this.root ?? this;
  }

  async getDirectoryHandle(name: string, opts?: { create?: boolean }) {
    let d = this.dirs.get(name);
    if (!d) {
      if (!opts?.create) throw notFound();
      d = new FakeDir(this.cfg);
      this.dirs.set(name, d);
    }
    return d;
  }

  async getFileHandle(name: string, opts?: { create?: boolean }) {
    let f = this.files.get(name);
    if (!f) {
      if (!opts?.create) throw notFound();
      f = new FakeFileHandle(this.cfg, name);
      this.files.set(name, f);
    }
    return f;
  }

  async removeEntry(name: string) {
    if (!this.files.delete(name) && !this.dirs.delete(name)) throw notFound();
  }

  async *entries(): AsyncIterable<[string, FakeDir | FakeFileHandle]> {
    yield* this.dirs;
    yield* this.files;
  }

  /** The file handle at a path, or undefined. */
  at(path: string): FakeFileHandle | undefined {
    const parts = path.split('/');
    let d: FakeDir | undefined = this;
    for (const p of parts.slice(0, -1)) d = d?.dirs.get(p);
    return d?.files.get(parts[parts.length - 1]);
  }
}

const fsa = () => {
  const root = new FakeDir();
  return { root, s: new FsaStorage(root as unknown as FileSystemDirectoryHandle) };
};

// --- maxBytes: the same rules for all 3 adapters. ---

async function maxBytesContract(s: Storage) {
  await s.writeNew('a/x.json', 'Žluť'); // 6 bytes in UTF-8
  expect(await s.read('a/x.json', { maxBytes: 6 })).toBe('Žluť');
  expect(await s.read('a/x.json')).toBe('Žluť');
  const err = await s.read('a/x.json', { maxBytes: 5 }).catch((e) => e);
  expect(err).toBeInstanceOf(FileTooLargeError);
  expect(err).toMatchObject({ path: 'a/x.json', maxBytes: 5 });
  await expect(s.readBytes('a/x.json', { maxBytes: 5 })).rejects.toBeInstanceOf(FileTooLargeError);
  expect(await s.readBytes('a/x.json', { maxBytes: 6 })).toEqual(new TextEncoder().encode('Žluť'));

  await s.writeNewBytes('a/b.bin', new Uint8Array([1, 2, 3]));
  expect(await s.readBytes('a/b.bin', { maxBytes: 3 })).toEqual(new Uint8Array([1, 2, 3]));
  await expect(s.readBytes('a/b.bin', { maxBytes: 2 })).rejects.toBeInstanceOf(FileTooLargeError);
  await expect(s.read('a/b.bin', { maxBytes: 2 })).rejects.toBeInstanceOf(FileTooLargeError);

  // A folder at the path gives null, also with a small limit.
  expect(await s.read('a', { maxBytes: 1 })).toBeNull();
  expect(await s.readBytes('a', { maxBytes: 1 })).toBeNull();

  // The adapter checks the limit before it looks for the file.
  for (const maxBytes of [-1, 1.5, NaN, Infinity, 2 ** 53]) {
    await expect(s.read('a/x.json', { maxBytes })).rejects.toBeInstanceOf(RangeError);
    await expect(s.readBytes('a/missing', { maxBytes })).rejects.toBeInstanceOf(RangeError);
  }

  await s.writeNew('a/empty', '');
  expect(await s.read('a/empty', { maxBytes: 0 })).toBe('');
  expect(await s.readBytes('a/empty', { maxBytes: 0 })).toEqual(new Uint8Array());

  // A file that does not exist gives null, also with a limit.
  expect(await s.read('a/missing', { maxBytes: 0 })).toBeNull();
  expect(await s.readBytes('a/missing', { maxBytes: 0 })).toBeNull();
  expect(await s.read('nodir/missing', { maxBytes: 10 })).toBeNull();
}

async function withTmp(fn: (dir: string) => Promise<void>) {
  const dir = await mkdtemp(join(tmpdir(), 'oplog-core-hardening-'));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

/** The prototype of the FileHandle class. node:fs/promises does not export the class. */
async function fileHandleProto(dir: string): Promise<FileHandle> {
  const fh = await open(join(dir, '.proto'), 'w');
  await fh.close();
  await rm(join(dir, '.proto'));
  return Object.getPrototypeOf(fh) as FileHandle;
}

/** All 3 adapters decode text like File.text() in the browser: the decoder removes a UTF-8 BOM. */
async function bomContract(s: Storage) {
  await s.writeNewBytes('bom1.json', new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
  expect(await s.read('bom1.json')).toBe('{}');
  expect(await s.read('bom1.json', { maxBytes: 5 })).toBe('{}');
  await s.writeNew('bom2.json', '\uFEFF{}');
  expect(await s.read('bom2.json')).toBe('{}');
  // The BOM counts for the limit: it has 3 bytes in UTF-8.
  await expect(s.read('bom2.json', { maxBytes: 4 })).rejects.toBeInstanceOf(FileTooLargeError);
  // readBytes() gives the bytes without a change.
  expect(await s.readBytes('bom2.json')).toEqual(new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]));
}

afterEach(() => vi.restoreAllMocks());

describe('checkMaxBytes', () => {
  it('accepts undefined and non-negative safe integers', () => {
    for (const v of [undefined, 0, 1, 32 * 2 ** 20, Number.MAX_SAFE_INTEGER]) expect(() => checkMaxBytes(v)).not.toThrow();
  });
  it('throws RangeError for other numbers', () => {
    for (const v of [-1, -0.5, 1.5, NaN, Infinity, -Infinity, 2 ** 53]) expect(() => checkMaxBytes(v)).toThrow(RangeError);
  });
});

describe('UTF-8 BOM', () => {
  it('memory storage', () => bomContract(new MemoryStorage()));
  it('Node fs storage', () => withTmp((dir) => bomContract(new NodeFsStorage(dir))));
  it('FSA storage', () => bomContract(fsa().s));
});

describe('ReadOptions.maxBytes', () => {
  it('memory storage', () => maxBytesContract(new MemoryStorage()));
  it('memory storage counts the UTF-8 bytes of a stored string', async () => {
    const s = new MemoryStorage();
    await s.writeNew('x', '€'); // 3 bytes in UTF-8, 1 UTF-16 unit
    await expect(s.read('x', { maxBytes: 2 })).rejects.toBeInstanceOf(FileTooLargeError);
    expect(await s.read('x', { maxBytes: 3 })).toBe('€');
  });

  it('Node fs storage', () => withTmp((dir) => maxBytesContract(new NodeFsStorage(dir))));

  it('Node fs storage does not read the content of a file that is too large', () =>
    withTmp(async (dir) => {
      const s = new NodeFsStorage(dir);
      await s.writeNewBytes('big', new Uint8Array(1000));
      const proto = await fileHandleProto(dir);
      const read = vi.spyOn(proto, 'read');
      const fhReadFile = vi.spyOn(proto, 'readFile');
      vi.mocked(readFile).mockClear();
      const sizes: number[] = [];
      for (const f of ['alloc', 'allocUnsafe', 'allocUnsafeSlow'] as const) {
        const orig = Buffer[f] as (n: number, ...rest: unknown[]) => Buffer;
        vi.spyOn(Buffer, f).mockImplementation(((n: number, ...rest: unknown[]) => {
          sizes.push(n);
          return orig.call(Buffer, n, ...rest);
        }) as never);
      }
      await expect(s.readBytes('big', { maxBytes: 999 })).rejects.toBeInstanceOf(FileTooLargeError);
      await expect(s.read('big', { maxBytes: 999 })).rejects.toBeInstanceOf(FileTooLargeError);
      expect(read).not.toHaveBeenCalled();
      expect(fhReadFile).not.toHaveBeenCalled();
      expect(readFile).not.toHaveBeenCalled();
      // No buffer for the content: all buffers are smaller than the file.
      expect(sizes.filter((n) => n >= 1000)).toEqual([]);
    }));

  it('Node fs storage checks the length of the content after the stat (the file can grow)', () =>
    withTmp(async (dir) => {
      const s = new NodeFsStorage(dir);
      const data = new Uint8Array(5000).map((_, i) => i & 0xff);
      await s.writeNewBytes('grows', data);
      const proto = await fileHandleProto(dir);
      const stat = proto.stat;
      // The stat gives the size before the file grew to 5000 bytes.
      vi.spyOn(proto, 'stat').mockImplementation(async function (this: FileHandle) {
        const st = await stat.call(this);
        st.size = 10;
        return st;
      });
      await expect(s.readBytes('grows', { maxBytes: 4999 })).rejects.toBeInstanceOf(FileTooLargeError);
      // In the limit: the adapter reads all of the content, also after the stat.
      expect(await s.readBytes('grows', { maxBytes: 5000 })).toEqual(data);
      expect(await s.readBytes('grows', { maxBytes: 1 << 20 })).toEqual(data);
    }));

  it('Node fs storage gives null for a folder, also if the folder is larger than the limit', () =>
    withTmp(async (dir) => {
      const s = new NodeFsStorage(dir);
      for (let i = 0; i < 50; i++) await mkdir(join(dir, 'd', `sub-folder-with-a-long-name-${i}`), { recursive: true });
      expect(await s.read('d', { maxBytes: 1 })).toBeNull();
      expect(await s.readBytes('d', { maxBytes: 0 })).toBeNull();
      expect(await s.read('d')).toBeNull();
    }));

  it('FSA storage', () => maxBytesContract(fsa().s));

  it('FSA storage uses File.size and does not read the content of a file that is too large', async () => {
    const { root, s } = fsa();
    await s.writeNewBytes('d/big', new Uint8Array(100));
    const fh = root.at('d/big')!;
    await expect(s.readBytes('d/big', { maxBytes: 99 })).rejects.toBeInstanceOf(FileTooLargeError);
    await expect(s.read('d/big', { maxBytes: 99 })).rejects.toBeInstanceOf(FileTooLargeError);
    expect(fh.reads).toBe(0);
    expect(await s.readBytes('d/big', { maxBytes: 100 })).toHaveLength(100);
    expect(fh.reads).toBe(1);
  });

  it('FSA storage checks the length of the content after File.size', async () => {
    const { root, s } = fsa();
    await s.writeNewBytes('d/f', new Uint8Array(100));
    root.at('d/f')!.fakeSize = 10;
    await expect(s.readBytes('d/f', { maxBytes: 50 })).rejects.toBeInstanceOf(FileTooLargeError);
  });

  it('FSA storage gives null if the content is not readable', async () => {
    const { root, s } = fsa();
    await s.writeNew('d/f', 'x');
    root.failRead = true;
    expect(await s.read('d/f')).toBeNull();
    expect(await s.readBytes('d/f', { maxBytes: 10 })).toBeNull();
  });
});

describe('FSA storage: a failed write', () => {
  it('still throws FileExistsError and does not change the existing file', async () => {
    const { root, s } = fsa();
    await s.writeNew('ops/k/1.json', '{"a":1}');
    await expect(s.writeNew('ops/k/1.json', 'x')).rejects.toBeInstanceOf(FileExistsError);
    await expect(s.writeNewBytes('ops/k/1.json', new Uint8Array([1]))).rejects.toBeInstanceOf(FileExistsError);
    expect(await s.read('ops/k/1.json')).toBe('{"a":1}');
    expect((await s.list('ops/k'))!.map((e) => e.name)).toEqual(['1.json']);
    expect(root.aborts).toBe(0);
  });

  for (const step of ['createWritable', 'write', 'close'] as const) {
    it(`keeps the empty file, aborts and throws the original error if ${step} fails`, async () => {
      const { root, s } = fsa();
      const remove = vi.spyOn(FakeDir.prototype, 'removeEntry');
      const boom = new Error(`${step} failed`);
      root.hook = (st) => {
        if (st === step) throw boom;
      };
      await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBe(boom);
      // The adapter does not delete by path: the empty file stays.
      expect(remove).not.toHaveBeenCalled();
      expect(root.at('ops/k/1.json')!.data).toHaveLength(0);
      expect(await s.read('ops/k/1.json')).toBe('');
      // The adapter aborts the writable if it has one.
      expect(root.aborts).toBe(step === 'createWritable' ? 0 : 1);
      // The path is not free: a new write gives FileExistsError.
      root.hook = undefined;
      await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBeInstanceOf(FileExistsError);
    });
  }

  it('throws the original error if the abort fails', async () => {
    const { root, s } = fsa();
    const boom = new Error('write failed');
    root.hook = (st) => {
      if (st === 'write') throw boom;
    };
    root.failAbort = true;
    await expect(s.writeNew('ops/k/1.json', 'x')).rejects.toBe(boom);
    expect(root.aborts).toBe(1);
    expect(root.at('ops/k/1.json')!.data).toHaveLength(0);
  });

  it('does not delete the op of a different writer at the same path', async () => {
    const { root, s } = fsa();
    const boom = new Error('close failed');
    const other = new TextEncoder().encode('{"other":1}');
    root.hook = (st, fh) => {
      if (st === 'close') {
        fh.data = other;
        throw boom;
      }
    };
    await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBe(boom);
    expect(await s.read('ops/k/1.json')).toBe('{"other":1}');
  });
});

describe('Node fs storage: a failed write', () => {
  it('keeps the partial file and throws the original error', () =>
    withTmp(async (dir) => {
      const s = new NodeFsStorage(dir);
      const proto = await fileHandleProto(dir);
      const boom = new Error('disk full');
      vi.spyOn(proto, 'writeFile').mockImplementationOnce(async function (this: FileHandle) {
        await this.write(Buffer.from('{"a"')); // a partial file
        throw boom;
      });
      await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBe(boom);
      // The adapter does not delete by path: the partial file stays.
      expect(await readdir(join(dir, 'ops/k'))).toEqual(['1.json']);
      expect(await s.read('ops/k/1.json')).toBe('{"a"');
      // The path is not free: a new write gives FileExistsError.
      await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBeInstanceOf(FileExistsError);
    }));

  it('keeps the file if only the close fails (the content can be complete)', () =>
    withTmp(async (dir) => {
      const s = new NodeFsStorage(dir);
      const proto = await fileHandleProto(dir);
      const writeFile = proto.writeFile;
      const boom = new Error('close failed');
      // close() is a property of each handle, not of the prototype: replace it after the write.
      vi.spyOn(proto, 'writeFile').mockImplementationOnce(async function (this: FileHandle, ...args: Parameters<FileHandle['writeFile']>) {
        await writeFile.apply(this, args);
        const close = this.close.bind(this);
        this.close = async () => {
          await close();
          throw boom;
        };
      });
      await expect(s.writeNew('ops/k/1.json', '{"a":1}')).rejects.toBe(boom);
      expect(await s.read('ops/k/1.json')).toBe('{"a":1}');
      await expect(s.writeNew('ops/k/1.json', 'x')).rejects.toBeInstanceOf(FileExistsError);
    }));
});
