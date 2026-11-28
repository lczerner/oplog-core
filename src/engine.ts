// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Engine: scans a Storage, verifies op files, replays, and writes new ops.
// UI-free. The browser app, the tests and the simulation use the same class.

import { canonicalize } from './canonical';
import { fingerprint, hashCanonical } from './crypto';
import type { Domain } from './domain';
import { utf8 } from './encoding';
import { compareHlc, HlcClock, type Hlc } from './hlc';
import { uuidv7 } from './ids';
import { filePath, KEY_ID_RE, OP_FILE_RE, parsePath, TRUST_ROOT_PATH } from './paths';
import { FUTURE_CLOCK_MS, hasRevocation, orderKey, replayFull, sortOps, type KeyBindings, type Replayer, type ReplayResult } from './replay';
import { FileExistsError, FileTooLargeError, type Storage } from './storage/types';
import type { AuditEntry, Envelope, Issue, TrustRoot, UnsignedEnvelope } from './types';
import { checkChains, checkEnvelope, KeyMap, parseOpFile, signEnvelope, verifySignature, type ChainInput, type ChainResult, type SigStatus } from './verify';
import { isId, isIso, isPlainObject } from './validate';

/** The maximum sizes of the files that the engine reads. The engine does not read a larger file: it is an issue. */
export const MAX_OP_FILE_BYTES = 32 * 1024 * 1024;
export const MAX_CHECKPOINT_BYTES = 256 * 1024 * 1024;
export const MAX_TRUST_ROOT_BYTES = 1024 * 1024;

/**
 * The opId of the probe op of check(). It is not a valid ID (verify.ts rejects it). No op file can
 * have it. Thus also a file of the same key (another tab or PC) cannot make the probe a duplicate.
 */
export const PROBE_OP_ID = '#probe';

/**
 * Returns null if `x` is a valid trust root. Else returns the reason. The engine uses the same rule
 * for the trust root file and for the trust root of a cache. A valid trust root can be canonicalized
 * (JCS refuses for example 1e400 in an extra field).
 */
export function trustRootError(x: unknown): string | null {
  if (!isPlainObject(x) || x.v !== 1 || !Array.isArray(x.roots)) return 'bad format (v 1 and a list of roots expected)';
  const keyIds = new Set<string>();
  for (let i = 0; i < x.roots.length; i++) {
    const r: unknown = x.roots[i];
    const at = `roots[${i}]`;
    if (!isPlainObject(r)) return `${at}: object expected`;
    if (!isId(r.userId)) return `${at}.userId: id expected`;
    if (typeof r.keyId !== 'string' || !KEY_ID_RE.test(r.keyId)) return `${at}.keyId: key ID expected`;
    if (r.alg !== 'Ed25519') return `${at}.alg: Ed25519 expected`;
    if (typeof r.publicKey !== 'string') return `${at}.publicKey: string expected`;
    if (typeof r.displayName !== 'string') return `${at}.displayName: string expected`;
    const c = r.cutoffs;
    if (c !== null && !(isPlainObject(c) && Object.entries(c).every(([k, v]) => isId(k) && Number.isSafeInteger(v) && (v as number) >= 0)))
      return `${at}.cutoffs: null or an object of scope → non-negative integer expected`;
    // 1 key has 1 root entry. Else a later entry can change the user or the cutoff of the key. A user can have 2 keys.
    if (keyIds.has(r.keyId)) return `${at}.keyId: the key is in the trust root 2 times`;
    keyIds.add(r.keyId);
  }
  try {
    canonicalize(x);
  } catch {
    return 'not canonicalizable';
  }
  return null;
}

/** A deep copy that nobody can change (for a value that the engine gives to the app). */
function frozenCopy<T>(v: T): T {
  const freeze = (x: unknown): void => {
    if (typeof x !== 'object' || x === null) return;
    for (const k of Object.keys(x)) freeze((x as Record<string, unknown>)[k]);
    Object.freeze(x);
  };
  const c = JSON.parse(canonicalize(v)) as T;
  freeze(c);
  return c;
}

const TOO_LARGE = Symbol('too large');
const tooLarge = (maxBytes: number) => `file is larger than ${maxBytes} bytes`;

/**
 * Reads a text file with a size limit. Returns the text, null (no file or not readable) or TOO_LARGE
 * (the file is larger than `maxBytes`). Other errors of the storage go to the caller.
 */
async function readLimited(storage: Storage, path: string, maxBytes: number): Promise<string | null | typeof TOO_LARGE> {
  try {
    return await storage.read(path, { maxBytes });
  } catch (e) {
    if (e instanceof FileTooLargeError) return TOO_LARGE;
    throw e;
  }
}

export interface Signer {
  keyId: string;
  sign(data: Uint8Array): Promise<string>;
}

export interface EngineOptions {
  now?: () => number;
}

interface KnownOp {
  env: Envelope;
  hash: string;
  source: 'file' | 'checkpoint' | 'local';
}

export interface Checkpoint {
  v: 1;
  scope: string;
  authorKeyId: string;
  seq: number;
  hlc: Hlc;
  wallTime: string;
  frontier: Record<string, { seq: number; hash: string }>;
  ops: Envelope[];
  sig: string;
}

/** Op files of 1 scope and how many of them are in a valid checkpoint. */
export interface ScopeFileStats {
  scope: string;
  /** Op files that this client knows (each op is 1 file in the shared folder). */
  opFiles: number;
  /** Op files that are in no valid checkpoint. A new client reads each of them as a separate file. */
  notInCheckpoint: number;
  /** Op files outside checkpoints that a new checkpoint can pack (only ops of valid chains). */
  packable: number;
  /** Valid checkpoint files of the scope. */
  checkpoints: number;
  /** wallTime of the newest valid checkpoint, or null. */
  lastCheckpoint: string | null;
}

/** The cache contains verified ops only, never the state. The state is always replayed. */
export interface EngineCache {
  v: 3;
  /** `source` = checkpoint: the op came from a trusted pack and is checked again like a pack op. */
  ops: { path: string; env: Envelope; hash: string; source?: 'file' | 'checkpoint' }[];
  sigOk: string[];
  /**
   * The known trust root: the trust root that the app acknowledged (or the first one that the engine
   * read). importCache() uses it as the last good copy. Thus the engine finds a change of the trust
   * root file also when the app was closed.
   */
  trustRoot: TrustRoot | null;
}

/** 1 op file that a scan read and parsed, before the engine applies it. */
interface ReadResult {
  path: string;
  parsed: Awaited<ReturnType<typeof parseOpFile>>;
}

/** Numbers that a quick scan tries after a missing number. Also: the maximum re-reads of parse errors for each author in 1 quick scan. */
const QUICK_LOOKAHEAD = 16;
/**
 * The issue detail of verify.ts for an op file that is not valid JSON. A partial read of a file
 * that another client still writes gives this detail. A quick scan reads only such files again.
 */
const NOT_JSON = 'not valid JSON';
/**
 * Read budget of 1 file that is not valid JSON (an op file or a checkpoint). The engine reads such
 * a file again at most MAX_NOT_JSON_READS times with the same content. Then it keeps the issue and
 * reads the file again only after a wait: NOT_JSON_WAIT_MS × 2^n after the last read (n = the
 * reads after the budget), at most NOT_JSON_MAX_WAIT_MS. A changed content (a file that another
 * client still writes) does not use the budget: it starts the count again. Thus static garbage
 * files cannot make each scan read them again, and a file that syncs slowly is not hidden.
 * reverifyAll() resets the budget of all files.
 */
const MAX_NOT_JSON_READS = 3;
const NOT_JSON_WAIT_MS = 5_000;
const NOT_JSON_MAX_WAIT_MS = 600_000;
/**
 * The maximum wait before the engine reads again a checkpoint whose author key is not known: 6 hours.
 * It is larger than NOT_JSON_MAX_WAIT_MS, because the engine reads such a pack at once when its key
 * becomes known. The wait is NOT_JSON_WAIT_MS × 2^n after the last read (n = the reads after the first one).
 */
export const UNKNOWN_KEY_PACK_MAX_WAIT_MS = 6 * 3600_000;

/** A short identity of a text: the text itself if it is short, else the length and a 32-bit FNV-1a hash. */
function contentSig(text: string): string {
  if (text.length <= 64) return `=${text}`;
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) h = Math.imul(h ^ text.charCodeAt(i), 0x01000193);
  return `${text.length}:${(h >>> 0).toString(16)}`;
}
/** The highest number of an op or checkpoint file name (10 digits). */
const MAX_SEQ = 9_999_999_999;
/**
 * Files that a scan reads and verifies at the same time. The storage reads and the WebCrypto
 * checks are async: if the scan reads 1 file at a time, it mostly waits for them.
 */
const READ_CONCURRENCY = 32;

/**
 * Runs `f(item, index)` for each item, with at most `n` calls at the same time.
 * At the first error, no new call starts, and pool() rejects only after all running calls
 * have ended. Thus no call runs after the caller (a serial engine task) has ended.
 */
export async function pool<T>(items: readonly T[], n: number, f: (x: T, i: number) => Promise<unknown>): Promise<void> {
  let next = 0;
  let failed = false;
  let error: unknown;
  const worker = async () => {
    while (!failed && next < items.length) {
      const i = next++;
      try {
        await f(items[i], i);
      } catch (e) {
        if (!failed) (failed = true), (error = e);
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  if (failed) throw error;
}

/** File names that the scan may read. The storage adapters refuse "\\" and ":". */
const SAFE_NAME_RE = /^[^\\:/]+$/;

/** The op is not permitted (rejected by validation or authorize). */
export class AuthError extends Error {}
/** The op is permitted, but it would have no effect now (superseded). */
export class SupersededError extends Error {
  /** The code of the Superseded result of the domain (AuditEntry.code), if it gave one. */
  declare readonly code?: string;

  constructor(message?: string, code?: string) {
    super(message);
    if (code !== undefined) (this as { code?: string }).code = code;
  }
}

export class Engine {
  readonly clock: HlcClock;
  trustRoot: TrustRoot | null = null;
  private ops = new Map<string, KnownOp>(); // path → op
  private heads_ = new Map<string, { scope: string; keyId: string; seq: number; hash: string }>(); // scope|keyId → highest known op
  /** scope|keyId → the validly signed op with the highest seq (for the writer). */
  private lastSigned = new Map<string, KnownOp>();
  /** scope|keyId → the last op of the valid chain. */
  private chainHeads = new Map<string, { seq: number; hash: string }>();
  /** The chain check of each (scope|author), with the exact input it was computed from. */
  private chainCache = new Map<string, { input: string; res: ChainResult }>();
  private forkCandidates = new Map<string, KnownOp>(); // conflict-copy path → op with a seq that has a main file
  private fileIssues = new Map<string, Issue>(); // path → issue (unknown / unparsable files)
  private sigStatus = new Map<string, SigStatus>(); // op hash → ok | bad
  private keys = new KeyMap();
  private checkpointsSeen = new Set<string>();
  /** Op paths that a trusted checkpoint contains. A scan does not read these files. */
  private packedPaths = new Set<string>();
  /** Checkpoint path → result of the pack signature check. */
  private cpSigOk = new Map<string, boolean>();
  /** Checkpoint paths whose ops the engine used (trusted when read). Only these count in checkpointStats. */
  private usedPacks = new Set<string>();
  /** Op path → issue: a trusted pack had a bad version of this op. */
  private packIssues = new Map<string, Issue>();
  /** Used checkpoint path → its scope, time and the op paths in it (for the statistics only). */
  private checkpointInfo = new Map<string, { scope: string; wallTime: string; paths: string[] }>();
  /**
   * The checkpoints whose author key was known at the read: recompute() reports a bad signature or an
   * author that is not an admin. The signature result is in cpSigOk. The engine keeps nothing else of the pack.
   */
  private pendingCheckpoints: { path: string; authorKeyId: string }[] = [];
  /**
   * Checkpoint path → a pack that the engine read while the key of its author was not known: the
   * author key, the reads after the first one (n), and the time of the last read. The engine keeps
   * nothing else of such a pack. A later full scan reads it again: at once if the key is known then,
   * else after NOT_JSON_WAIT_MS × 2^n (at most UNKNOWN_KEY_PACK_MAX_WAIT_MS). reverifyAll() clears it.
   */
  private packWaits = new Map<string, { authorKeyId: string; n: number; at: number }>();
  result: ReplayResult;
  private replayer: Replayer;
  private appliedHashes = new Set<string>();
  private trustRootSig = 'null';
  /** The known trust root: the trust root that the app acknowledged, or the first one that the engine read. */
  private knownTr: TrustRoot | null = null;
  /** True if the trust root changed after the app acknowledged the known trust root. Only acknowledgeTrustRoot() clears it. */
  private trChanged = false;
  /** See the getter trustRootHash. */
  private trHash: string | null = null;
  /** True if the trust root file was missing (or not readable) in the last read. */
  private trustRootMissing = false;
  /** True if a scan changed an issue of a file (also only the detail). Then the scan runs recompute. */
  private issuesDirty = false;
  /**
   * Path → the content of the last read that gave "not valid JSON", the number of reads in a row
   * with this content, and the time of the last read (see MAX_NOT_JSON_READS). reverifyAll() clears it.
   */
  private notJsonReads = new Map<string, { sig: string; same: number; at: number }>();
  /** Conflict copies that are not an op (too large, or a parse issue that is not "not valid JSON"). reverifyAll() clears it. */
  private badCopies = new Set<string>();
  private keysScanned = new Set<string>();
  /** Counters for tests and the performance report. `takenBack`: rejected ops that an incremental apply took back and applied again. */
  stats = { fullReplays: 0, incrementalOps: 0, takenBack: 0 };
  issues: Issue[] = [];
  /** Folders that were missing or not readable in the last full scan. */
  missing: string[] = [];
  /** Scopes found in the last full scan. */
  scopes: string[] = [];
  private now: () => number;
  /** MAX_OP_FILE_BYTES. An instance field only so that a test can lower it. Apps must not change it: all clients must use the same limit. */
  private maxOpFileBytes = MAX_OP_FILE_BYTES;

  constructor(
    readonly storage: Storage,
    readonly domain: Domain,
    opts: EngineOptions = {},
  ) {
    this.now = opts.now ?? (() => Date.now());
    this.clock = new HlcClock(this.now);
    this.replayer = replayFull([], this.replayOpts());
    this.result = this.replayer.result();
  }

  /**
   * Runs scans, writes, checkpoints and cache imports 1 at a time. 2 writes at the same time
   * would both link to the same own last op: a fork that stops the own chain. Thus 1 engine
   * never writes 2 ops of 1 author at the same time.
   */
  private queue: Promise<unknown> = Promise.resolve();
  private serial<T>(f: () => Promise<T>): Promise<T> {
    const run = this.queue.then(f, f);
    this.queue = run.catch(() => undefined);
    return run;
  }

  get state() {
    return this.result.state;
  }
  get audit() {
    return this.result.audit;
  }
  get validKeyBindings(): KeyBindings {
    return this.keys;
  }

  private replayOpts() {
    return { domain: this.domain, trustRoot: this.trustRoot, validKeyBindings: this.keys };
  }

  private path(scope: string, kind: 'ops' | 'checkpoints', keyId: string, seq: number): string {
    const dir = this.domain.scopeDir(scope);
    if (dir === null) throw new Error(`invalid scope ${scope}`);
    return filePath(dir, kind, keyId, seq);
  }

  private setOp(path: string, op: KnownOp): void {
    this.ops.set(path, op);
    const k = `${op.env.scope}|${op.env.authorKeyId}`;
    const cur = this.heads_.get(k);
    if (!cur || op.env.seq > cur.seq) this.heads_.set(k, { scope: op.env.scope, keyId: op.env.authorKeyId, seq: op.env.seq, hash: op.hash });
  }

  // ---- Scan --------------------------------------------------------------------------------

  /**
   * Reads the trust root again. `this.trustRoot` is always the last good copy: it is null only if
   * the engine has no valid trust root yet.
   * - If the file is missing, not readable, too large or not valid, the engine keeps the last good
   *   copy and adds a 'trust-root' issue. Thus a file that OneDrive still downloads does not remove
   *   all users for 1 scan.
   * - With no last good copy: an invalid file is an issue. A missing file is an issue only if op
   *   files exist (see trustRootIssues).
   * - A valid file that differs from the last good copy replaces it (an admin can change it on
   *   purpose). If it differs from the known trust root, a 'trust-root' issue stays until the app
   *   calls acknowledgeTrustRoot(), also if the file changes back.
   * - The first valid trust root of an engine without a known trust root becomes the known one.
   */
  loadTrustRoot(): Promise<void> {
    return this.serial(() => this.loadTrustRootInner());
  }

  /**
   * The hash of the trust root that the engine uses (the last good copy): "sha256:" and 64
   * lowercase hex characters, the SHA-256 of the JCS (RFC 8785) of the trust root object, as
   * `hashCanonical` gives it. null if the engine has no trust root. The engine computes it when
   * it loads the trust root. Give it to acknowledgeTrustRoot().
   */
  get trustRootHash(): string | null {
    return this.trHash;
  }

  /**
   * The known trust root: the trust root that the app acknowledged, or the first one that the engine
   * read. A deep copy that nobody can change. For the UI that shows the change (old and new root admins).
   */
  get knownTrustRoot(): TrustRoot | null {
    return this.knownTr;
  }

  /** True while the issue "trust root changed" is open: the trust root differs (or differed) from the known trust root. */
  get trustRootChanged(): boolean {
    return this.trChanged;
  }

  /**
   * Accepts the trust root in use (the last good copy) as the known trust root, and removes the
   * issue that the trust root changed. Call it after an admin compared the fingerprints of the
   * root admins out of band. `expectedHash` is the trustRootHash of the trust root that the admin
   * compared. If the trust root changed again after that (another hash), this method throws and
   * changes nothing: show the new fingerprints again. exportCache() then contains this trust root.
   */
  acknowledgeTrustRoot(expectedHash: string): Promise<void> {
    return this.serial(async () => {
      if (expectedHash !== this.trHash) throw new Error('the trust root changed after the check (another hash): compare the fingerprints of the root admins again');
      this.knownTr = this.trustRoot && frozenCopy(this.trustRoot);
      this.trChanged = false;
      await this.recomputeInner();
    });
  }

  /** Sets the trust root in use and its hash. */
  private async useTrustRoot(tr: TrustRoot): Promise<void> {
    // The hash first: then the app never sees the new trust root with the old hash.
    const hash = await hashCanonical(tr);
    this.trustRoot = tr;
    this.trHash = hash;
  }

  private async loadTrustRootInner(): Promise<void> {
    const t = await readLimited(this.storage, TRUST_ROOT_PATH, MAX_TRUST_ROOT_BYTES);
    const before = this.trustRootIssuesSig();
    this.fileIssues.delete(TRUST_ROOT_PATH);
    this.trustRootMissing = t === null;
    let tr: unknown = null;
    let sig = '';
    let error: string | null = null;
    if (t === TOO_LARGE) error = tooLarge(MAX_TRUST_ROOT_BYTES);
    else if (t === null) error = this.trustRoot ? 'the file is missing or not readable' : null;
    else {
      try {
        tr = JSON.parse(t);
      } catch {
        error = 'not valid JSON';
      }
      // trustRootError() also refuses a trust root that JCS refuses: recompute() canonicalizes it.
      error ??= trustRootError(tr);
      if (error === null) sig = canonicalize(tr);
    }
    if (error !== null)
      this.fileIssues.set(TRUST_ROOT_PATH, { kind: 'trust-root', path: TRUST_ROOT_PATH, detail: this.trustRoot ? `trust root: ${error}. The engine uses the last good copy.` : `trust root: ${error}` });
    else if (t !== null && !(this.trustRoot && canonicalize(this.trustRoot) === sig)) {
      // A new valid trust root. With no change, the engine keeps the same object.
      await this.useTrustRoot(tr as TrustRoot);
      this.knownTr ??= frozenCopy(tr as TrustRoot);
    }
    if (this.trustRoot && this.knownTr && canonicalize(this.trustRoot) !== canonicalize(this.knownTr)) this.trChanged = true;
    if (this.trustRootIssuesSig() !== before) this.issuesDirty = true;
  }

  private trustRootIssuesSig(): string {
    return JSON.stringify([this.fileIssues.get(TRUST_ROOT_PATH) ?? null, this.trChanged, this.trustRootMissing, canonicalize(this.trustRoot)]);
  }

  /** The 'trust-root' issues that do not come from the read of the file (see loadTrustRoot). */
  private trustRootIssues(): Issue[] {
    const out: Issue[] = [];
    const admins = (tr: TrustRoot | null) => tr?.roots.map((r) => `${r.userId} ${fingerprint(r.keyId)}`).join(', ') || 'none';
    if (this.trChanged && this.trustRoot) {
      const back = !!this.knownTr && canonicalize(this.trustRoot) === canonicalize(this.knownTr);
      out.push({
        kind: 'trust-root',
        path: TRUST_ROOT_PATH,
        detail: back
          ? 'the trust root changed and then changed back to the known trust root. Acknowledge it after a check.'
          : `trust root changed: compare the fingerprints of the root admins out of band, then acknowledge the trust root. Known root admins: ${admins(this.knownTr)}. Root admins now: ${admins(this.trustRoot)}`,
      });
    }
    if (!this.trustRoot && this.trustRootMissing && this.ops.size > 0)
      out.push({ kind: 'trust-root', path: TRUST_ROOT_PATH, detail: 'trust root: the file is missing, but op files exist. The engine knows no root admin.' });
    return out;
  }

  /**
   * full = list all folders (finds new authors and unknown files).
   * quick = read forward from the valid head of each known author, with a look-ahead after a gap
   * (cheap, for polling). New authors and large gaps need a full scan.
   * Returns true if the known ops, the trust root or the issue list changed: then the app must
   * show the state and the issues again.
   */
  scan(mode: 'full' | 'quick' = 'full'): Promise<boolean> {
    return this.serial(() => this.scanInner(mode));
  }

  private async scanInner(mode: 'full' | 'quick'): Promise<boolean> {
    const before = this.ops.size;
    const issuesBefore = this.fileIssues.size;
    const issueList = JSON.stringify(this.issues);
    const trBefore = this.trustRoot;
    this.issuesDirty = false;
    if (mode === 'full' || !this.trustRoot) await this.loadTrustRootInner();
    if (mode === 'quick') {
      // Read forward from the head of each valid chain. Numbers that this client knows (also files
      // with an issue, but not a parse error) are skipped, so a known gap does not stop the scan.
      // A full scan lists the folders.
      // The heads are read in parallel. The workers change no engine state (as in scanKind): each
      // worker collects its results in read order. Then the results are applied 1 at a time, in the
      // order of the heads and then of the reads: the same order as a sequential scan. Each head has
      // its own paths, so the results of 1 head cannot change the look-ahead of another head.
      // If 1 read fails, pool() rejects after all workers have ended, and nothing is applied.
      const starts = new Map(this.validHeads().map((h) => [`${h.scope}|${h.keyId}`, h.seq]));
      const heads = this.heads();
      const found: ReadResult[][] = heads.map(() => []);
      await pool(heads, READ_CONCURRENCY, async ({ scope, keyId }, i) => {
        found[i] = await this.readForward(scope, keyId, (starts.get(`${scope}|${keyId}`) ?? 0) + 1);
      });
      for (const list of found) for (const r of list) this.applyRead(r.path, r.parsed);
    } else {
      const found = await this.domain.discoverScopes(this.storage);
      // Copies: scanScope adds to `missing`, and the arrays belong to the domain.
      this.missing = [...found.missing];
      this.scopes = [...found.scopes];
      for (const u of found.unknown) this.unknown(u.path, u.detail);
      for (let i = 0; i < found.scopes.length; i++) {
        const n = this.ops.size;
        await this.scanScope(found.scopes[i]);
        // Replay after the FIRST scope only (the users and admins): then the packs of the later
        // scopes are checked against all admins. The trust decision needs no other scope, and a
        // replay after each scope would cost O(scopes × ops).
        if (i === 0 && found.scopes.length > 1 && this.ops.size !== n) await this.recomputeInner();
      }
    }
    // A quick scan at the first start can find the first trust root: then replay with it.
    if (this.ops.size !== before || this.fileIssues.size !== issuesBefore || this.issuesDirty || this.trustRoot !== trBefore || mode === 'full') await this.recomputeInner();
    return this.ops.size !== before || this.trustRoot !== trBefore || JSON.stringify(this.issues) !== issueList;
  }

  private unknown(path: string, detail: string) {
    this.fileIssues.set(path, { kind: 'unknown-file', path, detail });
  }

  private async scanScope(scope: string): Promise<void> {
    const dir = this.domain.scopeDir(scope)!;
    const top = await this.storage.list(dir);
    if (top === null) {
      this.missing.push(dir);
      return;
    }
    for (const e of top) if (e.kind !== 'dir') this.unknown(`${dir}/${e.name}`, 'unexpected file in a scope folder');
    // Checkpoints first: they can replace many small file reads.
    await this.scanKind(scope, 'checkpoints');
    await this.scanKind(scope, 'ops');
  }

  private async scanKind(scope: string, kind: 'ops' | 'checkpoints'): Promise<void> {
    const dir = `${this.domain.scopeDir(scope)}/${kind}`;
    const authors = await this.storage.list(dir);
    for (const a of authors ?? []) {
      if (a.kind !== 'dir' || !KEY_ID_RE.test(a.name)) {
        this.unknown(`${dir}/${a.name}`, 'not an author folder');
        continue;
      }
      const files = (await this.storage.list(`${dir}/${a.name}`)) ?? [];
      const names = files.filter((f) => f.kind === 'file').map((f) => f.name).sort();
      for (const f of files) {
        if (f.kind === 'file' && OP_FILE_RE.test(f.name)) continue;
        const p = `${dir}/${a.name}/${f.name}`;
        this.unknown(p, 'file name does not match the pattern (conflict copy?)');
        if (!SAFE_NAME_RE.test(f.name)) continue; // never read a name that the storage refuses
        // A conflict copy "<seq>-<suffix>.json" can hold a second op with the same seq: a fork.
        const m = /^(\d{10})-.+\.json$/.exec(f.name);
        if (kind === 'ops' && f.kind === 'file' && m && !this.forkCandidates.has(p) && !this.badCopies.has(p) && this.mayRead(p)) {
          // A conflict copy that is too large or not an op is only an unknown file. The engine does not
          // read it again (files are immutable), except a copy that is not valid JSON (a partial read).
          const text = await readLimited(this.storage, p, this.maxOpFileBytes);
          const r = text === null || text === TOO_LARGE ? null : await parseOpFile(`${dir}/${a.name}/${m[1]}.json`, text, this.domain);
          if (r && 'env' in r) this.forkCandidates.set(p, { env: r.env, hash: r.hash, source: 'file' });
          else if (r && r.kind === 'parse-error' && r.detail === NOT_JSON && typeof text === 'string') this.countNotJson(p, text);
          else if (text !== null) this.badCopies.add(p);
        }
      }
      const paths = names.filter((n) => OP_FILE_RE.test(n)).map((n) => `${dir}/${a.name}/${n}`);
      if (kind === 'ops') {
        // Read and parse in parallel; the workers change no engine state. Then apply the results
        // 1 at a time in path order: the same order as the sequential scan (ops, fileIssues).
        // If 1 read fails, pool() rejects after all reads have ended, and nothing is applied.
        // A file with a known issue is not read again (op files are immutable), except a file that
        // is not valid JSON (a partial read, see MAX_NOT_JSON_READS). reverifyAll() reads all again.
        const todo = paths.filter((p) => !this.ops.has(p) && (!this.fileIssues.has(p) || this.fileIssues.get(p)!.detail === NOT_JSON) && this.mayRead(p));
        const parsed: (Awaited<ReturnType<typeof parseOpFile>> | null)[] = new Array(todo.length).fill(null);
        await pool(todo, READ_CONCURRENCY, async (p, i) => {
          parsed[i] = await this.readOpFile(p);
        });
        for (let i = 0; i < todo.length; i++) this.applyRead(todo[i], parsed[i]);
      } else for (const p of paths) if (!this.checkpointsSeen.has(p) && this.mayRead(p) && this.packWaitOver(p)) await this.readCheckpoint(p);
    }
  }

  /**
   * Reads forward from seq. Known numbers are skipped. After a missing number it also tries the
   * next QUICK_LOOKAHEAD numbers, because a gap (chain format 2) can come from files of another
   * person. A larger gap waits for the next full scan.
   * Changes no engine state: returns the files that exist, in read order. The caller applies them.
   * A file whose issue is "not valid JSON" is read again: the issue can come from a partial read
   * of a file that another client still writes (the Node adapter and OneDrive are not atomic).
   * At most QUICK_LOOKAHEAD such files are read again for each call. If the read gives the same
   * issue again, the file counts as a known number (it does not start the look-ahead again).
   */
  private async readForward(scope: string, keyId: string, seq: number): Promise<ReadResult[]> {
    const out: ReadResult[] = [];
    let missing = 0;
    let rereads = 0;
    for (let s = seq; missing <= QUICK_LOOKAHEAD; s++) {
      const path = this.path(scope, 'ops', keyId, s);
      if (this.ops.has(path)) continue;
      const known = this.fileIssues.get(path);
      if (known && (known.kind !== 'parse-error' || known.detail !== NOT_JSON || rereads >= QUICK_LOOKAHEAD || !this.mayRead(path))) continue;
      if (known) rereads++;
      const parsed = await this.readOpFile(path);
      if (known && parsed && !('env' in parsed) && JSON.stringify(parsed) === JSON.stringify(known)) continue;
      if (parsed === null) {
        missing++;
        continue;
      }
      out.push({ path, parsed });
      missing = 0;
    }
    return out;
  }

  /**
   * Reads and parses 1 op file. Returns null if the file does not exist, and a 'parse-error'
   * issue if it is larger than MAX_OP_FILE_BYTES. Changes no engine state, except the counter of
   * reads that gave "not valid JSON" (it only limits later reads).
   */
  private async readOpFile(path: string): Promise<ReadResult['parsed'] | null> {
    const text = await readLimited(this.storage, path, this.maxOpFileBytes);
    if (text === null) return null;
    if (text === TOO_LARGE) return { kind: 'parse-error', path, detail: tooLarge(this.maxOpFileBytes) };
    const r = await parseOpFile(path, text, this.domain);
    if (!('env' in r) && r.kind === 'parse-error' && r.detail === NOT_JSON) this.countNotJson(path, text);
    else this.notJsonReads.delete(path);
    return r;
  }

  /**
   * False if the file used its budget of reads with the same content that is not valid JSON, and the wait did not end yet.
   * If the clock went back after the last read, the wait ends: else a jump back makes the wait longer by the size of the jump.
   */
  private mayRead(path: string): boolean {
    const r = this.notJsonReads.get(path);
    if (!r || r.same < MAX_NOT_JSON_READS) return true;
    const wait = Math.min(NOT_JSON_WAIT_MS * 2 ** Math.min(r.same - MAX_NOT_JSON_READS, 20), NOT_JSON_MAX_WAIT_MS);
    const now = this.now();
    return now < r.at || now >= r.at + wait;
  }

  /** False while a pack of a key that is still not known waits for its next read (see packWaits). */
  private packWaitOver(path: string): boolean {
    const w = this.packWaits.get(path);
    return !w || this.keys.has(w.authorKeyId) || this.now() >= w.at + Math.min(NOT_JSON_WAIT_MS * 2 ** Math.min(w.n, 20), UNKNOWN_KEY_PACK_MAX_WAIT_MS);
  }

  /** Records a read that gave "not valid JSON". A new content starts the count again. */
  private countNotJson(path: string, text: string): void {
    const sig = contentSig(text);
    const r = this.notJsonReads.get(path);
    this.notJsonReads.set(path, { sig, same: r && r.sig === sig ? r.same + 1 : 1, at: this.now() });
  }

  /** Returns false if the file does not exist. */
  private async readOp(path: string): Promise<boolean> {
    const parsed = await this.readOpFile(path);
    if (parsed === null) return false;
    this.applyRead(path, parsed);
    return true;
  }

  /** Records the result of 1 op file read (null: the file does not exist). */
  private applyRead(path: string, r: Awaited<ReturnType<typeof parseOpFile>> | null): void {
    if (r === null) return;
    if ('env' in r) {
      if (this.fileIssues.delete(path)) this.issuesDirty = true;
      this.setOp(path, { env: r.env, hash: r.hash, source: 'file' });
    } else {
      // A new issue, or an issue with a different content (for example a re-read of a partial file).
      const old = this.fileIssues.get(path);
      if (!old || JSON.stringify(old) !== JSON.stringify(r)) this.issuesDirty = true;
      this.fileIssues.set(path, r);
    }
  }

  private async readCheckpoint(path: string): Promise<void> {
    const text = await readLimited(this.storage, path, MAX_CHECKPOINT_BYTES);
    if (text === null) return;
    if (text === TOO_LARGE) {
      this.checkpointsSeen.add(path);
      this.fileIssues.set(path, { kind: 'bad-checkpoint', path, detail: tooLarge(MAX_CHECKPOINT_BYTES) });
      return;
    }
    const pp = parsePath(path, (d) => this.domain.scopeFromDir(d));
    let cp: Checkpoint;
    try {
      cp = JSON.parse(text);
    } catch {
      // Possibly a partial read of a file that another client still writes: the next full scan reads
      // it again (see MAX_NOT_JSON_READS).
      this.countNotJson(path, text);
      this.fileIssues.set(path, { kind: 'bad-checkpoint', path, detail: NOT_JSON });
      return;
    }
    this.checkpointsSeen.add(path);
    this.fileIssues.delete(path);
    this.notJsonReads.delete(path);
    try {
      if (cp?.v !== 1 || !Array.isArray(cp.ops) || !pp || cp.scope !== pp.scope || cp.authorKeyId !== pp.keyId || cp.seq !== pp.seq || typeof cp.wallTime !== 'string' || typeof cp.sig !== 'string') throw new Error('bad format');
    } catch (e) {
      this.fileIssues.set(path, { kind: 'bad-checkpoint', path, detail: (e as Error).message });
      return;
    }
    await this.keys.addFromTrustRoot(this.trustRoot);
    if (!this.keys.has(cp.authorKeyId)) {
      // The key of the author is not known (yet). Keep nothing of the pack: else many large packs of
      // unknown keys can fill the memory. Read it again in a later full scan, after a wait. An honest
      // pack of a key that is not known yet is rare: the scan reads the users scope first.
      // recompute() reports the pack only if the key is still not known (see packWaits).
      this.checkpointsSeen.delete(path);
      const w = this.packWaits.get(path);
      this.packWaits.set(path, { authorKeyId: cp.authorKeyId, n: w ? w.n + 1 : 0, at: this.now() });
      return;
    }
    this.packWaits.delete(path);
    // Check the signature now (the key is known). A pack that JCS refuses (for example 1e400 in an
    // op) has a bad signature: it must not stop the scan.
    let data: Uint8Array | null = null;
    try {
      const { sig: _sig, ...rest } = cp;
      data = utf8(canonicalize(rest));
    } catch {
      this.cpSigOk.set(path, false);
    }
    if (data) await this.checkPackSig(path, cp.authorKeyId, cp.sig, data);
    this.pendingCheckpoints.push({ path, authorKeyId: cp.authorKeyId });
    // Use the ops of a pack only if an admin signed it (known now). Else the scan reads the op files:
    // a pack that nobody can check must not hide or replace real files.
    if (!this.packTrusted(path, cp.authorKeyId)) return;
    this.usedPacks.add(path);
    // The op paths of the pack, for checkpointStats. Only for a used pack: checkpointStats counts only
    // used packs, and a pack of another person must not keep a large list in memory.
    const paths: string[] = [];
    for (const env of cp.ops)
      if (env?.scope === cp.scope && typeof env.authorKeyId === 'string' && KEY_ID_RE.test(env.authorKeyId) && Number.isSafeInteger(env.seq) && env.seq >= 1)
        paths.push(this.path(env.scope, 'ops', env.authorKeyId, env.seq));
    this.checkpointInfo.set(path, { scope: cp.scope, wallTime: cp.wallTime, paths });
    for (const env of cp.ops) {
      if (env?.scope !== cp.scope || typeof env.authorKeyId !== 'string' || !KEY_ID_RE.test(env.authorKeyId) || !Number.isSafeInteger(env.seq) || env.seq < 1) continue;
      const p = this.path(env.scope, 'ops', env.authorKeyId, env.seq);
      if (this.ops.has(p)) continue;
      // Each op of the pack carries its own signature. It is verified like a file.
      const r = await checkEnvelope(env, p, this.domain);
      if ('env' in r) {
        this.setOp(p, { env: r.env, hash: r.hash, source: 'checkpoint' });
        this.packedPaths.add(p);
      }
    }
  }

  /**
   * Checks the pack signature 1 time for each file and keeps the result in cpSigOk. The result cannot
   * change once the key is known. The caller checks keys.has first.
   */
  private async checkPackSig(path: string, keyId: string, sig: string, data: Uint8Array): Promise<void> {
    if (this.cpSigOk.has(path)) return;
    const s = await this.keys.verify(keyId, sig, data);
    if (s !== 'unknown-key') this.cpSigOk.set(path, s === 'ok');
  }

  /** True if the pack signature is valid and its author is an admin (in the current state or in the trust root). */
  private packTrusted(path: string, keyId: string): boolean {
    if (this.cpSigOk.get(path) !== true) return false;
    return this.isAdminKey(this.state, keyId) || this.isAdminKey(this.domain.rootState(this.trustRoot), keyId);
  }

  /** True if the key is an admin key that is not revoked (no cutoff from the trust root or from an op). */
  private isAdminKey(state: ReplayResult['state'], keyId: string): boolean {
    if (this.result.cutoffs.has(keyId) || this.trustRoot?.roots.some((r) => r.keyId === keyId && r.cutoffs)) return false;
    try {
      const owner = this.domain.keyOwner(state, keyId);
      return typeof owner === 'string' && this.domain.isAdmin(state, owner);
    } catch {
      return false;
    }
  }

  /**
   * Forgets all cached files and reads and verifies everything again.
   * A client never reads a known file again during normal scans. So a file that
   * someone changed or deleted after the first read is only found by this full check.
   */
  reverifyAll(): Promise<void> {
    return this.serial(() => this.reverifyInner());
  }

  private async reverifyInner(): Promise<void> {
    this.ops.clear();
    this.heads_.clear();
    this.appliedHashes.clear();
    this.trustRootSig = '';
    this.keysScanned.clear();
    this.forkCandidates.clear();
    this.fileIssues.clear();
    this.sigStatus.clear();
    this.checkpointsSeen.clear();
    this.packedPaths.clear();
    this.cpSigOk.clear();
    this.packIssues.clear();
    this.usedPacks.clear();
    this.checkpointInfo.clear();
    this.notJsonReads.clear();
    this.badCopies.clear();
    this.packWaits.clear();
    this.pendingCheckpoints = [];
    await this.scanInner('full');
  }

  // ---- Verify + replay ---------------------------------------------------------------------

  /**
   * checkChains for each (scope|author) group, again only for a group whose input changed.
   * The chains of 2 authors are independent (verify.ts groups the same way), and the result
   * of 1 group depends only on its entries. The input key lists the path, the hash and the
   * signature status of each entry, so a change of any of them checks the group again.
   */
  private checkChainsCached(entries: ChainInput[]): ChainResult {
    const groups = new Map<string, ChainInput[]>();
    for (const e of entries) {
      const k = `${e.env.scope}|${e.env.authorKeyId}`;
      let g = groups.get(k);
      if (!g) groups.set(k, (g = []));
      g.push(e);
    }
    const out: ChainResult = { valid: [], issues: [], heads: new Map() };
    const cache = new Map<string, { input: string; res: ChainResult }>();
    for (const [k, g] of groups) {
      // In the order of `ops` (stable). Another order only misses the cache: that is safe.
      const input = g.map((e) => `${e.path} ${e.hash} ${e.sig}`).join('\n');
      const hit = this.chainCache.get(k);
      const res = hit && hit.input === input ? hit.res : checkChains(g);
      cache.set(k, { input, res });
      for (const v of res.valid) out.valid.push(v);
      for (const i of res.issues) out.issues.push(i);
      for (const [hk, h] of res.heads) out.heads.set(hk, h);
    }
    this.chainCache = cache;
    return out;
  }

  /**
   * Verifies and replays the known ops again (no storage reads). Runs in the queue of serial(), so
   * it never runs at the same time as a scan or a write. The tasks in that queue use
   * recomputeInner(). If a serial task calls recompute(), the task waits for itself for ever.
   */
  recompute(): Promise<void> {
    return this.serial(() => this.recomputeInner());
  }

  private async recomputeInner(): Promise<void> {
    await this.keys.addFromTrustRoot(this.trustRoot);
    const newEnvs: Envelope[] = [];
    for (const o of this.ops.values()) if (!this.keysScanned.has(o.hash)) (this.keysScanned.add(o.hash), newEnvs.push(o.env));
    for (const o of this.forkCandidates.values()) if (!this.keysScanned.has(o.hash)) (this.keysScanned.add(o.hash), newEnvs.push(o.env));
    await this.keys.addFromOps(newEnvs, this.domain);
    // An op from a pack with a bad signature must not hide the real file: drop it and read the file.
    const dropped: string[] = [];
    const packed = [...this.ops].filter(([, o]) => o.source === 'checkpoint' && this.sigStatus.get(o.hash) !== 'ok' && this.keys.has(o.env.authorKeyId));
    // The signatures are checked in parallel (WebCrypto is async). `dropped` keeps the order of `ops`.
    const packedBad = new Set<string>();
    await pool(packed, READ_CONCURRENCY, async ([path, o]) => {
      const s = await verifySignature(o.env, this.keys);
      this.sigStatus.set(o.hash, s);
      if (s === 'bad') packedBad.add(path);
    });
    for (const [path] of packed) if (packedBad.has(path)) dropped.push(path);
    if (dropped.length) {
      for (const path of dropped) this.packIssues.set(path, { kind: 'bad-checkpoint', path, detail: 'a trusted checkpoint contains this op with a bad signature: the file is used instead' });
      for (const path of dropped) {
        this.ops.delete(path);
        this.packedPaths.delete(path);
      }
      this.heads_.clear();
      for (const [p, x] of this.ops) this.setOp(p, x);
      for (const path of dropped) await this.readOp(path);
      // Keys that the re-read files register.
      await this.keys.addFromOps(dropped.map((p) => this.ops.get(p)?.env).filter((e): e is Envelope => !!e), this.domain);
    }
    // Check the signatures that are not known yet, in parallel. Then build the entries in the order of `ops`.
    const pending = new Map<string, SigStatus>();
    const todo = [...this.ops.values()].filter((o) => {
      const s = this.sigStatus.get(o.hash);
      return s !== 'ok' && s !== 'bad';
    });
    await pool(todo, READ_CONCURRENCY, async (o) => {
      const s = await verifySignature(o.env, this.keys);
      if (s !== 'unknown-key') this.sigStatus.set(o.hash, s);
      pending.set(o.hash, s);
    });
    const entries: ChainInput[] = [];
    for (const [path, o] of this.ops) {
      // Never pass an op without a checked signature to checkChains: check it here if necessary.
      const s = this.sigStatus.get(o.hash) ?? pending.get(o.hash) ?? (await verifySignature(o.env, this.keys));
      entries.push({ path, env: o.env, hash: o.hash, sig: s });
    }
    for (const [path, o] of this.forkCandidates) {
      let s = this.sigStatus.get(o.hash);
      if (s !== 'ok' && s !== 'bad') s = await verifySignature(o.env, this.keys);
      // Only a validly signed second op is a fork. A broken copy is only an unknown file.
      if (s === 'ok') entries.push({ path, env: o.env, hash: o.hash, sig: s });
    }
    const chains = this.checkChainsCached(entries);
    this.chainHeads = chains.heads;
    this.lastSigned = new Map();
    for (const o of this.ops.values()) {
      if (this.sigStatus.get(o.hash) !== 'ok') continue;
      const k = `${o.env.scope}|${o.env.authorKeyId}`;
      const cur = this.lastSigned.get(k);
      if (!cur || o.env.seq > cur.env.seq) this.lastSigned.set(k, o);
    }
    // Incremental apply if it gives the same result as a full replay: same trust
    // root, no op became invalid, no new revocation, and all new ops sort after
    // the last applied op. Otherwise: full replay (always correct).
    // Exception: rejected ops at the end of the order (for example of an outsider with a
    // far-future HLC). The Replayer takes back the rejected ops that sort after the first new op,
    // exactly. Then it applies the new ops and these ops again, in the total order. A rejected op
    // does not change the state, thus it cannot change the revocations: the tail can contain a
    // revocation op. But a re-applied op can apply now (for example after a new grant). If such an
    // op contains a revocation and the replay does not reject it now, the cutoffs can change: then
    // the engine does a full replay.
    const trSig = canonicalize(this.trustRoot);
    const fresh = sortOps(chains.valid.filter((v) => !this.appliedHashes.has(v.hash)));
    const tail = this.replayer.rejectedTail();
    let back = 0;
    if (fresh.length) while (back < tail.length && orderKey(tail[tail.length - 1 - back].op.env, fresh[0].env) > 0) back++;
    const last = back ? tail[tail.length - back].before : this.replayer.last;
    const incremental =
      this.appliedHashes.size > 0 &&
      (!this.replayer.endIssue || fresh.length === 0) &&
      trSig === this.trustRootSig &&
      chains.valid.length - fresh.length === this.appliedHashes.size &&
      fresh.every((v) => !hasRevocation(v.env, this.domain)) &&
      (fresh.length === 0 || last === null || orderKey(fresh[0].env, last) > 0);
    let full = !incremental;
    if (incremental) {
      const again = this.replayer.takeBackRejected(back);
      const revocations = new Set(again.filter((v) => hasRevocation(v.env, this.domain)));
      for (const v of sortOps([...fresh, ...again])) if (this.replayer.apply(v).status !== 'rejected' && revocations.has(v)) full = true;
      for (const v of fresh) this.appliedHashes.add(v.hash);
      // Count only an incremental run that the engine keeps (not one that a full replay replaces).
      if (!full) {
        this.stats.incrementalOps += fresh.length;
        this.stats.takenBack += again.length;
      }
    }
    if (full) {
      this.replayer = replayFull(chains.valid, this.replayOpts());
      this.appliedHashes = new Set(chains.valid.map((v) => v.hash));
      this.trustRootSig = trSig;
      this.stats.fullReplays++;
    }
    this.result = this.replayer.result();
    // Observe only the HLCs of ops that the replay did not reject and that are not far in the future
    // of this computer. A person without a grant can sign a valid chain with a self-signed key. A
    // granted user can write a superseded op with the maximum HLC. Neither must move the clock of
    // all clients (at the maximum, tick() throws and nobody can write). The replay reports such an
    // op as 'future-clock'. writeInner() also observes the own last op of the writer.
    const now = this.now();
    for (const a of this.result.audit) if (a.status !== 'rejected' && a.hlc.t <= now + FUTURE_CLOCK_MS) this.clock.observe(a.hlc);

    const issues: Issue[] = [...this.fileIssues.values(), ...this.trustRootIssues(), ...this.packIssues.values(), ...chains.issues, ...this.result.issues];
    // Local future-clock check: the wall time of the op is far after the time of this computer.
    for (const o of this.ops.values()) {
      const wall = isIso(o.env.wallTime) ? Date.parse(o.env.wallTime) : NaN;
      if (Number.isFinite(wall) && wall - now > FUTURE_CLOCK_MS)
        issues.push({ kind: 'future-clock', opId: o.env.opId, scope: o.env.scope, authorKeyId: o.env.authorKeyId, seq: o.env.seq, detail: 'the wall time of the op is in the future of this computer' });
    }
    for (const [path, w] of this.packWaits)
      if (!this.keys.has(w.authorKeyId)) issues.push({ kind: 'bad-checkpoint', path, detail: 'the key of the checkpoint author is not known (yet): the engine reads the pack again later' });
    for (const { path, authorKeyId } of this.pendingCheckpoints) {
      const ok = this.cpSigOk.get(path);
      const isAdmin = this.isAdminKey(this.state, authorKeyId);
      const revoked = this.result.cutoffs.has(authorKeyId) || !!this.trustRoot?.roots.some((r) => r.keyId === authorKeyId && r.cutoffs);
      if (!ok || !isAdmin)
        issues.push({ kind: 'bad-checkpoint', path, detail: !ok ? 'checkpoint signature is not valid' : revoked ? 'checkpoint author key is revoked: the pack is not used' : 'checkpoint author is not an admin' });
    }
    this.issues = issues;
  }

  /** Highest known (scope, author, seq) for each chain. */
  heads(): { scope: string; keyId: string; seq: number; hash: string }[] {
    return [...this.heads_.values()];
  }

  // ---- Write ---------------------------------------------------------------------------------

  /**
   * The own last op of a key in a scope: the validly signed op with the highest seq.
   * Files with a bad signature in the own folder (for example garbage of another person) do not count.
   */
  private ownLast(scope: string, keyId: string): KnownOp | null {
    return this.lastSigned.get(`${scope}|${keyId}`) ?? null;
  }

  /** The last op of each valid chain (signature and chain checked). Use it for cutoffs and checkpoint frontiers. */
  validHeads(): { scope: string; keyId: string; seq: number; hash: string }[] {
    return [...this.chainHeads].map(([k, h]) => {
      // The key is "scope|keyId". A scope can contain "|" (ID_RE), a keyId never (KEY_ID_RE).
      const i = k.lastIndexOf('|');
      return { scope: k.slice(0, i), keyId: k.slice(i + 1), seq: h.seq, hash: h.hash };
    });
  }

  private nextSeq(scope: string, keyId: string): number {
    return (this.ownLast(scope, keyId)?.env.seq ?? 0) + 1;
  }

  /**
   * Applies an op as if it were the next op of this key, and undoes it. For the UI: write() does
   * its own check after it reads the new own files.
   * Returns the audit entry: status applied, no-effect, superseded or rejected.
   */
  check(keyId: string, scope: string, type: string, payload: Record<string, unknown>): AuditEntry {
    const hlc = this.clock.peek();
    const wall = this.now();
    return this.probe({
      v: 1,
      opId: PROBE_OP_ID,
      scope,
      authorKeyId: keyId,
      seq: this.nextSeq(scope, keyId),
      prevHash: null,
      hlc: { t: Math.max(hlc.t, Math.floor(wall)), c: hlc.c + 1 },
      wallTime: new Date(wall).toISOString(),
      type,
      payload,
    });
  }

  /** Applies the op on the current state and undoes it. The caller gives all fields, also the seq. */
  private probe(u: UnsignedEnvelope): AuditEntry {
    return this.replayer.probe({ ...u, sig: '' });
  }

  /**
   * Signs and writes 1 op. Checks it first with the same code as the replay.
   * Throws AuthError if the op is rejected, and SupersededError if it would have
   * no effect because of the current state (unless allowSuperseded is true).
   */
  write(signer: Signer, scope: string, type: string, payload: Record<string, unknown>, opts: { allowSuperseded?: boolean } = {}): Promise<Envelope> {
    return this.serial(() => this.writeInner(signer, scope, type, payload, opts));
  }

  private async writeInner(signer: Signer, scope: string, type: string, payload: Record<string, unknown>, opts: { allowSuperseded?: boolean }): Promise<Envelope> {
    // Keys that this op registers must be known before the check (else GrantUser/AddKey look invalid).
    await this.keys.addFromOps([{ type, payload } as Envelope], this.domain);
    for (let attempt = 0; attempt < 3; attempt++) {
      // The numbers that files in the own folder use (valid or not). A file of another person
      // under the next number must not block this author. Chain format 2: the chain skips files
      // that are not valid ops of the author. The writer takes the smallest free number above
      // its own last valid op.
      const dir = `${this.domain.scopeDir(scope)}/ops/${signer.keyId}`;
      const taken = new Set<number>();
      let fresh = false;
      for (const f of (await this.storage.list(dir)) ?? []) {
        const m = OP_FILE_RE.exec(f.name);
        if (!m) continue;
        taken.add(Number(m[1]));
        // Read unknown files of this author first (for example of the same key in another tab or PC):
        // the own last op must be known, else the new op would make a fork.
        // Also read again a "not valid JSON" file in the QUICK_LOOKAHEAD numbers above the own last op:
        // it can be a partial read of an own op from another tab or PC (then a write without it would
        // make a fork). A partial own op always gives this issue. Other issues do not change (the op
        // files are immutable).
        const p = `${dir}/${f.name}`;
        const n = Number(m[1]);
        const lastSeq = this.ownLast(scope, signer.keyId)?.env.seq ?? 0;
        const issue = this.fileIssues.get(p);
        const partial = issue?.kind === 'parse-error' && issue.detail === NOT_JSON && n > lastSeq && n <= lastSeq + QUICK_LOOKAHEAD;
        if (!this.ops.has(p) && (!issue || partial)) {
          await this.readOp(p);
          fresh = true;
        }
      }
      if (fresh) await this.recomputeInner();
      const last = this.ownLast(scope, signer.keyId);
      let seq = (last?.env.seq ?? 0) + 1;
      while (taken.has(seq)) seq++;
      const prevHash = last?.hash ?? null;
      // The clock observed the ops that are not rejected in recompute(). Also observe the own last op,
      // so that the chain HLC increases.
      if (last) this.clock.observe(last.env.hlc);
      const hlc = this.clock.tick();
      const u: UnsignedEnvelope = {
        v: 1,
        opId: uuidv7(this.now()),
        scope,
        authorKeyId: signer.keyId,
        seq,
        prevHash,
        hlc,
        wallTime: new Date(this.now()).toISOString(),
        type,
        payload,
      };
      // Check the op now, after the read of the new own files (of another tab or PC), with the
      // fields that the file will have. The seq matters: a revocation cutoff can reject it.
      const r = this.probe(u);
      if (r.status === 'rejected') throw new AuthError(r.reason ?? 'rejected');
      if (r.status === 'superseded' && !opts.allowSuperseded) throw new SupersededError(r.reason ?? 'superseded', r.code);
      const env = await signEnvelope(u, (b) => signer.sign(b));
      const path = this.path(scope, 'ops', signer.keyId, seq);
      // Check the envelope BEFORE the write: an invalid file would stay forever and block this seq.
      const c = await checkEnvelope(env, path, this.domain);
      if (!('env' in c)) throw new Error(`internal: the new op is invalid: ${c.detail}`);
      // Other clients do not read a larger op file: the chain of this author would stop there for them.
      const text = canonicalize(env);
      const size = utf8(text).length;
      if (size > this.maxOpFileBytes) throw new Error(`the op is too large (${size} bytes, the maximum is ${this.maxOpFileBytes} bytes)`);
      try {
        await this.storage.writeNew(path, text);
      } catch (e) {
        if (e instanceof FileExistsError) continue; // another tab or PC with the same key wrote this seq: re-read and retry
        throw e;
      }
      this.setOp(path, { env, hash: c.hash, source: 'local' });
      this.sigStatus.set(c.hash, 'ok');
      await this.recomputeInner();
      return env;
    }
    throw new Error('could not allocate a sequence number (3 attempts)');
  }

  // ---- Checkpoints ----------------------------------------------------------------------------

  /** Writes a pack of all valid ops of a scope (admins only). */
  createCheckpoint(signer: Signer, scope: string): Promise<string> {
    return this.serial(() => this.checkpointInner(signer, scope));
  }

  private async checkpointInner(signer: Signer, scope: string): Promise<string> {
    const owner = this.domain.keyOwner(this.state, signer.keyId);
    if (typeof owner !== 'string' || !this.domain.isAdmin(this.state, owner)) throw new AuthError('only an admin can write a checkpoint');
    const valid = this.result.audit.filter((a) => a.scope === scope).map((a) => a.hash);
    const byHash = new Map([...this.ops.values()].map((o) => [o.hash, o.env]));
    const ops = valid.map((h) => byHash.get(h)!).filter(Boolean);
    const frontier: Checkpoint['frontier'] = {};
    for (const h of this.validHeads()) if (h.scope === scope) frontier[h.keyId] = { seq: h.seq, hash: h.hash };
    const dir = `${this.domain.scopeDir(scope)}/checkpoints/${signer.keyId}`;
    // The next number after the highest own checkpoint (a used pack, or a listed file that the engine
    // does not know as a bad checkpoint). Thus a gap is not filled: a file of another PC can still
    // come there. A bad file of another person with a high number (for example 9999999999.json)
    // does not move the numbers after a full scan found it. Numbers in use (listed, or a
    // FileExistsError of an earlier attempt) are skipped.
    const bad = new Set(this.issues.filter((i) => i.kind === 'bad-checkpoint').map((i) => i.path));
    const nextAfter = (p: string) => {
      const m = p.startsWith(`${dir}/`) ? OP_FILE_RE.exec(p.slice(dir.length + 1)) : null;
      return m && !bad.has(p) ? Number(m[1]) + 1 : 1;
    };
    let start = 1;
    for (const p of this.usedPacks) start = Math.max(start, nextAfter(p));
    const used = new Set<number>();
    for (let attempt = 0; attempt < 3; attempt++) {
      for (const f of (await this.storage.list(dir)) ?? []) {
        const m = OP_FILE_RE.exec(f.name);
        if (!m) continue;
        used.add(Number(m[1]));
        start = Math.max(start, nextAfter(`${dir}/${f.name}`));
      }
      let seq = start;
      while (used.has(seq)) seq++;
      if (seq > MAX_SEQ) throw new Error(`no free checkpoint number: the number would be larger than ${MAX_SEQ}`);
      const rest: Omit<Checkpoint, 'sig'> = { v: 1, scope, authorKeyId: signer.keyId, seq, hlc: this.clock.tick(), wallTime: new Date(this.now()).toISOString(), frontier, ops };
      const cp: Checkpoint = { ...rest, sig: await signer.sign(utf8(canonicalize(rest))) };
      const text = canonicalize(cp);
      // Other clients refuse a larger checkpoint file. Thus do not write it.
      const size = utf8(text).length;
      if (size > MAX_CHECKPOINT_BYTES) throw new Error(`the checkpoint is too large (${size} bytes, the maximum is ${MAX_CHECKPOINT_BYTES} bytes)`);
      const path = this.path(scope, 'checkpoints', signer.keyId, seq);
      try {
        await this.storage.writeNew(path, text);
      } catch (e) {
        if (e instanceof FileExistsError) {
          used.add(seq); // another tab or PC with the same key wrote this number: list again and retry
          continue;
        }
        throw e;
      }
      this.checkpointsSeen.add(path);
      this.usedPacks.add(path);
      // Check the own checkpoint like any other (signature now, author is admin in the next recompute).
      await this.checkPackSig(path, signer.keyId, cp.sig, utf8(canonicalize(rest)));
      this.pendingCheckpoints.push({ path, authorKeyId: signer.keyId });
      this.checkpointInfo.set(path, { scope, wallTime: rest.wallTime, paths: ops.map((env) => this.path(env.scope, 'ops', env.authorKeyId, env.seq)) });
      await this.recomputeInner();
      return path;
    }
    throw new Error('could not allocate a checkpoint number (3 attempts)');
  }

  /**
   * For each scope: the op files, the op files that are in no valid checkpoint,
   * and the valid checkpoints. The admin page uses it to advise a checkpoint.
   */
  checkpointStats(scopes: readonly string[]): ScopeFileStats[] {
    const bad = new Set(this.issues.filter((i) => i.kind === 'bad-checkpoint').map((i) => i.path));
    const out = new Map(scopes.map((scope) => [scope, { scope, opFiles: 0, notInCheckpoint: 0, packable: 0, checkpoints: 0, lastCheckpoint: null as string | null }]));
    const covered = new Set<string>();
    for (const [path, info] of this.checkpointInfo) {
      const x = out.get(info.scope);
      // Count only packs whose ops a client uses. A pack that was not trusted when it was read does not help.
      if (!x || bad.has(path) || !this.usedPacks.has(path)) continue;
      x.checkpoints++;
      if (x.lastCheckpoint === null || info.wallTime > x.lastCheckpoint) x.lastCheckpoint = info.wallTime;
      for (const p of info.paths) covered.add(p);
    }
    const inAudit = new Set(this.result.audit.map((a) => a.hash));
    for (const [path, o] of this.ops) {
      const x = out.get(o.env.scope);
      if (!x) continue;
      x.opFiles++;
      if (covered.has(path)) continue;
      x.notInCheckpoint++;
      if (inAudit.has(o.hash)) x.packable++;
    }
    return [...out.values()];
  }

  // ---- Cache -------------------------------------------------------------------------------------

  exportCache(): EngineCache {
    return {
      v: 3,
      ops: [...this.ops].map(([path, o]) => ({ path, env: o.env, hash: o.hash, source: o.source === 'checkpoint' ? 'checkpoint' : 'file' })),
      sigOk: [...this.sigStatus].filter(([, s]) => s === 'ok').map(([h]) => h),
      trustRoot: this.knownTr,
    };
  }

  /**
   * Restores a cache. The cache must come from a trusted, integrity-protected store. An engine
   * without a known trust root takes the trust root of the cache as the known trust root and as
   * the last good copy. A cache of another version is ignored.
   */
  importCache(c: EngineCache): Promise<void> {
    return this.serial(() => this.importInner(c));
  }

  private async importInner(c: EngineCache): Promise<void> {
    if (c?.v !== 3) return;
    const tr = c.trustRoot;
    if (!this.knownTr && tr != null && trustRootError(tr) === null) {
      this.knownTr = frozenCopy(tr);
      // A copy: the app can change the cache object later.
      if (!this.trustRoot) await this.useTrustRoot(JSON.parse(canonicalize(tr)) as TrustRoot);
    }
    for (const o of c.ops)
      if (!this.ops.has(o.path)) {
        const source = o.source === 'checkpoint' ? 'checkpoint' : 'file';
        this.setOp(o.path, { env: o.env, hash: o.hash, source });
        if (source === 'checkpoint') this.packedPaths.add(o.path);
      }
    for (const h of c.sigOk) this.sigStatus.set(h, 'ok');
    await this.loadTrustRootInner();
    await this.recomputeInner();
  }

  /** All known op envelopes (for tests and tools). */
  knownOps(): Envelope[] {
    return [...this.ops.values()].map((o) => o.env);
  }
}

export const maxHlc = (envs: Envelope[]): Hlc => envs.reduce<Hlc>((m, e) => (compareHlc(e.hlc, m) > 0 ? e.hlc : m), { t: 0, c: 0 });
