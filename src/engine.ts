// SPDX-License-Identifier: MIT
// Copyright 2026, Lukáš Czerner <lukas@czerner.cz>
// Engine: scans a Storage, verifies op files, replays, and writes new ops.
// UI-free. The browser app, the tests and the simulation use the same class.

import { canonicalize } from './canonical';
import { verifyBytes } from './crypto';
import type { Domain } from './domain';
import { utf8 } from './encoding';
import { compareHlc, HlcClock, type Hlc } from './hlc';
import { uuidv7 } from './ids';
import { filePath, KEY_ID_RE, OP_FILE_RE, parsePath, TRUST_ROOT_PATH } from './paths';
import { FUTURE_CLOCK_MS, hasRevocation, orderKey, replayFull, sortOps, type Replayer, type ReplayResult } from './replay';
import { FileExistsError, type Storage } from './storage/types';
import type { AuditEntry, Envelope, Issue, TrustRoot, UnsignedEnvelope } from './types';
import { checkChains, checkEnvelope, KeyMap, parseOpFile, signEnvelope, verifySignature, type ChainInput, type SigStatus } from './verify';
import { isIso } from './validate';

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
  v: 2;
  /** `source` = checkpoint: the op came from a trusted pack and is checked again like a pack op. */
  ops: { path: string; env: Envelope; hash: string; source?: 'file' | 'checkpoint' }[];
  sigOk: string[];
}

/** The op is not permitted (rejected by validation or authorize). */
export class AuthError extends Error {}
/** The op is permitted, but it would have no effect now (superseded). */
export class SupersededError extends Error {}

export class Engine {
  readonly clock: HlcClock;
  trustRoot: TrustRoot | null = null;
  private ops = new Map<string, KnownOp>(); // path → op
  private heads_ = new Map<string, { scope: string; keyId: string; seq: number; hash: string }>(); // scope|keyId → highest known op
  private forkCandidates = new Map<string, KnownOp>(); // conflict-copy path → op with a seq that has a main file
  private fileIssues = new Map<string, Issue>(); // path → issue (unknown / unparsable files)
  private sigStatus = new Map<string, SigStatus>(); // op hash → ok | bad
  private keys = new KeyMap();
  private checkpointsSeen = new Set<string>();
  /** Op paths that a trusted checkpoint contains. A scan does not read these files. */
  private packedPaths = new Set<string>();
  /** Checkpoint path → result of the pack signature check. */
  private cpSigOk = new Map<string, boolean>();
  /** Checkpoint path → its scope, time and the op paths in it (for the statistics only). */
  private checkpointInfo = new Map<string, { scope: string; wallTime: string; paths: string[] }>();
  private pendingCheckpoints: { path: string; cp: Checkpoint }[] = [];
  result: ReplayResult;
  private replayer: Replayer;
  private appliedHashes = new Set<string>();
  private trustRootSig = 'null';
  private keysScanned = new Set<string>();
  /** Counters for tests and the performance report. */
  stats = { fullReplays: 0, incrementalOps: 0 };
  issues: Issue[] = [];
  /** Folders that were missing or not readable in the last full scan. */
  missing: string[] = [];
  /** Scopes found in the last full scan. */
  scopes: string[] = [];
  private now: () => number;

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

  get state() {
    return this.result.state;
  }
  get audit() {
    return this.result.audit;
  }
  get validKeyBindings(): Set<string> {
    return this.keys.validBindings;
  }

  private replayOpts() {
    return { domain: this.domain, trustRoot: this.trustRoot, validKeyBindings: this.keys.validBindings };
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

  async loadTrustRoot(): Promise<void> {
    const t = await this.storage.read(TRUST_ROOT_PATH);
    this.fileIssues.delete(TRUST_ROOT_PATH);
    if (t === null) {
      this.trustRoot = null;
      return;
    }
    try {
      const tr = JSON.parse(t) as TrustRoot;
      if (tr.v !== 1 || !Array.isArray(tr.roots)) throw new Error('bad format');
      this.trustRoot = tr;
    } catch (e) {
      this.trustRoot = null;
      this.fileIssues.set(TRUST_ROOT_PATH, { kind: 'parse-error', path: TRUST_ROOT_PATH, detail: `trust root: ${(e as Error).message}` });
    }
  }

  /**
   * full = list all folders (finds new authors and unknown files).
   * quick = only try the next seq of each known author (cheap, for polling).
   * Returns true if something new was found.
   */
  async scan(mode: 'full' | 'quick' = 'full'): Promise<boolean> {
    const before = this.ops.size;
    const issuesBefore = this.fileIssues.size;
    if (mode === 'full' || !this.trustRoot) await this.loadTrustRoot();
    if (mode === 'quick') {
      for (const { scope, keyId, seq } of this.heads()) await this.readForward(scope, keyId, seq + 1);
    } else {
      const found = await this.domain.discoverScopes(this.storage);
      this.missing = found.missing;
      this.scopes = found.scopes;
      for (const u of found.unknown) this.unknown(u.path, u.detail);
      for (const scope of found.scopes) await this.scanScope(scope);
    }
    if (this.ops.size !== before || this.fileIssues.size !== issuesBefore || mode === 'full') {
      await this.recompute();
      return this.ops.size !== before;
    }
    return false;
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
        // A conflict copy "<seq>-<suffix>.json" can hold a second op with the same seq: a fork.
        const m = /^(\d{10})-.+\.json$/.exec(f.name);
        if (kind === 'ops' && f.kind === 'file' && m && !this.forkCandidates.has(p)) {
          const text = await this.storage.read(p);
          const r = text === null ? null : await parseOpFile(`${dir}/${a.name}/${m[1]}.json`, text, this.domain);
          if (r && 'env' in r) this.forkCandidates.set(p, { env: r.env, hash: r.hash, source: 'file' });
        }
      }
      for (const name of names) {
        if (!OP_FILE_RE.test(name)) continue;
        const path = `${dir}/${a.name}/${name}`;
        if (kind === 'ops') {
          if (!this.ops.has(path)) await this.readOp(path);
        } else if (!this.checkpointsSeen.has(path)) await this.readCheckpoint(path);
      }
    }
  }

  private async readForward(scope: string, keyId: string, seq: number): Promise<void> {
    for (let s = seq; ; s++) {
      const path = this.path(scope, 'ops', keyId, s);
      if (this.ops.has(path)) continue;
      if (!(await this.readOp(path))) return;
    }
  }

  /** Returns false if the file does not exist. */
  private async readOp(path: string): Promise<boolean> {
    const text = await this.storage.read(path);
    if (text === null) return false;
    const r = await parseOpFile(path, text, this.domain);
    if ('env' in r) {
      this.fileIssues.delete(path);
      this.setOp(path, { env: r.env, hash: r.hash, source: 'file' });
    } else this.fileIssues.set(path, r);
    return true;
  }

  private async readCheckpoint(path: string): Promise<void> {
    const text = await this.storage.read(path);
    if (text === null) return;
    this.checkpointsSeen.add(path);
    const pp = parsePath(path, (d) => this.domain.scopeFromDir(d));
    let cp: Checkpoint;
    try {
      cp = JSON.parse(text);
      if (cp?.v !== 1 || !Array.isArray(cp.ops) || !pp || cp.scope !== pp.scope || cp.authorKeyId !== pp.keyId || cp.seq !== pp.seq || typeof cp.wallTime !== 'string' || typeof cp.sig !== 'string') throw new Error('bad format');
    } catch (e) {
      this.fileIssues.set(path, { kind: 'bad-checkpoint', path, detail: (e as Error).message });
      return;
    }
    const paths: string[] = [];
    for (const env of cp.ops)
      if (env?.scope === cp.scope && typeof env.authorKeyId === 'string' && KEY_ID_RE.test(env.authorKeyId) && Number.isSafeInteger(env.seq) && env.seq >= 1)
        paths.push(this.path(env.scope, 'ops', env.authorKeyId, env.seq));
    this.checkpointInfo.set(path, { scope: cp.scope, wallTime: cp.wallTime, paths });
    this.pendingCheckpoints.push({ path, cp });
    // Use the ops of a pack only if an admin signed it (known now). Else the scan reads the op files:
    // a pack that nobody can check must not hide or replace real files.
    if (!(await this.packTrusted(cp))) return;
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

  /** True if the pack signature is valid and its author is an admin (in the current state or in the trust root). */
  private async packTrusted(cp: Checkpoint): Promise<boolean> {
    await this.keys.addFromTrustRoot(this.trustRoot);
    const k = this.keys.get(cp.authorKeyId);
    if (!k) return false;
    let ok = this.cpSigOk.get(this.cpPath(cp)!);
    if (ok === undefined) {
      const { sig, ...rest } = cp;
      try {
        ok = await verifyBytes(k, sig, utf8(canonicalize(rest)));
      } catch {
        ok = false;
      }
      this.cpSigOk.set(this.cpPath(cp)!, ok);
    }
    if (!ok) return false;
    return this.isAdminKey(this.state, cp.authorKeyId) || this.isAdminKey(this.domain.rootState(this.trustRoot), cp.authorKeyId);
  }

  private cpPath(cp: Checkpoint): string | null {
    const dir = this.domain.scopeDir(cp.scope);
    return dir === null ? null : filePath(dir, 'checkpoints', cp.authorKeyId, cp.seq);
  }

  private isAdminKey(state: ReplayResult['state'], keyId: string): boolean {
    try {
      const owner = this.domain.keyOwner(state, keyId);
      return owner !== null && this.domain.isAdmin(state, owner);
    } catch {
      return false;
    }
  }

  /**
   * Forgets all cached files and reads and verifies everything again.
   * A client never reads a known file again during normal scans. So a file that
   * someone changed or deleted after the first read is only found by this full check.
   */
  async reverifyAll(): Promise<void> {
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
    this.checkpointInfo.clear();
    this.pendingCheckpoints = [];
    await this.scan('full');
  }

  // ---- Verify + replay ---------------------------------------------------------------------

  async recompute(): Promise<void> {
    await this.keys.addFromTrustRoot(this.trustRoot);
    const newEnvs: Envelope[] = [];
    for (const o of this.ops.values()) if (!this.keysScanned.has(o.hash)) (this.keysScanned.add(o.hash), newEnvs.push(o.env));
    for (const o of this.forkCandidates.values()) if (!this.keysScanned.has(o.hash)) (this.keysScanned.add(o.hash), newEnvs.push(o.env));
    await this.keys.addFromOps(newEnvs, this.domain);
    // An op from a pack with a bad signature must not hide the real file: drop it and read the file.
    const dropped: string[] = [];
    for (const [path, o] of this.ops) {
      if (o.source !== 'checkpoint' || this.sigStatus.get(o.hash) === 'ok' || !this.keys.get(o.env.authorKeyId)) continue;
      const s = await verifySignature(o.env, this.keys);
      this.sigStatus.set(o.hash, s);
      if (s === 'bad') dropped.push(path);
    }
    if (dropped.length) {
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
    const entries: ChainInput[] = [];
    for (const [path, o] of this.ops) {
      let s = this.sigStatus.get(o.hash);
      if (s !== 'ok' && s !== 'bad') {
        s = await verifySignature(o.env, this.keys);
        if (s !== 'unknown-key') this.sigStatus.set(o.hash, s);
      }
      entries.push({ path, env: o.env, hash: o.hash, sig: s });
    }
    for (const [path, o] of this.forkCandidates) {
      let s = this.sigStatus.get(o.hash);
      if (s !== 'ok' && s !== 'bad') s = await verifySignature(o.env, this.keys);
      // Only a validly signed second op is a fork. A broken copy is only an unknown file.
      if (s === 'ok') entries.push({ path, env: o.env, hash: o.hash, sig: s });
    }
    const chains = checkChains(entries);
    // Incremental apply if it gives the same result as a full replay: same trust
    // root, no op became invalid, no new revocation, and all new ops sort after
    // the last applied op. Otherwise: full replay (always correct).
    const trSig = canonicalize(this.trustRoot);
    const fresh = sortOps(chains.valid.filter((v) => !this.appliedHashes.has(v.hash)));
    const last = this.replayer.last;
    const incremental =
      this.appliedHashes.size > 0 &&
      trSig === this.trustRootSig &&
      chains.valid.length - fresh.length === this.appliedHashes.size &&
      fresh.every((v) => !hasRevocation(v.env, this.domain)) &&
      (fresh.length === 0 || last === null || orderKey(fresh[0].env, last) > 0);
    if (incremental) {
      for (const v of fresh) {
        this.replayer.apply(v);
        this.appliedHashes.add(v.hash);
      }
      this.stats.incrementalOps += fresh.length;
    } else {
      this.replayer = replayFull(chains.valid, this.replayOpts());
      this.appliedHashes = new Set(chains.valid.map((v) => v.hash));
      this.trustRootSig = trSig;
      this.stats.fullReplays++;
    }
    this.result = this.replayer.result();
    for (const v of chains.valid) this.clock.observe(v.env.hlc);

    const issues: Issue[] = [...this.fileIssues.values(), ...chains.issues, ...this.result.issues];
    // Local future-clock check: the wall time of the op is far after the time of this computer.
    const now = this.now();
    for (const o of this.ops.values()) {
      const wall = isIso(o.env.wallTime) ? Date.parse(o.env.wallTime) : NaN;
      if (Number.isFinite(wall) && wall - now > FUTURE_CLOCK_MS)
        issues.push({ kind: 'future-clock', opId: o.env.opId, scope: o.env.scope, authorKeyId: o.env.authorKeyId, seq: o.env.seq, detail: 'the wall time of the op is in the future of this computer' });
    }
    for (const { path, cp } of this.pendingCheckpoints) {
      // The pack signature is checked 1 time for each file (the result cannot change once the key is known).
      let ok = this.cpSigOk.get(path);
      if (ok === undefined) {
        const k = this.keys.get(cp.authorKeyId);
        const { sig, ...rest } = cp;
        try {
          ok = k ? await verifyBytes(k, sig, utf8(canonicalize(rest))) : undefined;
        } catch {
          ok = false;
        }
        if (ok !== undefined) this.cpSigOk.set(path, ok);
      }
      const isAdmin = this.isAdminKey(this.state, cp.authorKeyId);
      if (!ok || !isAdmin) issues.push({ kind: 'bad-checkpoint', path, detail: !ok ? 'checkpoint signature is not valid (or the key is unknown)' : 'checkpoint author is not an admin' });
    }
    this.issues = issues;
  }

  /** Highest known (scope, author, seq) for each chain. */
  heads(): { scope: string; keyId: string; seq: number; hash: string }[] {
    return [...this.heads_.values()];
  }

  // ---- Write ---------------------------------------------------------------------------------

  private nextSeq(scope: string, keyId: string): number {
    return (this.heads_.get(`${scope}|${keyId}`)?.seq ?? 0) + 1;
  }

  /**
   * Applies an op as if it were the next op of this key, and undoes it.
   * Returns the audit entry: status applied, no-effect, superseded or rejected.
   */
  check(keyId: string, scope: string, type: string, payload: Record<string, unknown>): AuditEntry {
    const hlc = this.clock.peek();
    const env: Envelope = {
      v: 1,
      opId: `check-${hlc.t}-${hlc.c}`,
      scope,
      authorKeyId: keyId,
      seq: this.nextSeq(scope, keyId),
      prevHash: null,
      hlc: { t: Math.max(hlc.t, Math.floor(this.now())), c: hlc.c + 1 },
      wallTime: new Date(this.now()).toISOString(),
      type,
      payload,
      sig: '',
    };
    return this.replayer.probe(env);
  }

  /**
   * Signs and writes 1 op. Checks it first with the same code as the replay.
   * Throws AuthError if the op is rejected, and SupersededError if it would have
   * no effect because of the current state (unless allowSuperseded is true).
   */
  async write(signer: Signer, scope: string, type: string, payload: Record<string, unknown>, opts: { allowSuperseded?: boolean } = {}): Promise<Envelope> {
    const r = this.check(signer.keyId, scope, type, payload);
    if (r.status === 'rejected') throw new AuthError(r.reason ?? 'rejected');
    if (r.status === 'superseded' && !opts.allowSuperseded) throw new SupersededError(r.reason ?? 'superseded');
    for (let attempt = 0; attempt < 3; attempt++) {
      if (attempt > 0) {
        // The seq was taken (for example by the same key in another tab or PC): read the files of this author.
        const dir = `${this.domain.scopeDir(scope)}/ops/${signer.keyId}`;
        for (const f of (await this.storage.list(dir)) ?? []) {
          const p = `${dir}/${f.name}`;
          if (OP_FILE_RE.test(f.name) && !this.ops.has(p)) await this.readOp(p);
        }
      }
      const seq = this.nextSeq(scope, signer.keyId);
      let prevHash: string | null = null;
      if (seq > 1) {
        const prev = this.ops.get(this.path(scope, 'ops', signer.keyId, seq - 1));
        if (!prev) throw new Error(`own op ${seq - 1} in ${scope} is not readable. Ask an admin.`);
        prevHash = prev.hash;
      }
      // The clock observed the valid ops in recompute(). Also observe the own last op, so that the chain HLC increases.
      if (seq > 1) this.clock.observe(this.ops.get(this.path(scope, 'ops', signer.keyId, seq - 1))!.env.hlc);
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
      const env = await signEnvelope(u, (b) => signer.sign(b));
      const path = this.path(scope, 'ops', signer.keyId, seq);
      // Check the envelope BEFORE the write: an invalid file would stay forever and block this seq.
      const c = await checkEnvelope(env, path, this.domain);
      if (!('env' in c)) throw new Error(`internal: the new op is invalid: ${c.detail}`);
      try {
        await this.storage.writeNew(path, canonicalize(env));
      } catch (e) {
        if (e instanceof FileExistsError) continue; // another tab or PC with the same key wrote this seq: re-read and retry
        throw e;
      }
      this.setOp(path, { env, hash: c.hash, source: 'local' });
      this.sigStatus.set(c.hash, 'ok');
      await this.recompute();
      return env;
    }
    throw new Error('could not allocate a sequence number (3 attempts)');
  }

  // ---- Checkpoints ----------------------------------------------------------------------------

  /** Writes a pack of all valid ops of a scope (admins only). */
  async createCheckpoint(signer: Signer, scope: string): Promise<string> {
    const owner = this.domain.keyOwner(this.state, signer.keyId);
    if (owner === null || !this.domain.isAdmin(this.state, owner)) throw new AuthError('only an admin can write a checkpoint');
    const valid = this.result.audit.filter((a) => a.scope === scope).map((a) => a.hash);
    const byHash = new Map([...this.ops.values()].map((o) => [o.hash, o.env]));
    const ops = valid.map((h) => byHash.get(h)!).filter(Boolean);
    const frontier: Checkpoint['frontier'] = {};
    for (const h of this.heads()) if (h.scope === scope) frontier[h.keyId] = { seq: h.seq, hash: h.hash };
    const dir = `${this.domain.scopeDir(scope)}/checkpoints/${signer.keyId}`;
    const existing = ((await this.storage.list(dir)) ?? []).map((f) => OP_FILE_RE.exec(f.name)).filter((m) => m !== null);
    const seq = existing.reduce((mx, m) => Math.max(mx, Number(m![1])), 0) + 1;
    const rest: Omit<Checkpoint, 'sig'> = { v: 1, scope, authorKeyId: signer.keyId, seq, hlc: this.clock.tick(), wallTime: new Date(this.now()).toISOString(), frontier, ops };
    const cp: Checkpoint = { ...rest, sig: await signer.sign(utf8(canonicalize(rest))) };
    const path = this.path(scope, 'checkpoints', signer.keyId, seq);
    await this.storage.writeNew(path, canonicalize(cp));
    this.checkpointsSeen.add(path);
    // Check the own checkpoint like any other (signature, author is admin) in the next recompute.
    this.pendingCheckpoints.push({ path, cp });
    this.checkpointInfo.set(path, { scope, wallTime: rest.wallTime, paths: ops.map((env) => this.path(env.scope, 'ops', env.authorKeyId, env.seq)) });
    await this.recompute();
    return path;
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
      if (!x || bad.has(path)) continue;
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
      v: 2,
      ops: [...this.ops].map(([path, o]) => ({ path, env: o.env, hash: o.hash, source: o.source === 'checkpoint' ? 'checkpoint' : 'file' })),
      sigOk: [...this.sigStatus].filter(([, s]) => s === 'ok').map(([h]) => h),
    };
  }

  /** Restores a cache. The cache must come from a trusted, integrity-protected store. */
  async importCache(c: EngineCache): Promise<void> {
    if (c?.v !== 2) return;
    for (const o of c.ops)
      if (!this.ops.has(o.path)) {
        const source = o.source === 'checkpoint' ? 'checkpoint' : 'file';
        this.setOp(o.path, { env: o.env, hash: o.hash, source });
        if (source === 'checkpoint') this.packedPaths.add(o.path);
      }
    for (const h of c.sigOk) this.sigStatus.set(h, 'ok');
    await this.loadTrustRoot();
    await this.recompute();
  }

  /** All known op envelopes (for tests and tools). */
  knownOps(): Envelope[] {
    return [...this.ops.values()].map((o) => o.env);
  }
}

export const maxHlc = (envs: Envelope[]): Hlc => envs.reduce<Hlc>((m, e) => (compareHlc(e.hlc, m) > 0 ? e.hlc : m), { t: 0, c: 0 });
