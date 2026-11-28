# oplog-core

A library for apps that keep their data as a log of signed, immutable JSON op files in a shared folder (for example a synced OneDrive folder). There is no server. Each client reads all op files, checks them and replays them in 1 deterministic order.

Users: `mytasker` (Tasks) and other apps of the owner. Each app links oplog-core as `file:../oplog-core` and pins a commit in its `.oplog-core-ref`.

## What the library does

| Module | Content |
|---|---|
| `canonical` | RFC 8785 (JCS) canonical JSON |
| `crypto` | SHA-256, Ed25519 keys and signatures, key file wrapped with a passphrase (PBKDF2-SHA256 600 000, AES-256-GCM), AES-GCM for a local cache |
| `hlc` | Hybrid logical clock |
| `verify` | Op file parsing, path check, signatures, hash chains (gaps, forks, broken chains, HLC that does not increase) |
| `replay` | Deterministic replay with an app `Domain`: authorize, effects, Batch, Revert, revocation fixpoint, derived writes, state checks |
| `revert` | Revert planning for the UI |
| `engine` | Scan, incremental or full replay, write with a check, checkpoints, cache |
| `enrollment` | Access requests `enroll/<name>-<keyIdShort>.json`: public key, name, ISO time, self-signature. The self-signature proves only that the requester has the key, not the name: an admin must compare the fingerprint out of band. |
| `storage` | `Storage` interface. Adapters: File System Access (browser), memory, Node fs (`oplog-core/node-fs`) |

## Folder layout

```text
<scopeDir>/ops/<keyId>/<seq 10 digits>.json
<scopeDir>/checkpoints/<keyId>/<seq 10 digits>.json
app/trust-root.json
enroll/<name>-<keyIdShort>.json
```

The domain maps each scope to its folder (`Domain.scopeDir`).

## Op envelope

```json
{ "v": 1, "opId": "…", "scope": "…", "authorKeyId": "k…", "seq": 1, "prevHash": null,
  "hlc": { "t": 0, "c": 0 }, "wallTime": "…", "type": "…", "payload": {}, "sig": "…" }
```

- `sig`: Ed25519 over the JCS of the envelope without `sig`.
- `prevHash`: `sha256:<hex>` of the JCS of the previous valid op of the same author and scope.
- Chain (format 2): only validly signed ops of the author are chain members. Other files in the author folder are issues, and the chain skips them. The chain follows the `prevHash` links. `seq` must increase but can have gaps. An op whose previous op is missing waits (`chain-gap`). 2 valid ops with the same `seq` or the same `prevHash` are a fork. The writer takes the smallest free number above its own last valid op. Thus a NEW file of another person under the next number cannot block an author. Limit: a person who changes or deletes an EXISTING op file of an author stops that chain at the next op (`chain-gap`) until somebody restores the file (for example from the OneDrive version history or recycle bin). An author can also stop the own chain with a second signed op after an old own op (a fork).
- Total order: `(hlc.t, hlc.c, authorKeyId, seq, scope)`.
- `hlc.t` is at most 253 402 300 799 999 (the year 9999) and `hlc.c` is at most 2 147 483 647. Larger values make the op invalid. The HLC must increase along the chain of an author.
- `sig` must be the canonical base64url text (unused bits are 0). Thus 1 signature has only 1 text.

## The Domain

An app gives a `Domain` object (`src/domain.ts`): the scopes and their folders, the op catalogue (schema and `effects()` for each op type), `authorize()`, the initial state from the trust root, the owner of a key, the keys that an op registers, the revocation cutoffs, derived writes (`normalize`), state checks (`checkState`) and the remove writes for a Revert. All domain functions must be pure and deterministic.

`keysIn`: a domain must not register more than `MAX_BATCH` (500) keys in 1 op. Else the replay result is not defined: a later key is valid only if another file registers it.

Optional hooks. If a domain does not give them, the replay works as before.

- `scopeKind(scope)`: the kind of a scope that the app makes at run time (for example `team` for the scope `team:a1`). If it is given, the replay compares `OpDef.scopes` with `scopeKind(scope)` of the op. If it is not given, the replay compares `OpDef.scopes` with the scope itself. An error rejects the op.
- `EffectCtx.revertTarget`: for a Revert, `authorize` (and the later domain functions of the Revert) get a read-only copy of the target op (`RevertTarget`: op ID, hash, scope, type, item types, user, writes). The copy is frozen but shallow: the values `v` and `before` of the writes are the same objects as in the state, and the domain must not change them. For example, `authorize` can let a user revert only own ops. The field is undefined if the target is not an applied op before the Revert, with the same hash and opId, in the same scope. Then the replay rejects the Revert after `authorize`. `Engine.check()` and `planRevert()` give the same field.
- `code` in a superseded result (`Superseded`: `{ superseded, code? }`) of `effects`, `checkState` and `removeWrites`: a machine-readable kind for the app, for example for a list of one kind of superseded change. The replay copies it to `ItemNote.code`, and to `AuditEntry.code` for a superseded op that is not a Batch. `Engine.write()` puts it in `SupersededError.code`. The core gives it no meaning. `checkState` can also return a text, as before (no code).

## Replay rules

1. Keys: the key must be known at the point of the op (`Domain.keyOwner` returns a string), and the `seq` must not be above a revocation cutoff. A cutoff applies to all ops of the key, in any order. If a key has more than 1 cutoff, the lowest applies. A scope that a cutoff does not list has the cutoff 0.
2. opId: an opId is unique only for 1 author key. If an author key uses an opId again, also in another scope, the replay rejects the later op (`duplicate opId`). Rejected ops also count. 2 different author keys can use the same opId. Thus an author cannot cancel the op of another author with a copied opId. `ReplayResult.applied` uses the op hash as the key.
3. Each item (a plain op, or each item of a `Batch`) is validated against its schema and authorized against the state after the earlier items. A rejected item rejects the full op. An empty `Batch` is rejected (`invalid-payload`), because it would skip `authorize`.
4. `effects()` returns writes, `noEffect` or `superseded` (with an optional `code`). A superseded item has no effect. The other items of a Batch apply.
5. After the writes of an item: `normalize` (derived writes), then `checkState`. If `checkState` fails, the writes of the item are undone and the item is superseded.
6. Ops cannot change entities with `root: true` (from the trust root).
7. `Revert`: `authorize` runs first (with `ctx.revertTarget`). The replay finds the target by `payload.target.hash`. The target must be an applied op in the same scope, before the Revert, and its opId must be `payload.target.opId`. The replay computes the inverse itself (the `before` values, and `Domain.removeWrites` for created entities). The payload must contain the same inverse, without the computed fields. `planRevert(result, { opId, hash }, …)` takes the opId and the hash of the target (an `AuditEntry` fits). `AuditEntry.revertOf` and `AuditEntry.revertOfHash` name the target.
8. A field for which `Domain.isDerived` is true is not part of a Revert inverse. `normalize` computes it again.
9. Errors in domain code:
   - During the replay of an op: only that op is rejected (issue kind `domain`).
   - In `keysIn`: that item is ignored.
   - In `isRevocation`: the engine does a full replay.
   - In `keyOwner` or `isAdmin` during the checkpoint check: the pack is not trusted, and the engine reads the op files.
   - In `revocations`: the fixpoint stops with the cutoffs that it has, and an issue of kind `domain` shows it. This fails open: ops of revoked keys can apply. A domain must never throw in `revocations`.
10. Future clock: the replay reports an op whose HLC is more than 1 hour after its own wall time and after the HLCs of the earlier ops that count (issue kind `future-clock`). These ops count: ops that the replay did not reject, and ops that the replay rejected only because of a revocation cutoff. Before the revocation, honest clients applied such an op and copied its HLC. Other rejected ops do not count, for example an op of a key that nobody granted. The engine clock is stricter: it copies only the HLCs of ops that the replay did not reject and whose HLC is at most 1 hour after the time of this computer. Limit: a key that an admin revoked can still hide the future clock of later ops of other keys. Its own first far-future op is still reported.
11. Audit status of an op: `applied`, `no-effect`, `superseded` or `rejected`. Only rejected ops are integrity issues.

## Keys, signatures and validation

- Ed25519: before WebCrypto, the library checks keys and signatures with deterministic BigInt code, so that all clients accept the same data.
  - Key registration (`KeyMap.add`, from the trust root and from the ops) does only cheap checks: base64url, 32 bytes, a canonical y (y < p), not a small-order point, and keyId = hash of the key. `KeyMap` reads at most `MAX_BATCH` items and at most `MAX_BATCH` keys of each op, in a fixed order. Thus 1 op cannot cost much CPU time.
  - The full check (a point on the curve in the prime-order subgroup, `[L]A = identity`, about 1 ms) runs lazily, 1 time for each public key. It runs before WebCrypto uses a key for a signature (at most 1 time for each author key that has an op file or a checkpoint file), and when the domain asks `isValidKeyBinding`. A domain must ask it only after `authorize` accepted the item. At most `MAX_BATCH` keys of each op count, in the order of the items. A domain must not register more keys in 1 op (see The Domain). `validKeyBindings` is a `KeyBindings` object with `isValid(keyId, publicKey)`. `NO_KEY_BINDINGS` is always false.
  - A signature must have 64 bytes, a canonical R that is not small-order, and S < L.
  - The signature status of an op or a checkpoint is `unknown-key` if no binding exists, and `bad` if the key fails the full check, if the signature fails the form check, or if WebCrypto rejects the key or the signature. Else it is `ok`. Other errors (for example of the environment) go to the caller.
  - Residual risk: R is checked only for form. A key owner can make a signature with a mixed-order R that cofactored and cofactorless verifiers treat differently. The current browser and Node implementations are cofactorless.
- URL field (`{ url: [...] }`): the replay checks a URL without the `URL` class, because URL parsers and IDNA tables differ between engines. The URL must not contain a control character, a bidirectional format character or white space. The scheme must be in the list (ASCII case-insensitive). For http, https, ws, wss and ftp, the URL needs a non-empty host after 0 or more `/` or `\`. The URL can have userinfo, an IPv6 host in `[...]` and a port of 65535 or less. For `file:` and the other schemes, there are no more rules (also `mailto:` alone is valid). The check accepts a superset of WHATWG URLs, also Unicode hosts and paths, and `\` in the query, the fragment and the path. It does not normalize the URL. Its time is linear.
- Key file: the KDF must be PBKDF2 with SHA-256, 100 000 to 10 000 000 iterations, and a salt of 16 to 256 bytes. `wrap.name` must be `AES-GCM`. The public key must be acceptable, and `keyId` must match it. Else `unwrapSigningKey` throws `unsupported key file` before the slow key derivation. `wrapSigningKey` throws `RangeError` for an iteration count out of range or an invalid display name. The default is 600 000 iterations.
- Display name (key file and enrollment): a display name must have 1 to 200 characters and no control or bidirectional format characters. It must have at least 1 character that is not white space or invisible. Fixed lists define these characters, also some invisible characters outside the BMP (tags, variation selectors supplement, musical and shorthand format controls). Thus the result does not depend on the Unicode version (`isValidDisplayName`). `createEnrollment` throws for an invalid name, and `verifyEnrollment` refuses it. `listEnrollments` does not read a file larger than 64 KiB (`MAX_ENROLLMENT_BYTES`), and such a file is an invalid entry.

## Engine

- Trust root: the engine checks the structure of `app/trust-root.json`. `v` is 1, and each root has `userId` (an ID), `keyId`, `alg` `Ed25519`, `publicKey`, `displayName` and `cutoffs` (null, or an object of scope → non-negative integer). Each `keyId` must be in the trust root only 1 time, because a second entry could change the user or the cutoff of the key. A user can have more than 1 key. If the file is missing, not readable, larger than 1 MiB or not valid, the engine uses the last good copy and shows a `trust-root` issue. If the engine has no last good copy, an invalid file is an issue, and a missing file is an issue if op files exist.
- Known trust root: the engine keeps the first trust root that it read, or the trust root that the app acknowledged. The cache (`EngineCache` v 3) contains it. Call `importCache()` before the first scan: else the engine keeps its own known trust root. The app must store the cache under a key that does not depend on the trust root, and must save the cache again after `acknowledgeTrustRoot()`. If the trust root differs from the known trust root, the engine uses the new trust root and shows a `trust-root` issue. The issue stays until the app calls `acknowledgeTrustRoot(expectedHash)`, also if the file changes back and also after a restart. `Engine.trustRootHash` is the hash of the trust root in use: `sha256:` and 64 lowercase hex characters, the SHA-256 of the JCS of the trust root. Show the fingerprints of the root admins with this hash, and give the same hash to `acknowledgeTrustRoot()`. Compare the fingerprints out of band before the acknowledgment. If the trust root changed again after that, the call throws and changes nothing. Then show the new fingerprints again. `Engine.trustRootChanged` is true while this issue is open. If the trust root changed and then changed back to the known trust root, the issue text says so. `Engine.knownTrustRoot` is the known trust root (a deep-frozen copy), for a UI that shows the old and the new root admins. The engine sets `trustRoot` and `trustRootHash` together. `trustRootError()` (exported) is the validity rule of the engine, also for a trust root that JCS refuses. Use it in an app that writes or shows a trust root.
- `scan()` returns true if the known ops, the trust root or the issue list changed. Then show the state and the issues again.
- Limit: the engine uses a changed trust root at once. It only shows the issue. Until an admin acknowledges it, the state, the checks of `write()` and the trust in checkpoints use the new root admins. The app must show the change clearly (`trustRootChanged`) to admins and to users who wait for approval. Users must not make a new key while the change is open.
- Size limits: the engine does not read an op file larger than 32 MiB (`MAX_OP_FILE_BYTES`), a checkpoint larger than 256 MiB (`MAX_CHECKPOINT_BYTES`) or a trust root larger than 1 MiB (`MAX_TRUST_ROOT_BYTES`). A too-large op file is a `parse-error`, a too-large checkpoint is a `bad-checkpoint`, and a too-large trust root is a `trust-root` issue. The scan continues. `write()` refuses an op whose file would be larger than 32 MiB, because other clients would not read the file, and the chain of the author would stop there for them.
- Clock: the HLC clock of the engine observes only ops that the replay did not reject and whose HLC is at most 1 hour after the time of this computer. Thus a key that nobody granted, or a granted user with a far-future HLC, cannot move the clock of the clients. `write()` also observes the own last op, so that the own chain increases.
- Limit of the clock rule: if the clock of a device is more than 1 hour ahead, the ops of that device are reported as `future-clock` on the other clients (the wall time of the op is in the future of this computer). The other clients do not copy their HLC. Thus a later op of another client can sort before an op that its author saw, and lose the race (for example an edit of a note that the device with the wrong clock created). Fix the clock of the device.
- Check: `Engine.check()` probes with the opId `#probe` (`PROBE_OP_ID`). It is not a valid ID, so no op file can have it. `write()` checks the op again after it reads the new own files, with the seq, HLC and opId of the new file.
- Quick scan: a quick scan reads a known file again only if its issue is `not valid JSON`. Such an issue can come from a partial read of a file that another client still writes. The scan reads at most 16 such files for each author in 1 scan. The engine reads a file that is not valid JSON at most 3 times with the same content. After that, it keeps the issue and reads the file again only after a wait: 5 seconds × 2^n after the last read, at most 10 minutes. A changed content starts the count again. Thus the engine applies a file that syncs slowly when it is complete. If the content of a partial file did not change for 3 reads, the engine applies the file at the latest 10 minutes after it is complete. If the clock of this computer goes back, the wait ends. `reverifyAll()` resets the count of all files. `write()` reads the new files of the own folder (also from another tab or PC). Of the files with a known issue, it reads again only "not valid JSON" files in the 16 numbers above the own last op. These reads do not use the read budget. If the issue of a file changes, the issue list updates. The scan does not read files with other issues again. Op files are immutable: also a full scan does not read a file with a known issue again, except a file that is not valid JSON (with the read budget). This also applies to conflict copies that are not an op. `reverifyAll()` reads all files again.
- Incremental replay: new ops that sort after the last op apply incrementally. If the last ops in the order are rejected ops (for example of a key that nobody granted, with a far-future HLC), the engine takes them back exactly, applies the new ops and then these ops again. The result is the same as a full replay. The rejected ops at the end of the order can contain a revocation op, because a rejected op does not change the state. If such an op applies after the new ops (for example after a new grant), the engine does a full replay. New ops with a revocation always cause a full replay. If a full replay ends with an issue after the last op (`revocations` failed, or the cutoffs did not become stable), the engine does a full replay for each new op. Thus the order of the issues is the same as in a full replay.
- Limit: an applied, superseded or no-effect op of a granted user with a far-future HLC stays after all new ops in the order. Each later recompute then does a full replay, until an admin revokes the key with a cutoff below the seq of that op. The replay reports such an op as `future-clock`.
- All public methods that change the engine (`scan`, `write`, `createCheckpoint`, `recompute`, `loadTrustRoot`, `acknowledgeTrustRoot`, `importCache`, `reverifyAll`) run 1 at a time.

## Checkpoints

A checkpoint is a signed pack of the original ops. The engine uses the ops of a pack only if the pack signature is valid and its author is an admin whose key is not revoked (in the state or in the trust root). Else the engine reads the op files. An op of a trusted pack with a bad signature is dropped, the engine reads the file, and a `bad-checkpoint` issue shows it. Thus a pack can never hide or replace a valid op file. Limit: only a client that reads the bad pack op before the op file shows this issue, and only until it restarts. The replay result is the same on all clients.

A full scan reads the scopes in the order of `Domain.discoverScopes` and replays 1 time after the first scope. Put the scope with the users and admins first: then the packs of the later scopes can be checked against all admins, not only the root admins. Packs of the first scope are trusted only if a root admin signed them. `checkpointStats` counts only packs whose ops the engine used.

The engine checks the signature of a pack when it reads the pack. If the key of the author is not known yet, the engine keeps nothing of the pack. The engine keeps the list of op paths of a pack only if it uses the pack. Thus many large packs of outsiders cannot fill the memory, also if an outsider registers his own key. A later full scan reads the pack again: at once if the key is known then, else after 5 seconds × 2^n from the last read, at most 6 hours (`UNKNOWN_KEY_PACK_MAX_WAIT_MS`). The engine shows a `bad-checkpoint` issue for such a pack only while the key is not known after the scan. Then it uses the pack if its author is an admin. `reverifyAll()` reads all packs again.

A checkpoint takes the next number after the highest own checkpoint (a used pack, or a listed file that is not a known bad checkpoint), and skips numbers in use. The engine refuses a number above 9 999 999 999 and a checkpoint larger than 256 MiB, because other clients do not read it. The engine reads a checkpoint file that is not valid JSON again in the next full scans, with the same limit as an op file: at most 3 reads with the same content, then a read only after the wait (5 seconds × 2^n, at most 10 minutes).

## Storage

Paths are relative to the shared root and use `/`. The adapters refuse empty segments, `.`, `..`, `\`, `:` and a leading `/`. `remove()` is only for content-addressed blobs. The browser adapter uses a Web Lock for each new file, so that 2 tabs cannot write the same file at the same time.

`read()` and `readBytes()` accept `{ maxBytes }`. The value must be a non-negative safe integer, or the adapter throws `RangeError`. If the file is larger, the adapter throws `FileTooLargeError` and does not read the content into memory. A file that does not exist, or a folder at the path, gives null. All adapters decode text as UTF-8 and remove a UTF-8 BOM.

A failed write can leave an empty or partial file. The adapters do not delete it, because a delete by path can remove the op of another writer. For op and checkpoint files, the engine skips such a file and the writer takes the next free number. For a file at a fixed path (trust root, enrollment request, blob `files/<sha256>`), nothing skips the file. A retry then gives `FileExistsError`, but the content can be incomplete. The caller must read the file and check its content. The Node adapter is not atomic for a reader: a reader can see a partial file while the write continues. The engine reads a file with a parse error again in a quick scan.

## Commands

```sh
make install      # npm ci
make check        # typecheck, tests, SBOM with its check
make sbom         # SBOMs in sbom/ (runtime + build, CycloneDX, or SPDX with SBOM_FORMAT=spdx)
make help         # all targets
```

The Git workflow (branches, pull requests, CI, Dependabot) is in `AGENTS.md`.

## Use from an app

No package registry is used. The app depends on a local checkout or a git commit:

```json
"dependencies": { "oplog-core": "file:../oplog-core" }
```

Import from `oplog-core` in browser code and from `oplog-core/node-fs` in Node code only.

## License

MIT. Copyright 2026, Lukáš Czerner <lukas@czerner.cz>. See `LICENSE`.
