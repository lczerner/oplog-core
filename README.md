# oplog-core

A library for apps that keep their data as a log of signed, immutable JSON op files in a shared folder (for example a synced OneDrive folder). There is no server. Each client reads all op files, checks them and replays them in 1 deterministic order.

Users: `mytasker` ("Úkoly") and other apps of the owner. Each app links oplog-core as `file:../oplog-core` and pins a commit in its `.oplog-core-ref`.

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

Optional hooks. If a domain does not give them, the replay works as before.

- `scopeKind(scope)`: the kind of a scope that the app makes at run time (for example `team` for the scope `team:a1`). If it is given, the replay compares `OpDef.scopes` with `scopeKind(scope)` of the op. If it is not given, the replay compares `OpDef.scopes` with the scope itself. An error rejects the op.
- `EffectCtx.revertTarget`: for a Revert, `authorize` (and the later domain functions of the Revert) get a read-only copy of the target op (`RevertTarget`: op ID, hash, scope, type, item types, user, writes). The copy is frozen but shallow: the values `v` and `before` of the writes are the same objects as in the state, and the domain must not change them. For example, `authorize` can let a user revert only own ops. The field is undefined if the target is not an applied op before the Revert, with the same hash, in the same scope. Then the replay rejects the Revert after `authorize`. `Engine.check()` and `planRevert()` give the same field.
- `code` in a superseded result (`Superseded`: `{ superseded, code? }`) of `effects`, `checkState` and `removeWrites`: a machine-readable kind for the app, for example for a list of one kind of superseded change. The replay copies it to `ItemNote.code`, and to `AuditEntry.code` for a superseded op that is not a Batch. `Engine.write()` puts it in `SupersededError.code`. The core gives it no meaning. `checkState` can also return a text, as before (no code).

## Replay rules

1. Keys: the key must be known at the point of the op (`Domain.keyOwner`), and the `seq` must not be above a revocation cutoff. A cutoff applies to all ops of the key, in any order. If a key has more than 1 cutoff, the lowest applies. A scope that a cutoff does not list has the cutoff 0.
2. Each item (a plain op, or each item of a `Batch`) is validated against its schema and authorized against the state after the earlier items. A rejected item rejects the full op. An empty `Batch` is rejected (`invalid-payload`), because it would skip `authorize`.
3. `effects()` returns writes, `noEffect` or `superseded` (with an optional `code`). A superseded item has no effect. The other items of a Batch apply.
4. After the writes of an item: `normalize` (derived writes), then `checkState`. If `checkState` fails, the writes of the item are undone and the item is superseded.
5. Ops cannot change entities with `root: true` (from the trust root).
6. `Revert`: `authorize` runs first (with `ctx.revertTarget`). Then the target must be an applied op in the same scope, before the Revert. The replay computes the inverse itself (the `before` values, and `Domain.removeWrites` for created entities). The payload must contain the same inverse, without the computed fields.
7. A field for which `Domain.isDerived` is true is not part of a Revert inverse. `normalize` computes it again.
8. Errors in domain code:
   - During the replay of an op: only that op is rejected (issue kind `domain`).
   - In `keysIn`: that item is ignored.
   - In `isRevocation`: the engine does a full replay.
   - In `keyOwner` or `isAdmin` during the checkpoint check: the pack is not trusted, and the engine reads the op files.
   - In `revocations`: the fixpoint stops with the cutoffs that it has, and an issue of kind `domain` shows it. This fails open: ops of revoked keys can apply. A domain must never throw in `revocations`.
9. Audit status of an op: `applied`, `no-effect`, `superseded` or `rejected`. Only rejected ops are integrity issues.

## Checkpoints

A checkpoint is a signed pack of the original ops. The engine uses the ops of a pack only if the pack signature is valid and its author is an admin whose key is not revoked (in the state or in the trust root). Else the engine reads the op files. An op of a trusted pack with a bad signature is dropped, the engine reads the file, and a `bad-checkpoint` issue shows it. Thus a pack can never hide or replace a valid op file. Limit: only a client that reads the bad pack op before the op file shows this issue, and only until it restarts. The replay result is the same on all clients.

A full scan reads the scopes in the order of `Domain.discoverScopes` and replays 1 time after the first scope. Put the scope with the users and admins first: then the packs of the later scopes can be checked against all admins, not only the root admins. Packs of the first scope are trusted only if a root admin signed them. `checkpointStats` counts only packs whose ops the engine used.

## Storage

Paths are relative to the shared root and use `/`. The adapters refuse empty segments, `.`, `..`, `\`, `:` and a leading `/`. `remove()` is only for content-addressed blobs. The browser adapter uses a Web Lock for each new file, so that 2 tabs cannot write the same file at the same time.

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
