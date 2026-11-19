# oplog-core

A library for apps that keep their data as a log of signed, immutable JSON op files in a shared folder (for example a synced OneDrive folder). There is no server. Each client reads all op files, checks them and replays them in 1 deterministic order.

Users: `mytasker` ("Úkoly"). `system-vzdelavani` has the same core in its own repository and will migrate later.

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
| `storage` | `Storage` interface. Adapters: File System Access (browser), memory, Node fs (`oplog-core/node-fs`) |

## Folder layout

```text
<scopeDir>/ops/<keyId>/<seq 10 digits>.json
<scopeDir>/checkpoints/<keyId>/<seq 10 digits>.json
app/trust-root.json
```

The domain maps each scope to its folder (`Domain.scopeDir`).

## Op envelope

```json
{ "v": 1, "opId": "…", "scope": "…", "authorKeyId": "k…", "seq": 1, "prevHash": null,
  "hlc": { "t": 0, "c": 0 }, "wallTime": "…", "type": "…", "payload": {}, "sig": "…" }
```

- `sig`: Ed25519 over the JCS of the envelope without `sig`.
- `prevHash`: `sha256:<hex>` of the JCS of the previous op of the same author and scope.
- Total order: `(hlc.t, hlc.c, authorKeyId, seq, scope)`.
- `hlc.t` is at most 253 402 300 799 999 (the year 9999) and `hlc.c` is at most 2 147 483 647. Larger values make the op invalid. The HLC must increase along the chain of an author.
- `sig` must be the canonical base64url text (unused bits are 0). Thus 1 signature has only 1 text.

## The Domain

An app gives a `Domain` object (`src/domain.ts`): the scopes and their folders, the op catalogue (schema and `effects()` for each op type), `authorize()`, the initial state from the trust root, the owner of a key, the keys that an op registers, the revocation cutoffs, derived writes (`normalize`), state checks (`checkState`) and the remove writes for a Revert. All domain functions must be pure and deterministic.

## Replay rules

1. Keys: the key must be known at the point of the op (`Domain.keyOwner`), and the `seq` must not be above a revocation cutoff. A cutoff applies to all ops of the key, in any order. If a key has more than 1 cutoff, the lowest applies. A scope that a cutoff does not list has the cutoff 0.
2. Each item (a plain op, or each item of a `Batch`) is validated against its schema and authorized against the state after the earlier items. A rejected item rejects the full op.
3. `effects()` returns writes, `noEffect` or `superseded`. A superseded item has no effect. The other items of a Batch apply.
4. After the writes of an item: `normalize` (derived writes), then `checkState`. If `checkState` fails, the writes of the item are undone and the item is superseded.
5. Ops cannot change entities with `root: true` (from the trust root).
6. `Revert`: the target must be an applied op in the same scope, before the Revert. The replay computes the inverse itself (the `before` values, and `Domain.removeWrites` for created entities). The payload must contain the same inverse, without the computed fields.
7. A field for which `Domain.isDerived` is true is not part of a Revert inverse. `normalize` computes it again.
8. Errors in domain code:
   - During the replay of an op: only that op is rejected (issue kind `domain`).
   - In `keysIn`: that item is ignored.
   - In `isRevocation`: the engine does a full replay.
   - In `keyOwner` or `isAdmin` during the checkpoint check: the pack is not trusted, and the engine reads the op files.
   - In `revocations`: the fixpoint stops with the cutoffs that it has, and an issue of kind `domain` shows it. This fails open: ops of revoked keys can apply. A domain must never throw in `revocations`.
9. Audit status of an op: `applied`, `no-effect`, `superseded` or `rejected`. Only rejected ops are integrity issues.

## Checkpoints

A checkpoint is a signed pack of the original ops. The engine uses the ops of a pack only if the pack signature is valid and its author is an admin (in the state or in the trust root). Else the engine reads the op files. An op of a trusted pack with a bad signature is dropped, and the engine reads the file. Thus a pack can never hide or replace a valid op file.

## Storage

Paths are relative to the shared root and use `/`. The adapters refuse empty segments, `.`, `..`, `\`, `:` and a leading `/`. `remove()` is only for content-addressed blobs. The browser adapter uses a Web Lock for each new file, so that 2 tabs cannot write the same file at the same time.

## Commands

```sh
npm install
npm test
npm run typecheck
```

## Use from an app

No package registry is used. The app depends on a local checkout or a git commit:

```json
"dependencies": { "oplog-core": "file:../oplog-core" }
```

Import from `oplog-core` in browser code and from `oplog-core/node-fs` in Node code only.
