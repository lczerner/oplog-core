# AGENTS.md – instructions for coding agents

`oplog-core` is the shared, security-critical core of serverless op-log apps. Read `README.md` first.

## Invariants (never break)

1. Op files are immutable. `Storage.writeNew()` and `writeNewBytes()` fail if the file exists. `Storage.remove()` is only for content-addressed blobs after an admin purge in an app.
2. The replay is deterministic: the same set of ops gives the same state, in any input order and partition. No `Date.now()`, randomness, locale or iteration-order dependence in `verify`, `replay` or the `Domain` functions.
3. `Domain.authorize()` is the only permission gate. The replay checks every op.
4. No DOM access and no network access. The code runs in the browser and in Node 22.
5. The op format (envelope, JCS, paths, chain rules) does not change without a new format version and the owner's approval.

## Rules

- No domain code here. If an app needs a new hook, add it to `Domain` with a test in `test/notes-domain.ts`.
- Each change has tests. `test/property/convergence.test.ts` must pass.
- Docs, comments and commit messages: English in Simplified Technical English style.
- Default branch: `master`. No remote yet: commit on `master`, do not push.
- Before each commit: `npm run typecheck`, `npm test`, then an independent expert review (in Claude Code: a subagent with a model at least as strong as the author's). Fix the findings first.
