# AGENTS.md – instructions for coding agents

`oplog-core` is the shared, security-critical core of serverless op-log apps. Read `README.md` first. `make help` lists the commands.

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
- Stop and ask the owner before you change the op format or the replay rules.

## Git workflow

Remote: `github.com/lczerner/oplog-core` (private). The default branch `master` is protected.

1. **Never commit on `master`, and never push `master`.** All changes come to `master` through a pull request.
2. **Work on a branch.** Start each piece of work on a new branch from the current `origin/master`: `git fetch origin && git switch -c <short-topic> origin/master`. Use 1 branch for 1 topic. If the owner asks for several changes on 1 branch, keep them on that branch.
3. **Before each commit:** `make check` (typecheck, tests, SBOM), then an independent expert review (in Claude Code: a subagent with a model at least as strong as the author's, with no `model` or `effort` override). This rule applies to all changes, also to small changes and to changes of documentation only. Fix the findings first. Run the checks again after the fixes. If a fix changes more than the finding asks for, review again. If you do not fix a finding, tell the owner why, and write it in the commit message.
4. **Commit messages** in Simplified Technical English, with a "Review:" paragraph: what the reviewer found and what you did with each finding.
5. **Push and create the pull request only when the owner says so:** `git push -u origin <branch>`, then `gh pr create --base master` with the summary, the checks, the review result and the attribution line. Watch the CI (`gh pr checks`). If it fails, fix the cause on the same branch and push again (the owner's command for this PR covers the fixes). The owner merges. Never merge, close or force-push without the owner's command.
6. **Users of oplog-core:** `mytasker` pins the commit of oplog-core in its `.oplog-core-ref`, and its CI checks out that commit with a read-only deploy key ("mytasker CI (read-only)"). For this reason, a commit that mytasker uses must be pushed. After the merge, mytasker pins the commit on `master` again, because a squash merge or a rebase merge makes a new commit (mytasker `AGENTS.md` §7.1).
7. **After the merge** (when the owner says so): `git switch master && git pull --ff-only`, then delete the local branch.

## CI, SBOM and Dependabot

- **CI** (`.github/workflows/ci.yml`) runs for each pull request and for each push to `master`: typecheck, tests, SBOM with its check, `npm audit`. A pull request must have a green CI before the merge.
- **SBOM:** `make sbom` writes `sbom/runtime.cdx.json` and `sbom/build.cdx.json` (`SBOM_FORMAT=spdx` for SPDX) and checks that oplog-core has no runtime dependencies. `make check` and the CI regenerate it. Run it after each change of `package.json` or `package-lock.json`. `sbom/` is generated and git-ignored.
- **Dependabot** (`.github/dependabot.yml`) opens weekly pull requests for npm and GitHub Actions, and security updates at once. The checks and the review apply to them too. Push to a Dependabot branch only on the owner's command.
