# Working in this repository

This is a Bun workspace: `packages/receipts` (receipts), `packages/state` (governed memory), `packages/python` (the Python client), and `site/` (the VitePress website). `bun run test`, `typecheck`, `build`, `demo`, and `ci` at the root run across the packages. The CLI, the tutorials, and `bun run vectors` run from inside `packages/receipts`.

Before you work in an area, read its rules:

- Code in `packages/`, a release, or a publish: `CONTRIBUTING.md`.
- `site/`: `site/README.md`.
- `deploy/`: `deploy/README.md`, and `deploy/RUNBOOK.md` for operations.
- Security-relevant code: the comment beside it, and the security invariants in `CONTRIBUTING.md`.

## Before a commit

- Update the READMEs in the same commit: the README of each package that the change touches, and the root README when the layout or the package list changes. In `packages/receipts/README.md`, check the intro, the doc links, the supported hosts table, the quick start, the layout block, and the Plan section (move finished items to Done, renumber Next).
- A new adapter, command, flag, or check gets its documentation in `packages/receipts/docs/` in the same commit.
- A new or changed public function, route, MCP tool, or CLI flag updates its page in `site/reference/` in the same commit.
- A new module or adapter in `packages/receipts` or `packages/state` gets an example in that package's `examples/`, which ends by printing `OK`. In receipts, it also gets a row in `docs/tutorials.md`.
- Every version bump gets an entry in `CHANGELOG.md`.
- Commit messages carry no attribution trailers.
- Nothing goes to main until `bun run ci` passes locally. Run gate commands bare: `bun run ci | grep ...` reports the exit code of grep.
- main is protected. Every change lands by pull request, and the `test` check must pass on a head that is up to date with main. Wait for `gh pr checks --watch` before a merge.

## Rules for all code

- Write a code comment only when the code cannot explain itself. Keep it short. Do not put issue or PR numbers in code comments; they go in the commit message and the CHANGELOG.
- The CLI runs on plain Node 22 through native type stripping. Do not use parameter properties or enums. Use `.ts` import specifiers.
- The state package imports receipts from `dist/` through the `exports` map. Run `bun run build` at the root before you run a state example by hand.
- Money is integer minor units. Cedar has no floats.
- Secrets come from the environment, never from flag values. Never put a token into a transcript. Tests mint their own.
- Every outbound fetch in the receipts package carries an `AbortSignal.timeout`.
- Tests never use the network. A timeout on a loaded machine is not a failure.
- Regenerate `packages/receipts/vectors/` only when the receipt format or a check changes, never to make a test pass. A check added or renamed in `src/verify.ts` gets the same change in `site/verifier/verify-web.ts`.

On a machine with `~/.config/agent-custody/hook.sh`, the custody hook in `.claude/` makes each tool call of a session a receipt and refuses force pushes. On any other machine it does nothing. "Agent sessions in this repository" in the root README explains it.
