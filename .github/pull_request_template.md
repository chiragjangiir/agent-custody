<!-- Fill in every section. The `pr-template` check fails while a section is missing or empty. Delete these comments. -->

## What and why

<!-- What changes, and why. Link the issue: "Fixes #123" or "Part of #123". -->

## How it was tested

<!-- The tests you added or changed, and what each would catch if the behaviour regressed. Paste the summary of a bare `bun run ci` run (the test counts, and that it exited 0). For a change that tests cannot reach, say what you ran by hand. -->

## Checklist

- [ ] `bun run ci` passes locally, run bare (not piped through `grep`), with exit code 0.
- [ ] New or changed code has tests that fail when its behaviour breaks. `bun run coverage` shows what the tests reach.
- [ ] READMEs, `packages/receipts/docs/`, and `site/reference/` are updated where this changes behaviour, a command, a flag, or a public function.
- [ ] `CHANGELOG.md` has an entry under `## Unreleased`.
- [ ] A new module or adapter has an example that ends by printing `OK`, and a row in `docs/tutorials.md`.
- [ ] Security-relevant code follows the invariants in `CONTRIBUTING.md`. A changed verifier check is mirrored in `packages/state/src/verify-web.ts` and the Python verifier, and `vectors/` is regenerated only when the receipt format or a check changed.
- [ ] No secrets, tokens, or real customer data in the code, tests, or this description.

## Notes for the reviewer

<!-- Anything that needs a closer look, a follow-up you have left out of scope, or "None". -->
