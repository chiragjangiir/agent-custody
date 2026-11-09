# Review rules for agent-custody

agent-custody produces signed receipts of what AI agents did, and verifiers that check them. A bug that makes a check pass when it should fail is worse than a crash. Review with that in mind, and report only what you can point to in the diff.

The full rules are in `CLAUDE.md` (every change) and `CONTRIBUTING.md` (by area). Its "Security invariants" section is the most important part.

## Flag as a bug

- **Fail-open paths.** An error, timeout, parse failure, or unreachable dependency that leads to allow, relay, forward, or a check passing. The gateway, the door, the egress witness, and the ACS Guardian must refuse when they cannot decide. A policy engine that throws must deny.
- **A weakened security invariant** from `CONTRIBUTING.md`, especially: the grant checked on every call and again before forwarding; `precommit` withholding when the authorization append fails; `strict` refusals; capture rules applied once, before signing; no salt in a receipt; an upstream signature covering `{ content, isError }` only.
- **Verifiers out of step.** A check added or changed in `packages/receipts/src/verify.ts` without the same change in `packages/state/src/verify-web.ts` and `packages/python/agent_custody/verify.py`. A change to `verifyInclusion` or `verifyConsistency` in `log.ts` without the matching change in those verifiers and in `spec/lean`.
- **Vectors regenerated without a format or check change.** `packages/receipts/vectors/` changes only when the receipt format or a check changes, never to make a test pass.
- **Secrets.** A secret read from a flag value instead of the environment, a token written to a log or a receipt, or a fixed credential in a test, where tests should mint their own.
- **Network calls.** An outbound fetch in `packages/receipts` without `AbortSignal.timeout`. A test that uses the network.
- **Money as a float.** Money is integer minor units. Cedar has no floats.
- **Unescaped output in the portal and admin pages**, which are template literals. A value placed in HTML without escaping, or a page script that writes data other than with `textContent`.
- **Caches and shared state** that can give one caller's decision, policy, or session to another. For example, an id reused while a live entry still holds it, or a session keyed only by a value the caller chooses.

## Flag as a gap

- New or changed behaviour without a test that would fail if it broke. A test that cannot fail is not a test.
- A new command, flag, public function, route, or MCP tool without docs in `packages/receipts/docs/` and `site/reference/`, or a change that leaves a README stale.
- No `CHANGELOG.md` entry under `## Unreleased`.
- Node 22 type stripping: no enums, no parameter properties, and `.ts` import specifiers.

## Do not flag

- Style and naming that match the code around them.
- Long, plain sentences in docs and comments: that is the house style.
- The absence of a code comment where the code explains itself.
