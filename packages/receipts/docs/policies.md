# Writing policies

Policies are written in [Cedar](https://www.cedarpolicy.com/), the language AWS uses for AgentCore and Verified Permissions, or in [Rego](https://www.openpolicyagent.org/docs/policy-language), the language of Open Policy Agent. There is no home-grown policy language here. Cedar is the default and most of this page uses it; [Rego](#rego) has its own section, including the choice between a Rego file the gateway compiles and an OPA server you already run. Every example on this page is executed against the real evaluator in the test suite.

## How a tool call becomes a Cedar request

For an intercepted call to tool `T` by the agent named in the grant:

| Cedar slot | value |
| --- | --- |
| `principal` | `Agent::"<agent id from the grant>"` |
| `action` | `Action::"<T>"` |
| `resource` | `Tool::"<T>"` |
| `context.args` | the call's arguments, exactly as the agent sent them. **Provenance: claimed.** |
| `context.facts` | results of the gateway's own upstream lookups configured in `facts`. **Provenance: observed.** |
| `context.grant` | `{ principal, scopes }` from the signed delegation. **Provenance: attested.** |

No entity hierarchy or schema is loaded yet, so policies reason about `context` and the three identifiers above.

Two things happen before Cedar runs and cannot be overridden by policy:

1. If `T` is not in the grant's scopes, the call is denied. No facts are fetched.
2. Each configured fact for `T` is fetched from upstream. If any lookup fails, the call is denied.

## The rules Cedar applies

- **Default deny.** With no matching `permit`, the decision is deny.
- **`forbid` wins.** A matching `forbid` overrides every `permit`.
- **Errors deny.** If evaluating any policy raises an error, such as a missing attribute or a float, the gateway denies regardless of what other policies said. The errors are recorded in the receipt.
- **The policy is pinned.** The receipt carries the sha256 of the policy file, so a verifier knows which text produced the decision.

## Examples

Each of these is a complete, valid policy file.

**Permit a read to any agent holding the scope.**

```cedar
permit(principal, action == Action::"customer.lookup", resource);
```

**Cap an amount.** Amounts are integer minor units. 100000 pence is £1,000.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 };
```

A call without `amount` is an error, hence a deny. That is the behaviour you want from a payments policy.

**Require a fact the gateway fetched, not something the agent asserted.** This is the pattern the whole project exists for.

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when {
  context.args.amount <= 100000 &&
  context.facts has customer &&
  context.facts.customer.verified == true
};
```

With the matching `facts` entry in the gateway config, `context.facts.customer` is whatever `customer.lookup` returned for the customer id in the call. An agent that sends `{ "verified": true }` in its arguments changes nothing, because the policy never reads `context.args.verified`.

**Restrict to a named agent.**

```cedar
permit(principal == Agent::"support-agent", action == Action::"stripe.refund", resource);
```

**Several tools in one rule.**

```cedar
permit(principal, action in [Action::"customer.lookup", Action::"customer.search"], resource);
```

**A hard block that no permit can override.**

```cedar
permit(principal, action == Action::"stripe.refund", resource)
when { context.args.amount <= 100000 };

forbid(principal, action == Action::"stripe.refund", resource)
when { context.facts has customer && context.facts.customer.flagged == true };
```

**Pattern-match a string argument.**

```cedar
permit(principal, action == Action::"github.merge", resource)
when { context.args.repo like "acme/*" && context.args.base == "main" };
```

**`unless` reads better for exceptions.**

```cedar
permit(principal, action == Action::"stripe.refund", resource)
unless { context.args.currency != "GBP" };
```

**Reach the grant itself.**

```cedar
permit(principal, action, resource)
when { context.grant.principal == "user_456" };
```

## Policies for memory

The memory server in `@agent-custody/state` is an upstream like any other, so its tools are governed by the same policy file with the same request shape. What differs is what is in the context:

| for | `context.args` carries | `context.facts` can carry |
| --- | --- | --- |
| `memory.write` | `subject`, `predicate`, `value`, `space`, and optionally `supersedes` and `evidence` | `target`, the fact being superseded, when the gateway is configured to look it up with `memory.get` |
| `memory.read` | the query, and `includeClaimed` or `requireVerified` when the caller asks for them | |
| `memory.retract`, `memory.forget`, `memory.hold`, `memory.release` | `factId` and `reason` | `target`, the fact being changed |
| `memory.sweep` | `before`, `space`, `reason` | |
| `memory.repair` | `reason`, and optionally `before` (an earlier cutoff) | |
| `memory.confirm` | `factId` | |

A looked-up `target` has `space`, `actor`, `provenance` (`claimed`, `attested`, or `verified`), `subject`, `predicate`, `value`, and `retracted`. Fields that would be null are absent, so test with `has`. The lookup config that makes `target` available is in the [state package README](../../state/README.md#the-memory-server).

**Confine an agent to its team's space.** Reads anywhere, writes only to one space.

```cedar
permit(principal, action == Action::"memory.read", resource);
permit(principal, action == Action::"memory.write", resource)
when { context.args.space == "team:support" };
```

**Keep quarantine closed.** Only a named reviewer may read claimed facts or lift them out of quarantine.

```cedar
permit(principal, action == Action::"memory.read", resource)
unless { context.args has includeClaimed && context.args.includeClaimed == true && principal != Agent::"reviewer" };
permit(principal == Agent::"reviewer", action == Action::"memory.confirm", resource);
```

**Require evidence for org memory.** A write to the org space must cite a fact the gateway fetched itself; the memory server then checks the value against it and writes it as verified, or refuses.

```cedar
permit(principal, action == Action::"memory.write", resource)
when { context.args.space != "org" || context.args has evidence };
```

**Protect attested org facts from being displaced or retracted.** Needs the `target` lookup. A self-reported org note can be replaced; an attested one cannot.

```cedar
permit(principal, action in [Action::"memory.write", Action::"memory.retract"], resource);
forbid(principal, action in [Action::"memory.write", Action::"memory.retract"], resource)
when { context.facts has target && context.facts.target.space == "org" && context.facts.target.provenance == "attested" };
```

**Erasure and holds belong to named roles.** Everyone else is denied by default.

```cedar
permit(principal == Agent::"privacy-officer", action in [Action::"memory.forget", Action::"memory.sweep"], resource);
permit(principal == Agent::"legal", action in [Action::"memory.hold", Action::"memory.release"], resource);
```

**A complete policy for a support agent.** The pieces above, together: read anywhere but not into quarantine, write team memory freely, write org memory only with evidence, retract only claimed facts, and no erasure or holds at all.

```cedar
permit(principal, action == Action::"memory.read", resource)
unless { context.args has includeClaimed && context.args.includeClaimed == true };
permit(principal, action == Action::"memory.write", resource)
when { context.args.space == "team:support" || (context.args.space == "org" && context.args has evidence) };
permit(principal, action == Action::"memory.retract", resource)
when { context.facts has target && context.facts.target.provenance == "claimed" };
```

## Rego

A gateway decides by Rego in one of two ways. Give `policyFile` a path ending in `.rego`, and the gateway compiles the file itself. Or give `opa` instead of `policyFile`, and the gateway asks an OPA server you run. Both read the same request and the same rules, so a policy moves between them unchanged.

### The request and the rules

The input is the Cedar request with plain strings for the three identifiers:

| Rego | value |
| --- | --- |
| `input.principal` | the agent id from the grant |
| `input.action` | the tool name |
| `input.resource` | the tool name |
| `input.context.args` | the call's arguments. **Provenance: claimed.** |
| `input.context.facts` | the gateway's own upstream lookups. **Provenance: observed.** |
| `input.context.grant` | `{ principal, scopes }` from the signed delegation. **Provenance: attested.** |

The policy declares `package agentcustody` and defines two rules:

- **`allow`**, a boolean. **Default deny:** the call is permitted only when `allow` is exactly `true`.
- **`deny`**, a set of strings. Any entry wins over `allow`, as a Cedar `forbid` wins over a `permit`. Its strings are the reasons in the receipt and in the message the agent gets.
- **Errors deny.** A policy that fails while it evaluates, or whose `allow` is not a boolean or whose `deny` is not a set of strings, denies the call. The receipt records the error.
- **The scope check and the fact lookups run first**, exactly as for Cedar, and no policy can override them.

The fixture policy from the top of this page, in Rego:

```rego
package agentcustody

# Reads of customer records are permitted to any agent holding the scope.
allow if input.action == "customer.lookup"

# Refunds: a whole number of pence from 1 to 100000 (£1,000), and only for customers the gateway itself verified.
allow if {
	input.action == "stripe.refund"
	amount := input.context.args.amount
	is_number(amount)
	amount == floor(amount)
	amount > 0
	amount <= 100000
	input.context.facts.customer.verified == true
}

deny contains "this customer is flagged for review" if {
	input.action == "stripe.refund"
	input.context.facts.customer.flagged == true
}
```

A missing attribute is *undefined* in Rego, not an error: the rule does not hold when there is no `amount`, so the call is denied. That is the same outcome as Cedar's error, reached a different way. Rego has floats, which Cedar does not, so `amount <= 100000` alone would hold for `0.5`, and for `0` and `-1` as well. Amounts are integer minor units: `amount == floor(amount)` holds only for a whole number, and `amount > 0` sets the floor.

### A Rego file, or an OPA server

| | `policyFile: "policy.rego"` | `opa: { "url": ... }` |
| --- | --- | --- |
| where the policy lives | a file beside `gateway.json`, as with Cedar | in the bundles of an OPA server your platform team runs |
| how it is evaluated | compiled to WebAssembly by `opa build` when the file loads or changes, then evaluated inside the gateway | an HTTP query to the server's Data API for every call |
| what it needs | the `opa` binary on `PATH` when the policy loads or changes. The gateway notices a change on the first call after it and compiles the file then, synchronously: the whole process waits for `opa build`, typically a few hundred milliseconds, so `/health` and every other call wait too. The compile has no deadline, so an `opa` that hangs stalls the gateway until it exits or the process is killed. A file that does not compile is compiled once, not again on each call, until it changes. The gateway image includes `opa` | a reachable server at an `https` URL, or `http` on a loopback address. A call it cannot answer within `timeoutMs` (default 2000) is denied |
| what `policyDigest` in a receipt is | the sha256 of the file's text, as for Cedar. The portal can name it, and anyone with the file can check it | the sha256 of the decision URL and the revision of every bundle the server reports. Map it back with `receipts/policy-reloads.jsonl`. A call the server did not answer is denied under the URL's own "unanswered" digest, never under a revision that did not decide it |
| changing the policy | write the file by rename. It applies from the next call, and a file that does not compile is refused while the policy in force stays | publish a new bundle revision. The first call under it records the new digest |
| builtins | those the WebAssembly runtime supports. `http.send`, `time.now_ns`, and other builtins it cannot run are refused when the file loads | everything the server allows, including `http.send` |
| best for | a gateway that should decide on its own, with the policy text pinned in every receipt | an organisation that already governs policy centrally in OPA and wants agents under the same bundles |

**What a receipt can prove differs.** With a file, the receipt pins the exact text that decided, so a verifier holding the file can show it was this policy. With a server, the receipt pins only what the server *said* it was running: the bundle revisions in its `provenance` answer. The gateway asks for provenance on every query, records each new combination in `policy-reloads.jsonl` with the bundle names and revisions, and prints it. Serve the policy from a bundle built with `opa build --revision <id>`, so the revision names a version you can find again. A server that reports no revision still works, but the gateway warns at start and on each new answer that its receipts cannot name the policy. `agent-custody check` warns about it as well.

**A server outside the policy also decides.** A Rego file is evaluated where the gateway runs, under the operator's control. An OPA server's answer is trusted as it comes back over HTTP. Run it where only your platform team can change it, and give the gateway a token with `tokenEnv` when the server requires one. Each query carries the call's arguments and that token, so the gateway refuses a plain `http` URL unless the host is a loopback address, and it never follows a redirect: a 3xx answer denies the call. The gateway refuses to start when it cannot reach the server, or when the server does not define the package.

A gateway config with an OPA server:

```json
"opa": {
  "url": "http://localhost:8181",
  "decision": "agentcustody",
  "tokenEnv": "OPA_TOKEN",
  "timeoutMs": 2000
}
```

`decision` is the package path under `/v1/data`, such as `authz/agents` for `package authz.agents`, and defaults to `agentcustody`. The document at that path must have the `allow` and `deny` rules above. The gateway posts `{ "input": ... }` to `<url>/v1/data/<decision>?provenance=true`.

### Testing and simulating a Rego policy

`opa test` runs Rego unit tests as usual. `evaluateRego` and `compileRego` from `@agent-custody/receipts` evaluate a policy exactly as the gateway does, with the same decision and digest:

```ts
import { compileRego, evaluateRego, policyDigest } from "@agent-custody/receipts";

const text = readFileSync("policy.rego", "utf8");
const { policy, errors } = compileRego(text); // errors: why it cannot load
const d = evaluateRego(policy!, policyDigest(text), { agentId: "support-agent", tool: "stripe.refund", context: { args: { amount: 50000 }, facts: { customer: { verified: true } } } });
```

`agent-custody policy simulate --policy proposed.rego ...` replays recorded receipts against a Rego policy, including receipts a Cedar policy decided, so a move from Cedar to Rego can be checked against history before it is enforced. `agent-custody check` compiles a `.rego` file, or queries the OPA server once. An SDK issuer reads a `.rego` `policyFile` the same way. The console's policy editor, the deny report, and `init claude-code` work with Cedar only for now.

## Saying why a rule denies

Put a `@reason("...")` annotation before a `forbid` rule. The Claude Code hook shows the text to the agent and to the person who reads the session, and `agent-custody report` prints it before the rule.

```cedar
@reason("force push rewrites shared history")
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };
```

The hook text is `agent-custody denied this call: force push rewrites shared history (rule policy1, receipt <id>)`. A rule with no annotation shows its id. The annotation is part of the policy file, so it changes the policy digest, but it never changes the decision or the receipt format. Keep the reason short and say what the rule forbids, not what the agent did. Only the Claude Code hook and the report read it today.

## Gotchas

- **Integers only.** `12.50` is not a Cedar value. Send `1250`.
- **Test `has` before reading an optional attribute.** `context.facts.customer.verified` errors if there is no `customer` fact, and an error is a deny. Sometimes that is what you want. When it is not, guard with `context.facts has customer`.
- **No schema means no typo protection.** A policy that reads `context.args.ammount` never matches and every refund is denied. Fail-closed hides typos as denials, so test your policies.
- **Scope is enforced outside Cedar.** You cannot use a policy to grant a tool the delegation did not include.

## Testing a policy

The evaluator is a pure function, so a policy test is a unit test. See [test/policy.test.ts](../test/policy.test.ts).

```ts
import { evaluate } from "../src/policy.ts";
import { readFileSync } from "node:fs";

const policy = readFileSync("policy.cedar", "utf8");
const d = evaluate(policy, {
  agentId: "support-agent",
  tool: "stripe.refund",
  context: {
    args: { customer_id: "cust_123", amount: 50000 },
    facts: { customer: { verified: true } },
    grant: { principal: "user_456", scopes: ["customer.lookup", "stripe.refund"] },
  },
});
// d.decision  "allow" | "deny"
// d.reasons   ids of the policies that decided it
// d.errors    evaluation errors, non-empty always means deny
// d.policyDigest  sha256 of the policy text, the same value a receipt will carry
```

Write one case per branch of every `when` clause, plus one for the missing-attribute path.

## Simulating a policy against recorded history

Use `policy simulate` before enforcing a tighter policy. It verifies local receipt bundles with your public keys, then evaluates the proposed Cedar text against the arguments and fact values each receipt recorded at call time. Gateway receipts also supply the principal and scopes from their signed delegation as `context.grant`; SDK receipts keep their original context of `args` and `facts: {}`. Replay runs offline, without fetching new facts or executing tools.

```bash
agent-custody policy simulate --policy proposed.cedar --receipts receipts \
  --issuer-key keys/gateway.pub --principal-key keys/principal.pub \
  --out simulation.json
```

For SDK receipts, use the application's public key as `--issuer-key`; no principal key is needed. Add `--log-key keys/log.pub` when another key signed the log's tree heads. Add `--approval-key keys/approver.pub` when the history holds calls that a human approved: `verify` needs those keys for a forwarded call that carries an approval, and the command fails without them. Each key flag may be repeated when the history spans several keys. The directory is read in filename order, without recursion, one bundle at a time, so it never holds the tool results of the whole history in memory. A malformed or unverifiable bundle, or invalid Cedar syntax in the proposed policy, fails the command.

A gateway that dies after it forwards a `precommit` call leaves `<id>.authorization.json` and no `<id>.json`. The command verifies each such file as an authorization statement (the issuer key, the tree head, and the inclusion proof) and lists the call under `skipped`, so the report is `INCOMPLETE`. An authorization that does not verify fails the command. An authorization that sits beside its receipt is not read twice.

The command also checks that each `<id>.json` holds receipt `<id>`. A receipt under another file name fails the command, so a copy over the name of another receipt cannot hide that call.

A receipt under a capture rule needs its withheld arguments and fact values to replay. Give `--capture-key-env NAME` to decrypt the values that mode `encrypted` withheld, as `verify` does. Give `--disclose <file>`, which you can repeat, for the values that mode `digest` withheld. Each file is a disclosure as `reveal` writes it, and it applies only to the receipt that its `receiptId` names. A key or a disclosure that does not match a commitment skips that receipt as malformed. The key comes from the environment, never from a flag value.

The report lists every call whose `allow` or `deny` decision changes, grouped by tool and the proposed decision's policy ids or evaluation errors, with the receipt ids and both decisions. A call executed in observe mode may already have a recorded deny: replay compares that recorded decision, not whether the tool ran. Calls with the same decision stay unchanged even when different policy ids match. Cedar evaluation errors remain denials.

Every run records a `runId`, `timestamp`, the proposed text's sha256 as `policyDigest`, and the original digests as `previousPolicyDigests`. `--out` saves the full JSON report, and `--json` prints it to stdout. Changes alone exit 0. A report that cannot replay every call says `INCOMPLETE` and exits 1: `skipped` names each receipt and why. This includes record-only receipts with no policy baseline, withheld arguments or fact values, calls whose receipt is missing, and calls stopped before Cedar could evaluate. Grant failures cannot become permits through a policy change, and neither can an approval refusal: the gateway checks the approval before Cedar runs, so the call is skipped as a non-policy gate. The approval record says so even under a private rule. Withheld results alone do not prevent replay. A reconciliation receipt is a provider read, so no policy decision exists to replay. The report counts it in `reconciliations`, not in `evaluated` or `skipped`, and it does not make the report incomplete. A reconciliation whose original receipt is missing is the exception: the call that it settles cannot be replayed, so the report skips that call and says `INCOMPLETE`. The library trusts a reconciliation receipt only after `verifyBundle` accepts it; the CLI and the console verify first.

The report is an analysis of the supplied receipt directory; it does not prove that the directory contains the whole history. Keep the report beside the proposed policy and review the changed receipt ids before switching from observe mode to enforcement. [Tutorial 28](../examples/28-policy-simulation.ts) records three refunds, stops the gateway, and replays them against a lower limit.

## How an arrival at the door becomes a Cedar request

The [door](door.md) uses the same evaluator for arrivals at your own HTTP surface. `principal` is `Agent::"<agent>"` for the agent a verified grant names, and `Agent::"unknown"` for every other arrival: a declared name is a claim and stays in the arrival fact. `action` and `resource` are the route the arrival fell under. `context.args` is the request (`method`, `path`, `query`, `headers`, a JSON `body` when small, `bodyBytes`, `bodyDigest`; `bodyOversized: true` and no digest when the body passed `maxBodyBytes`), claimed. The policy reads it with `null` members dropped and numbers that are not safe integers as strings, since Cedar refuses both. `context.facts.arrival` is the door's own observation of the arrival: its `class` (`verified`, `claimed`, `unknown`), `subject`, what became of its `grant`, and its `remote` address. `context.grant` is present only for a verified arrival. A policy that lets `unknown` through on a route lets everything through on that route.

```cedar
permit(principal, action == Action::"catalogue", resource);

permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};
```

A bound on an amount needs both ends: `amount <= 5000` alone lets a negative refund through, and the door relays the body as it came. A permit that names an agent, `principal == Agent::"shopping-agent"`, is satisfied only by a verified grant for that agent: a declared name never reaches the principal slot. `agent-custody check` still warns on a permit that names an agent without requiring `context.facts.arrival.class == "verified"`, because a policy copied from the gateway reads as if it did.
