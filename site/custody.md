# Agent sessions in this repository

agent-custody is built with an AI agent in Claude Code. The hook that records the agent's tool calls is committed in the repository, but it records only on a machine that has its config in `~/.config/agent-custody`. Not every machine that works here has that config. On 2026-11-02 the tenant held six receipts, so most of the work in this repository has no receipt. Where the hook runs, the receipts, the signing key, and the log token stay on that machine, and the hash of each receipt goes to our own tenant on the hosted log within seconds of the call. This page shows the live evidence and how to check it yourself.

## What the hook records

| event | what happens |
| --- | --- |
| before a `Bash`, `Write`, `Edit`, or MCP tool call | the Cedar policy below decides; a refusal is returned to Claude Code as a denial, and a **denied** receipt is issued |
| after the call | an **executed** receipt is issued with the tool, its arguments, and its result |
| after a failed call | a **failed** receipt |

Each receipt is signed with the agent's key and its leaf hash is appended to the log at `https://log.agent-custody.dev/t/agent-custody/`, hash-only: the log never sees the receipt. The tree head and the checkpoints are public.

- The tenant's current head: [/t/agent-custody/head](https://log.agent-custody.dev/t/agent-custody/head)
- Its latest published checkpoint: [checkpoints.agent-custody.dev/agent-custody/latest.json](https://checkpoints.agent-custody.dev/agent-custody/latest.json)
- The log's keys: [/.well-known/agent-custody-log.json](https://log.agent-custody.dev/.well-known/agent-custody-log.json)

The tree size in the head is the number of receipts issued so far.

## The policy the agent runs under

Everything is permitted and recorded, except three things, which are refused before they run and recorded as refusals:

```cedar
permit(principal, action, resource);

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*-f *" };

forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*rm -rf /*" };
```

The policy file is [policy.cedar](https://agent-custody.dev/custody/policy.cedar); its sha256 is in every receipt, so a change to it shows in the receipts from that moment.

## Two receipts you can verify

Both were issued when the hook was first exercised on 2026-09-21, and both are in the log.

| receipt | what | file |
| --- | --- | --- |
| `c92e582b` | `git status --short`, executed | [c92e582b-681b-47dd-a7d7-a67897f3209e.json](/custody/c92e582b-681b-47dd-a7d7-a67897f3209e.json) |
| `47eb52af` | `git push --force origin main`, **denied** by the policy before it ran | [47eb52af-9cd0-4428-bbdc-b44c04a1f266.json](/custody/47eb52af-9cd0-4428-bbdc-b44c04a1f266.json) |

The agent's public key is [claude-code.pub](https://agent-custody.dev/custody/claude-code.pub). To verify one:

```bash
curl -sO https://agent-custody.dev/custody/47eb52af-9cd0-4428-bbdc-b44c04a1f266.json
curl -sO https://agent-custody.dev/custody/claude-code.pub
npx @agent-custody/receipts verify 47eb52af-9cd0-4428-bbdc-b44c04a1f266.json --issuer-key claude-code.pub --log-url https://log.agent-custody.dev/ --log-id agent-custody
```

`--log-url` fetches and pins the log's published keys; `--log-id` requires the tree head to be this tenant's. Or open it in the [browser verifier](/verify?receipt=47eb52af-9cd0-4428-bbdc-b44c04a1f266), which loads the receipt, the agent's key, and the log's key from this site and runs every check in the page. Every check is listed in [verification](/receipts/verification).

## What this does and does not prove

These are SDK receipts: the hook runs inside Claude Code's process, so every field is `claimed`, the agent's own report, and the [threat model](/receipts/threat-model) is explicit that an in-process receipt is history, not evidence against that process. What the log adds is the part the agent cannot fake after the fact: that a receipt with exactly this content existed by the time its leaf was appended, in a tree whose history has not been rewritten since. For the calls that matter in production, use the gateway, which is not the agent's process. For a repository, this is the honest amount of custody, and it is more than any commit log offers.

## Running the same on your machine

The hook is [`.claude/custody-hook.sh`](https://github.com/svayatta/agent-custody/blob/main/.claude/custody-hook.sh), registered in [`.claude/settings.json`](https://github.com/svayatta/agent-custody/blob/main/.claude/settings.json). It records only when `~/.config/agent-custody/hook.sh` exists, so cloning the repository changes nothing for you. To record your own sessions, create that directory with an SDK config, a key from `agent-custody keygen`, a policy, and a `log` block pointing at your own log or a tenant of ours; the [SDK guide](/receipts/sdk#claude-code) has the config.
