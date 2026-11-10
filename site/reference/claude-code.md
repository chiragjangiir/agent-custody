# Claude Code and the Claude Agent SDK

One hook command records every tool call of a session as a receipt, and can deny a call before it runs. Claude Code invokes it as a command hook with the event on stdin; the Claude Agent SDK calls the same handler in process.

## One command

```bash
npx @agent-custody/receipts init claude-code [--dir <dir>] [--user] [--enforce] [--log-url <url> --log-key <pub> [--log-id <id>] [--log-token-env NAME]]
```

The command makes an agent key, writes `sdk.json` with `"mode": "observe"`, writes a starter deny set to `policy.cedar`, and registers the three hooks with absolute paths. It prints each step and ends with the next step.

| option | effect |
| --- | --- |
| `--dir <dir>` | where the key, `sdk.json`, `policy.cedar`, and `receipts/` go. Default: `~/.config/agent-custody` |
| `--user` | write the hooks to `~/.claude/settings.json`. Default: `.claude/settings.local.json` in the current directory. `init` never edits `.gitignore`. When the project is a git repository and git does not ignore the file, `init` prints a warning with the line to add: `.claude/settings.local.json` |
| `--enforce` | leave out `"mode": "observe"`: a denied call is blocked |
| `--log-url <url>` | log the receipts to this URL as hashes (`hashOnly`, `timeoutMs` 3000). Without it, the config has `"logFile": "log.jsonl"` and the receipts stay on the machine |
| `--log-id <id>` | the log id that the tree heads must name |
| `--log-token-env NAME` | the NAME of the environment variable that holds the log token. Default: `AGENT_CUSTODY_LOG_TOKEN`. The token never goes into a flag or a file |
| `--log-key <pub>` | the log's public key file, in PEM form. `--log-url` needs it, because `report` cannot check the tree head of a receipt without it. The command refuses a private key and any other file. It copies the file to `log.pub` and pins it in `log.keys` when it writes a new `sdk.json`. A second run does not replace `log.pub` |

The starter deny set permits every call and forbids these Bash commands: `git push` with `--force`, `-f`, or a `+refspec` (also `git -C <dir> push`), `rm -rf` and its flag variants (`-fr`, `-Rf`, `-r -f`) on `/`, `~`, or `$HOME` (also in double quotes), `terraform destroy`, `terraform apply -destroy`, and `drop database` or `DROP DATABASE` (the Cedar `like` operator is case-sensitive). Each rule has a `@reason`, which the denial text shows. The file ships in the package as `templates/claude-code.cedar`.

The policy allows `git push --force-with-lease`. It is a force push that fails when the remote has new commits, so it is the safer form, and the `@reason` of the force push rule says so. A flag counts when it is the first argument after `push`, when no `&`, `|`, `;`, or newline follows `push`, or when one of them follows the flag. So `git push origin main && npm install --force`, `git push && git status -f`, and `git push origin fix-f` pass. A chain with two operators after `push` can be denied by mistake. Cedar `like` has only `*`, so it cannot read shell words: `rm --recursive --force /` and `terraform -chdir=infra destroy` pass. The rule ids are the places of the rules in the file, so change a rule in place and add a new rule at the end. The [starter deny set](https://github.com/svayatta/agent-custody/blob/main/packages/receipts/docs/sdk.md#the-starter-deny-set) lists every limit.

The settings file is merged, not replaced. Every other key and hook stays, a hook that is already there is not added again, and a settings file that is not valid JSON stops the command before it changes anything. Hooks can run at the same time. The local log takes the lock file `log.jsonl.lock` for each append, so concurrent hooks keep one log that `report` verifies. A writer waits up to 20 seconds for the lock. A `PreToolUse` hook that gives up still blocks a denied call, and the denial text ends with `no receipt: <reason>`. A `PostToolUse` or `PostToolUseFailure` hook that gives up loses its receipt: the tool call has already run, and the hook exits with code 1 and does not retry. A lock is stale when its process on this host is gone. The lock of a live process on this host is never broken. The lock of a process on another host, or a lock file with no readable owner, is stale when nobody touched it for 60 seconds. If a process is killed in the middle of a write, the next append moves the partial last line to `log.jsonl.torn`. The command never overwrites an existing key, `sdk.json`, `policy.cedar`, or `log.pub`, so it is safe to run two times. When `sdk.json` exists, the command ignores `--enforce` and the log options, and it warns for each one. A second run updates the path of a hook of ours. The hook pins the path of the Node binary that runs `init`. With nvm, a removed Node version breaks the hook, and every tool call then prints an error; run `init` again to update the path. When the path is in the npx cache (`/_npx/`), the command warns that npm can clear the cache; install the package globally and run the command again.

## The report

```bash
agent-custody report --config <sdk.json>
```

The command reads `receiptsDir` of the config and verifies each receipt with the agent's key (and the log keys of the config, when it has a log). It prints `would have denied N calls` and, for each call, the tool, the command or the file path, the `@reason` of the rule when it has one, the rule (cut to 160 characters), and the receipt id. A denial recorded with `enforced: false` is a call that ran. A receipt that does not verify is listed apart with its reason and is not counted. Exit code 1 when any receipt does not verify, otherwise 0. The last line says how to enforce: remove the `"mode": "observe"` line from `sdk.json`.

An [incident replay](/guide/incident-replay) runs the hook in enforce mode and shows the denial text that Claude Code gets.

## Registering the hook

`.claude/settings.json` in the project, or the user's settings:

```json
{ "hooks": {
  "PreToolUse":         [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }],
  "PostToolUse":        [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }],
  "PostToolUseFailure": [{ "matcher": "Bash|Write|Edit|MultiEdit|mcp__.*", "hooks": [{ "type": "command", "command": "agent-custody hook --config /abs/path/sdk.json" }] }]
} }
```

`AGENT_CUSTODY_CONFIG` works instead of `--config`. The config is the [SDK config](./sdk-typescript#the-config-file). A wrapper script that exports the log token from a file and then runs the command keeps the token off the command line; the [custody page](https://agent-custody.dev/custody) shows the one this repository uses.

## Input

Claude Code writes the hook event as JSON on stdin. The fields the handler reads:

```json
{ "hook_event_name": "PreToolUse", "session_id": "a1b2…", "tool_use_id": "toolu_01…", "tool_name": "Bash", "tool_input": { "command": "git status --short" } }
```

`PostToolUse` adds `"tool_response": {…}`; `PostToolUseFailure` adds `"error": "…"`. `tool_input` becomes the receipt's `request.args` (a non-object input is recorded as `{ "input": … }`); `session_id` and `tool_use_id` become `session.id` and `session.toolUseId`, `claimed`.

## Output

| event | what the handler does | stdout |
| --- | --- | --- |
| `PreToolUse`, policy denies | issues a **denied** receipt, blocks the call | `{ "continue": true, "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "agent-custody denied this call: terraform destroy deletes infrastructure (rule policy5, receipt 47eb52af-…)" } }` |
| `PreToolUse`, policy denies, the receipt cannot be recorded | blocks the call | the same, with `(no receipt: <why>)` in the reason |
| `PreToolUse`, policy allows or none | nothing | `{}`: Claude Code's own permission prompts still apply; the hook never auto-approves |
| `PostToolUse` | issues an **executed** receipt with `tool_response` as the result | `{}` |
| `PostToolUseFailure` | issues a **failed** receipt with the error as the result | `{}` |

The reason text comes from the `@reason("...")` annotation of the rule that denied the call. With several denying rules, the reasons join with `; ` in file order and the line says `rules policy1, policy2`. A rule with no annotation gives its id in place of the reason. A deny that names no rule keeps the plain text, such as `agent-custody: no permit policy matched (receipt …)`. The receipt does not change: it keeps the policy ids and the digest. The issuer parses the annotations once, when it loads the policy, and exposes them as `issuer.ruleReasons`.

Exit code 0, except when a `PostToolUse` or `PostToolUseFailure` receipt cannot be written (for example, the log lock stays held for 20 seconds): then the hook prints the error on stderr and exits with code 1, and that receipt is lost. If the user declines a call at the permission prompt, no `PostToolUse` fires and no receipt is issued for it.

## In process

```ts
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
import { handleHookEvent, claudeAgentHooks } from "@agent-custody/receipts/sdk/claude";
const issuer = createSdkIssuer(loadSdkConfig("sdk.json"));
const out = await handleHookEvent(issuer, input);      // HookInput → HookOutput, as above
const hooks = claudeAgentHooks(issuer, "Bash|Write|Edit"); // the hooks object the Claude Agent SDK takes
```

Python: `agent_custody.claude_agent_sdk.claude_hook(client)` and `handle_hook_event(client, input_data)`, same input and output, through the sidecar. When the sidecar cannot be reached or the denial cannot be recorded, `PreToolUse` still denies, and the reason ends with `no receipt: <reason>`.

## The policy's view

The tool name is the Cedar action, `context.args` is `tool_input`, and there are no facts. A policy that refuses force pushes:

```cedar
permit(principal, action, resource);
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };
```
