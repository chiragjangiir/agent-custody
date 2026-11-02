# Claude Code and the Claude Agent SDK

One hook command records every tool call of a session as a receipt, and can deny a call before it runs. Claude Code invokes it as a command hook with the event on stdin; the Claude Agent SDK calls the same handler in process.

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
| `PreToolUse`, policy denies | issues a **denied** receipt, blocks the call | `{ "continue": true, "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "agent-custody: policy1 (receipt 47eb52af-…)" } }` |
| `PreToolUse`, policy denies, the receipt cannot be recorded | blocks the call | the same, with `(no receipt: <why>)` in the reason |
| `PreToolUse`, policy allows or none | nothing | `{}`: Claude Code's own permission prompts still apply; the hook never auto-approves |
| `PostToolUse` | issues an **executed** receipt with `tool_response` as the result | `{}` |
| `PostToolUseFailure` | issues a **failed** receipt with the error as the result | `{}` |

Exit code 0 in every case; a receipt that could not be logged is printed on stderr. If the user declines a call at the permission prompt, no `PostToolUse` fires and no receipt is issued for it.

## In process

```ts
import { createSdkIssuer, loadSdkConfig } from "@agent-custody/receipts";
import { handleHookEvent, claudeAgentHooks } from "@agent-custody/receipts/sdk/claude";
const issuer = createSdkIssuer(loadSdkConfig("sdk.json"));
const out = await handleHookEvent(issuer, input);      // HookInput → HookOutput, as above
const hooks = claudeAgentHooks(issuer, "Bash|Write|Edit"); // the hooks object the Claude Agent SDK takes
```

Python: `agent_custody.claude_agent_sdk.claude_hook(client)` and `handle_hook_event(client, input_data)`, same input and output, through the sidecar.

## The policy's view

The tool name is the Cedar action, `context.args` is `tool_input`, and there are no facts. A policy that refuses force pushes:

```cedar
permit(principal, action, resource);
forbid(principal, action == Action::"Bash", resource)
when { context.args has command && context.args.command like "*git push*--force*" };
```
