// Aspect: one command for Claude Code, and the would-have-denied report. Source: src/claude-init.ts, src/deny-report.ts, templates/claude-code.cedar
// Run:    node examples/36-claude-code-init.ts
//
// `agent-custody init claude-code` makes the key, the config, the starter policy, and the three hooks. The config is in
// observe mode: the policy records a denied call and blocks nothing. After a session, `report` lists the calls that
// the policy would have denied. Each rule has a `@reason`, and the hook text in enforce mode names it. The example uses a temporary home and a temporary project, never your own.
import { mkdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { initClaudeCode } from "../src/claude-init.ts";
import { loadSdkConfig } from "../src/config.ts";
import { denyReport, formatDenyReport } from "../src/deny-report.ts";
import { handleHookEvent } from "../src/sdk/claude.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { out, step } from "./_out.ts";

const base = out("36-claude-code-init");
const home = join(base, "home");
const project = join(base, "project");
mkdirSync(home, { recursive: true });
mkdirSync(project, { recursive: true });

step(1, "init claude-code: the key, sdk.json, the starter policy, and the hooks, each step printed");
const cliPath = resolve(import.meta.dirname, "..", "src", "cli.ts");
const { configFile, settingsFile } = initClaudeCode({ cliPath, home, cwd: project, print: (line) => console.log(`   ${line}`) });

step(2, "the hooks that init wrote, with absolute paths");
const settings = JSON.parse(readFileSync(settingsFile, "utf8"));
console.log(`   events: ${Object.keys(settings.hooks).join(", ")}`);
console.log(`   command: ${settings.hooks.PreToolUse[0].hooks[0].command}`);

step(3, "run the command again: nothing is added, and the key, the config, and the policy stay");
initClaudeCode({ cliPath, home, cwd: project, print: (line) => console.log(`   ${line}`) });
const again = JSON.parse(readFileSync(settingsFile, "utf8"));
if (again.hooks.PreToolUse.length !== 1) throw new Error("the second run added a hook again");
console.log(`   PreToolUse still holds ${again.hooks.PreToolUse.length} entry`);

step(4, "a session in observe mode: Claude Code calls the hook before and after each tool call");
const issuer = createSdkIssuer(loadSdkConfig(configFile));
for (const command of ["ls -la", "git push --force origin main", "terraform destroy -auto-approve", "npm test"]) {
  const call = { session_id: "demo", tool_name: "Bash", tool_input: { command } };
  const pre = await handleHookEvent(issuer, { hook_event_name: "PreToolUse", ...call });
  await handleHookEvent(issuer, { hook_event_name: "PostToolUse", ...call, tool_response: { stdout: "" } });
  console.log(`   ${command}: PreToolUse answered ${JSON.stringify(pre)}`);
}

step(5, "report: each receipt is verified with the agent's key, then the denials are listed");
const report = denyReport(configFile);
console.log(formatDenyReport(report).split("\n").map((l) => `   ${l}`).join("\n"));
if (report.wouldDeny.length !== 2 || report.unverified.length !== 0) throw new Error("the report should list two calls and no receipt that fails");

step(6, "the same policy in enforce mode: the hook text names what the rule forbids");
const enforcing = createSdkIssuer({ ...loadSdkConfig(configFile), mode: undefined });
for (const command of ["terraform destroy -auto-approve", "rm -rf ~"]) {
  const denied = await handleHookEvent(enforcing, { hook_event_name: "PreToolUse", session_id: "demo", tool_name: "Bash", tool_input: { command } });
  const text = denied.hookSpecificOutput?.permissionDecisionReason ?? "";
  console.log(`   ${command}: ${text}`);
  if (!text.startsWith("agent-custody denied this call: ")) throw new Error("the denial text does not name the reason");
}

console.log("\nOK");
