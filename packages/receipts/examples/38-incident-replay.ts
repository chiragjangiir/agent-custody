// Aspect: an incident replay. Source: src/sdk/claude.ts, src/claude-init.ts, templates/claude-code.cedar, src/verify.ts
// Run:    node examples/38-incident-replay.ts
//
// A coding agent runs `terraform destroy` or `rm -rf ~`. The starter deny set, in enforce mode, stops the call before it runs.
// The example makes the same setup as `init claude-code --enforce`, in a temporary home and a temporary project.
// A script plays the Claude Code side: it runs the hook command from settings.json for each event, with the event on stdin.
// No model and no network. No command of the script runs: a stub records which calls the hook lets through.
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { initClaudeCode } from "../src/claude-init.ts";
import { generateKeyPair, loadPublicKey } from "../src/crypto.ts";
import { policyRules } from "../src/policy.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { out, step } from "./_out.ts";

const base = out("38-incident-replay");
const home = join(base, "home");
const project = join(base, "project");
mkdirSync(home, { recursive: true });
mkdirSync(project, { recursive: true });

step(1, "set up the hooks in enforce mode, in a temporary home and a temporary project");
const { configFile, settingsFile, hookCommand, dir } = initClaudeCode({
  cliPath: resolve(import.meta.dirname, "..", "src", "cli.ts"),
  home,
  cwd: project,
  enforce: true,
  print: () => {},
});
const settings = JSON.parse(readFileSync(settingsFile, "utf8"));
console.log(`   events: ${Object.keys(settings.hooks).join(", ")}`);
console.log(`   mode: ${JSON.parse(readFileSync(configFile, "utf8")).mode ?? "enforce"}`);

// What Claude Code does: run the hook command with the event on stdin, and read the answer on stdout.
function claudeCodeCallsHook(event: Record<string, unknown>): { permissionDecision?: string; permissionDecisionReason?: string } {
  const r = spawnSync(hookCommand, { shell: true, input: JSON.stringify(event), encoding: "utf8" });
  if (r.status !== 0) throw new Error(`the hook command failed: ${r.stderr}`);
  return JSON.parse(r.stdout).hookSpecificOutput ?? {};
}

const rules = policyRules(readFileSync(join(dir, "policy.cedar"), "utf8"));
const ran: string[] = [];
const denials: { command: string; receiptId: string }[] = [];
function agentRuns(command: string, toolUseId: string) {
  const call = { session_id: "replay", tool_use_id: toolUseId, tool_name: "Bash", tool_input: { command } };
  const pre = claudeCodeCallsHook({ hook_event_name: "PreToolUse", ...call });
  if (pre.permissionDecision === "deny") {
    console.log("   denied before it runs. Claude Code shows the agent this text:");
    console.log(`   ${pre.permissionDecisionReason}`);
    const reason = pre.permissionDecisionReason ?? "";
    denials.push({ command, receiptId: /receipt ([0-9a-f-]+)\)$/.exec(reason)![1]! });
    const rule = rules[Number(/rule policy(\d+)/.exec(reason)![1])]!;
    const shown = rule.replace(/^(?:\s*@\w+\s*\("(?:[^"\\]|\\.)*"\))+\s*/, "").replace(/\s+/g, " ").trim();
    console.log(`   that rule, in policy.cedar: ${shown.length > 200 ? `${shown.slice(0, 200)} ...` : shown}`);
    return;
  }
  ran.push(command);
  claudeCodeCallsHook({ hook_event_name: "PostToolUse", ...call, tool_response: { stdout: "(the command ran)" } });
  console.log("   the hook lets the call through, the command runs, and the hook records an executed receipt");
}

step(2, "the agent runs: terraform plan");
agentRuns("terraform plan", "t1");

step(3, "the agent runs: terraform destroy -auto-approve");
agentRuns("terraform destroy -auto-approve", "t2");

step(4, "the agent runs: rm -rf ~");
agentRuns("rm -rf ~", "t3");

if (ran.join() !== "terraform plan") throw new Error(`only terraform plan should run, but these ran: ${ran.join(" | ")}`);
if (denials.length !== 2) throw new Error("both destructive calls should be denied");

step(5, "a reviewer verifies offline: they hold the agent's public key and the receipt files, and nothing else");
const reviewer = join(base, "reviewer");
mkdirSync(reviewer);
copyFileSync(join(dir, "keys", "claude-code.pub"), join(reviewer, "agent.pub"));
const receiptsDir = join(dir, "receipts");
for (const file of readdirSync(receiptsDir)) copyFileSync(join(receiptsDir, file), join(reviewer, file));
const agentKey = loadPublicKey(join(reviewer, "agent.pub"));
const read = (id: string) => JSON.parse(readFileSync(join(reviewer, `${id}.json`), "utf8")) as ReceiptBundle;

const summaries = readdirSync(reviewer).filter((f) => f.endsWith(".json")).map((file) => {
  const result = verifyBundle(JSON.parse(readFileSync(join(reviewer, file), "utf8")) as ReceiptBundle, { issuerKeys: [agentKey], principalKeys: [] });
  if (!result.ok || !result.statement) throw new Error(`${file} does not verify`);
  const p = result.statement.predicate;
  return { p, line: `   ${p.receiptId}  VERIFIED (${result.checks.length} checks)  ${p.execution.status.padEnd(8)}  decision ${p.policy?.decision}  ${(p.request.args as { command: string }).command}` };
}).sort((a, b) => (a.p.timestamp < b.p.timestamp ? -1 : 1));
for (const s of summaries) console.log(s.line);
const statuses = summaries.map((s) => `${s.p.execution.status}/${s.p.policy?.decision}${s.p.policy?.enforced === false ? "/observe" : ""}`).join(" ");
if (statuses !== "executed/allow denied/deny denied/deny") throw new Error(`unexpected receipts: ${statuses}`);


step(6, "the same receipt checked against a key that is not the agent's does not verify");
const stranger = generateKeyPair();
const bad = verifyBundle(read(denials[0]!.receiptId), { issuerKeys: [{ publicKey: stranger.publicKey, keyid: stranger.keyid }], principalKeys: [] });
if (bad.ok) throw new Error("a receipt must not verify with a stranger's key");
console.log(`   ${bad.checks.find((c) => !c.ok)?.name}: FAIL. RESULT: NOT VERIFIED`);

console.log("\nOK");
