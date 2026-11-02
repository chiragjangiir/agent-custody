// Aspect: a LangChain agent under custody, end to end. Source: src/sdk/index.ts, src/sdk/langchain.ts, src/verify.ts
// Run:    node examples/23-langchain-kb-agent.ts
//
// A docs agent that reads and writes a git-style knowledge base: the kind of agent that keeps runbooks and notes in a
// repository for a team. It may read anything and write under notes/; a policy says so. The agent is a real LangChain
// `createAgent` loop; the model is LangChain's own scripted fake, so this runs with no API key and the same way every
// time. Every tool call becomes a signed receipt, a write outside notes/ is refused before it happens, and at the end
// each receipt is verified with the application's public key, as a stranger would verify it.
import { BaseChatModel } from "@langchain/core/language_models/chat_models";
import { AIMessage, HumanMessage, ToolMessage, type BaseMessage } from "@langchain/core/messages";
import type { ChatResult } from "@langchain/core/outputs";
import { tool } from "@langchain/core/tools";
import { createAgent } from "langchain";
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import { loadSdkConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import { createSdkIssuer, PolicyDeniedError } from "../src/sdk/index.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { out, step } from "./_out.ts";

// ---- the working directory: a key for the agent's process, the policy, the SDK config ----
const dir = out("23-langchain-kb-agent");
mkdirSync(join(dir, "keys"), { recursive: true });
const app = writeKeyPair(generateKeyPair(), join(dir, "keys"), "docs-agent");
const POLICY = `// The docs agent may read any page.
permit(principal, action == Action::"kb.read", resource);

// It may write only under notes/, and only when it says which page the note came from.
permit(principal, action == Action::"kb.write", resource)
when { context.args.path like "notes/*" && context.args has source };
`;
writeFileSync(join(dir, "policy.cedar"), POLICY);
writeFileSync(join(dir, "sdk.json"), JSON.stringify({ agentId: "docs-agent", principalId: "eng-lead@example.com", identity: { keyFile: "keys/docs-agent.key" }, policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl", framework: "langchain" }, null, 2));
const issuer = createSdkIssuer(loadSdkConfig(join(dir, "sdk.json")));

// ---- the knowledge base: a few markdown pages, in memory here; GitKB, a git repo, or a wiki in life ----
const kb = new Map<string, string>([
  ["runbooks/incident-42.md", "# Incident 42\nThe payment webhook queue backed up for 40 minutes. Root cause: a retry loop with no backoff. Fix: exponential backoff, max 5 retries."],
  ["runbooks/deploy.md", "# Deploy\n1. Tag the release. 2. Run the migration. 3. Roll the services."],
]);

// ---- tools under custody: decide, run, record; a denial is returned as the tool's result so the model sees why ----
function custody<A extends Record<string, unknown>, R>(name: string, fn: (args: A) => R | Promise<R>) {
  const wrapped = issuer.wrap(name, fn);
  return async (args: A): Promise<R | string> => {
    try {
      return await wrapped(args);
    } catch (e) {
      if (e instanceof PolicyDeniedError) return `Denied by policy: ${e.reason} (receipt ${e.receiptId})`;
      throw e;
    }
  };
}
const kbRead = tool(custody("kb.read", async (a: { path: string }) => kb.get(a.path) ?? `no page at ${a.path}`), { name: "kb.read", description: "Read a page of the knowledge base by path.", schema: z.object({ path: z.string() }) });
const kbWrite = tool(custody("kb.write", async (a: { path: string; content: string; source?: string }) => { kb.set(a.path, a.content); return `wrote ${a.path} (${a.content.length} chars)`; }), { name: "kb.write", description: "Write a page. Notes go under notes/ and must cite the source page.", schema: z.object({ path: z.string(), content: z.string(), source: z.string().optional() }) });

// ---- the agent: LangChain's createAgent over a scripted model, so the run is the same every time and needs no key.
// The script is what a real model does with this prompt: read the runbook, overreach, then do the job properly. ----
class ScriptedModel extends BaseChatModel {
  private turn = 0;
  private readonly script: AIMessage[];
  constructor(script: AIMessage[]) { super({}); this.script = script; } // no parameter properties: plain Node type stripping
  _llmType() { return "scripted"; }
  bindTools() { return this; }
  async _generate(_messages: BaseMessage[]): Promise<ChatResult> {
    const message = this.script[Math.min(this.turn++, this.script.length - 1)]!;
    return { generations: [{ text: String(message.content), message }] };
  }
}
const model = new ScriptedModel([
  new AIMessage({ content: "", tool_calls: [{ id: "call_1", name: "kb.read", args: { path: "runbooks/incident-42.md" } }] }),
  new AIMessage({ content: "", tool_calls: [{ id: "call_2", name: "kb.write", args: { path: "runbooks/deploy.md", content: "# Deploy\n1. Tag. 2. Roll. (migration step removed)" } }] }),
  new AIMessage({ content: "", tool_calls: [{ id: "call_3", name: "kb.write", args: { path: "notes/incident-42-summary.md", content: "Incident 42: webhook queue backed up 40 min; retry loop without backoff; fixed with exponential backoff.", source: "runbooks/incident-42.md" } }] }),
  new AIMessage({ content: "Done. I summarised incident 42 into notes/incident-42-summary.md. My edit to runbooks/deploy.md was refused by policy, so the runbook is unchanged." }),
]);
const agent = createAgent({ model: model as never, tools: [kbRead, kbWrite] });

step(1, "the agent reads a runbook, tries to edit a runbook, then writes a note that cites its source");
const result = await agent.invoke({ messages: [new HumanMessage("Summarise incident 42 into a note, and tidy the deploy runbook while you are there.")] });
for (const m of result.messages) {
  if (m instanceof AIMessage && m.tool_calls?.length) for (const c of m.tool_calls) console.log(`   agent -> ${c.name} ${JSON.stringify(c.args).slice(0, 90)}`);
  if (m instanceof ToolMessage) console.log(`   tool  <- ${String(m.content).slice(0, 110)}`);
}
console.log(`   agent: ${String(result.messages.at(-1)?.content)}`);
if (kb.get("runbooks/deploy.md")?.includes("migration step removed")) throw new Error("the runbook was changed; the denial did not hold");

step(2, "three receipts, one per tool call, signed by the agent's key, each a leaf in the Merkle log");
const receiptsDir = join(dir, "receipts");
const files = readdirSync(receiptsDir).filter((f) => f.endsWith(".json")).sort();
console.log(`   ${files.length} receipts in ${receiptsDir}`);

step(3, "verify each one the way a stranger would: the public key and a copy of the log, nothing else");
const key = loadPublicKey(app.pubFile);
const seen: string[] = [];
for (const f of files) {
  const bundle = JSON.parse(readFileSync(join(receiptsDir, f), "utf8"));
  const r = await verifyBundle(bundle, { issuerKeys: [key], principalKeys: [], logFile: join(dir, "log.jsonl") });
  const p = r.statement!.predicate;
  seen.push(`${p.tool.name}:${p.execution.status}`);
  console.log(`   ${r.ok ? "VERIFIED" : "FAILED  "} ${p.tool.name.padEnd(9)} ${p.execution.status.padEnd(9)} ${JSON.stringify(p.request.args).slice(0, 70)}`);
  if (!r.ok) throw new Error(`${f} does not verify`);
}
const denied = files.find((f) => JSON.parse(Buffer.from(JSON.parse(readFileSync(join(receiptsDir, f), "utf8")).envelope.payload, "base64").toString()).predicate.execution.status === "denied");
if (!denied || seen.sort().join(",") !== "kb.read:executed,kb.write:denied,kb.write:executed") throw new Error(`unexpected receipts: ${seen.join(",")}`);

step(4, "the full report for the refused write, the one an auditor asks about");
console.log(formatReport(await verifyBundle(JSON.parse(readFileSync(join(receiptsDir, denied), "utf8")), { issuerKeys: [key], principalKeys: [], logFile: join(dir, "log.jsonl") })).split("\n").map((l) => "   " + l).join("\n"));

step(5, "the same from the shell, or drop the file on https://agent-custody.dev/verify");
console.log(`   npx @agent-custody/receipts verify ${join(receiptsDir, denied)} --issuer-key ${app.pubFile} --log ${join(dir, "log.jsonl")}`);

console.log("\nOK");
