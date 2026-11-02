import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { loadSdkConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, writeKeyPair } from "../src/crypto.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { handleHookEvent } from "../src/sdk/claude.ts";
import { createSdkIssuer, PolicyDeniedError, receiptIdOf, type SdkIssuer } from "../src/sdk/index.ts";
import { verifyBundle, type VerifyOptions } from "../src/verify.ts";

const POLICY = `permit(principal, action == Action::"customer.lookup", resource);
permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 };
`;

let dir: string;
let configFile: string;
let sdk: SdkIssuer;
let opts: VerifyOptions;

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const bundleFor = (id: string) => JSON.parse(readFileSync(join(dir, "receipts", `${id}.json`), "utf8")) as ReceiptBundle;
const failing = (r: ReturnType<typeof verifyBundle>) => r.checks.filter((c) => !c.ok).map((c) => c.name);

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), "agent-custody-sdk-"));
  const app = writeKeyPair(generateKeyPair(), join(dir, "keys"), "app");
  writeFileSync(join(dir, "policy.cedar"), POLICY);
  configFile = join(dir, "sdk.json");
  writeFileSync(
    configFile,
    JSON.stringify({ agentId: "billing-bot", principalId: "user_456", identity: { keyFile: "keys/app.key" }, policyFile: "policy.cedar", receiptsDir: "receipts", logFile: "log.jsonl", framework: "test" }),
  );
  sdk = createSdkIssuer(loadSdkConfig(configFile));
  opts = { issuerKeys: [loadPublicKey(app.pubFile)], principalKeys: [], logFile: join(dir, "log.jsonl") };
});

describe("sdk wrap()", () => {
  it("runs an allowed tool and issues a receipt that verifies, labelled sdk and claimed throughout", async () => {
    const refund = sdk.wrap("stripe.refund", async (a: { amount: number }) => ({ refund_id: "re_1", amount: a.amount }));
    await expect(refund({ amount: 500 })).resolves.toEqual({ refund_id: "re_1", amount: 500 });
    const files = readFileSync(join(dir, "log.jsonl"), "utf8").trim().split("\n");
    const bundle = JSON.parse(JSON.parse(files.at(-1)!)) as ReceiptBundle["envelope"];
    const st = JSON.parse(Buffer.from(bundle.payload, "base64").toString()) as ReceiptStatement;
    const full = bundleFor(st.predicate.receiptId);
    expect(st.predicate.issuer).toMatchObject({ kind: "sdk", framework: "test" });
    expect(st.predicate.execution.status).toBe("executed");
    expect(st.predicate.principal).toEqual({ id: "user_456", provenance: "claimed" });
    expect(st.predicate.delegation).toBeUndefined();
    for (const f of [st.predicate.agent, st.predicate.tool, st.predicate.request, st.predicate.execution, st.predicate.policy!]) expect(f.provenance).toBe("claimed");
    const v = verifyBundle(full, opts);
    expect(failing(v)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toContain("principal is claimed, not attested");
  });

  it("denies by policy before running the tool, issues a denial receipt, and throws with its id", async () => {
    let ran = false;
    const refund = sdk.wrap("stripe.refund", async (_a: { amount: number }) => {
      ran = true;
      return "never";
    });
    const err = await refund({ amount: 500000 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(PolicyDeniedError);
    expect(ran).toBe(false);
    const bundle = bundleFor((err as PolicyDeniedError).receiptId);
    expect(decode(bundle).predicate.execution.status).toBe("denied");
    expect(failing(verifyBundle(bundle, opts))).toEqual([]);
  });

  it("records a thrown error as an error receipt and rethrows", async () => {
    const lookup = sdk.wrap("customer.lookup", async (_a: { id: string }) => {
      throw new Error("upstream down");
    });
    await expect(lookup({ id: "c1" })).rejects.toThrow("upstream down");
    const last = decode(bundleFor(lastReceiptId()));
    expect(last.predicate.execution).toMatchObject({ status: "error", error: "upstream down" });
  });

  it("without a policy, wrap() records but never denies", async () => {
    const noPolicy = createSdkIssuer({ ...loadSdkConfig(configFile), policyFile: undefined });
    const payout = noPolicy.wrap("stripe.payout", async (a: { amount: number }) => a.amount);
    await expect(payout({ amount: 10 ** 9 })).resolves.toBe(10 ** 9);
    expect(decode(bundleFor(lastReceiptId())).predicate.policy).toBeNull();
  });
});

describe("Claude Code hook handler", () => {
  it("PreToolUse: denies an over-limit call with the documented JSON and a receipt id", async () => {
    const out = await handleHookEvent(sdk, { hook_event_name: "PreToolUse", session_id: "s1", tool_use_id: "t1", tool_name: "stripe.refund", tool_input: { amount: 999999 } });
    expect(out.hookSpecificOutput?.permissionDecision).toBe("deny");
    const id = /receipt ([0-9a-f-]{36})/.exec(out.hookSpecificOutput!.permissionDecisionReason!)![1]!;
    const st = decode(bundleFor(id));
    expect(st.predicate.session).toEqual({ id: "s1", toolUseId: "t1", provenance: "claimed" });
    expect(st.predicate.execution.status).toBe("denied");
  });

  it("PreToolUse: still denies when the receipt cannot be recorded", async () => {
    const broken = { ...sdk, record: () => Promise.reject(new Error("log unreachable")) };
    const out = await handleHookEvent(broken, { hook_event_name: "PreToolUse", tool_name: "stripe.refund", tool_input: { amount: 999999 } });
    expect(out.hookSpecificOutput?.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput?.permissionDecisionReason).toContain("no receipt: log unreachable");
  });

  it("PreToolUse: still denies when the receipt id cannot be read from the recorded bundle", async () => {
    const malformed = { ...sdk, record: () => Promise.resolve({ envelope: { payload: "bm90IGpzb24=" } } as unknown as Awaited<ReturnType<typeof sdk.record>>) };
    const out = await handleHookEvent(malformed, { hook_event_name: "PreToolUse", tool_name: "stripe.refund", tool_input: { amount: 999999 } });
    expect(out.hookSpecificOutput?.permissionDecision).toBe("deny");
    expect(out.hookSpecificOutput?.permissionDecisionReason).toContain("no receipt:");
  });

  it("PreToolUse: on allow returns no decision, so the host's own permission flow still applies", async () => {
    expect(await handleHookEvent(sdk, { hook_event_name: "PreToolUse", tool_name: "stripe.refund", tool_input: { amount: 1 } })).toEqual({});
  });

  it("PostToolUse: issues an executed receipt carrying the tool response", async () => {
    await handleHookEvent(sdk, { hook_event_name: "PostToolUse", tool_name: "customer.lookup", tool_input: { id: "c1" }, tool_response: { verified: true } });
    const st = decode(bundleFor(lastReceiptId()));
    expect(st.predicate.execution).toMatchObject({ status: "executed", result: { verified: true } });
    expect(st.predicate.tool.name).toBe("customer.lookup");
  });

  it("CLI `hook` reads the event from stdin and prints the decision", () => {
    const r = spawnSync(process.execPath, [resolve("src/cli.ts"), "hook"], {
      input: JSON.stringify({ hook_event_name: "PreToolUse", tool_name: "stripe.refund", tool_input: { amount: 999999 } }),
      env: { ...process.env, AGENT_CUSTODY_CONFIG: configFile },
      encoding: "utf8",
    });
    expect(r.status, r.stderr).toBe(0);
    expect(JSON.parse(r.stdout).hookSpecificOutput.permissionDecision).toBe("deny");
  });
});

function lastReceiptId(): string {
  const lines = readFileSync(join(dir, "log.jsonl"), "utf8").trim().split("\n");
  const env = JSON.parse(JSON.parse(lines.at(-1)!)) as ReceiptBundle["envelope"];
  return receiptIdOf({ envelope: env } as ReceiptBundle);
}
