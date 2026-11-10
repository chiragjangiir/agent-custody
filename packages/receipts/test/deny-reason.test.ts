// A deny reason goes into the model's context. When the denial receipt cannot be issued, the reason says why by
// failure class only: a log URL can carry credentials and the log's answer can carry anything, and neither may reach
// the model. The operator still gets the full error, on stderr.
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { loadSdkConfig } from "../src/config.ts";
import { httpLog } from "../src/log-sink.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { handleHookEvent } from "../src/sdk/claude.ts";
import { deepseekHarnessHooks } from "../src/sdk/deepseek-harness.ts";
import { createSdkIssuer, type SdkIssuer } from "../src/sdk/index.ts";
import { wrapTools } from "../src/sdk/openai-agents.ts";
import { openclawHooks } from "../src/sdk/openclaw.ts";
import { connectSigner } from "../src/signer.ts";
import { buildSdkFixture } from "../scripts/fixture.ts";

const SECRETS = ["admin", "s3cr3t", "t0k3n", "log.example", "upstream said"];
const DENIED = { amount: 999999 };

const adapters: Record<string, (issuer: SdkIssuer) => Promise<string>> = {
  claude: async (issuer) => (await handleHookEvent(issuer, { hook_event_name: "PreToolUse", tool_name: "stripe.refund", tool_input: DENIED })).hookSpecificOutput!.permissionDecisionReason!,
  openclaw: async (issuer) => (await openclawHooks(issuer).before_tool_call({ toolName: "stripe.refund", params: DENIED }))!.blockReason,
  "deepseek-harness": async (issuer) => {
    const d = await deepseekHarnessHooks(issuer).preExecute({ name: "stripe.refund", arguments: DENIED }, async () => ({ kind: "allow" }));
    return d.kind === "deny" ? d.reason : `not denied: ${d.kind}`;
  },
  "openai-agents": async (issuer) => String(await wrapTools(issuer, [{ name: "stripe.refund", invoke: async (_ctx: unknown, _input: string) => "ran" }])[0]!.invoke(null, JSON.stringify(DENIED))),
};

const issuer = createSdkIssuer(loadSdkConfig(buildSdkFixture(mkdtempSync(join(tmpdir(), "deny-reason-"))).configFile));
// the remote log sink, refusing the append the way a real log does, with a URL that carries credentials
const refusingLog = httpLog("https://admin:s3cr3t@log.example/?token=t0k3n", { fetch: async () => new Response("upstream said t0k3n", { status: 400 }) });
// a remote signer that serves its key but refuses to sign, at a URL that carries credentials
const refusingSigner = await connectSigner("https://admin:s3cr3t@signer.example/?token=t0k3n", {
  fetch: async (u) => (String(u).includes("/keys") ? Response.json({ keys: [{ keyid: "k" }] }) : new Response("upstream said t0k3n", { status: 401 })),
});
const failures: Record<string, { record: SdkIssuer["record"]; why: string; logged: string; notLogged: string[] }> = {
  "the log refuses the receipt": { record: () => refusingLog.append("{}") as unknown as Promise<ReceiptBundle>, why: "the receipt could not be recorded", logged: "log https://log.example/ refused the append", notLogged: ["admin", "s3cr3t", "token="] },
  "the signer refuses to sign": { record: () => refusingSigner.sign("x", {}) as unknown as Promise<ReceiptBundle>, why: "the receipt could not be recorded", logged: "signer https://signer.example/ refused to sign: 401", notLogged: ["admin", "s3cr3t", "token="] },
  "the receipt cannot be read": { record: async () => ({ envelope: { payload: Buffer.from("s3cr3t").toString("base64") } }) as unknown as ReceiptBundle, why: "the receipt could not be recorded", logged: "agent-custody: no receipt:", notLogged: [] },
};

afterEach(() => vi.restoreAllMocks());

describe("a deny reason without a receipt", () => {
  for (const [adapter, reasonOf] of Object.entries(adapters)) {
    for (const [failure, { record, why, logged, notLogged }] of Object.entries(failures)) {
      it(`${adapter}: ${failure}: names the failure, keeps secrets out, and reports the error on stderr`, async () => {
        const stderr = vi.spyOn(console, "error").mockImplementation(() => {});
        const reason = await reasonOf({ ...issuer, record });
        expect(reason).toMatch(new RegExp(`no permit policy matched \\(no receipt: ${why}\\)$`));
        expect(SECRETS.filter((s) => reason.includes(s))).toEqual([]);
        const err = stderr.mock.calls.flat().join("\n");
        expect(err).toContain(logged);
        expect(notLogged.filter((s) => err.includes(s))).toEqual([]); // a log or signer URL is shown without its credentials
      });
    }
  }
});
