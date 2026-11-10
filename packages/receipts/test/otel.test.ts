// Export is additive: the collector gets a span per receipt with the receipt id as the trace id, and a collector
// that is down or refusing costs nothing but a line on stderr. The receipt is the evidence; the span is a pointer.
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, loadSdkConfig } from "../src/config.ts";
import { createGateway, RECEIPT_META_KEY } from "../src/gateway.ts";
import { otlpExporter, spanFor } from "../src/otel.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { buildFixture, buildSdkFixture } from "../scripts/fixture.ts";

function collector(status = 200): Promise<{ server: Server; url: string; received: { path: string; headers: Record<string, string | string[] | undefined>; body: any }[] }> {
  const received: { path: string; headers: Record<string, string | string[] | undefined>; body: any }[] = [];
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ path: req.url!, headers: req.headers, body: JSON.parse(body) });
      res.writeHead(status, { "content-type": "application/json" });
      res.end("{}");
    });
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, received })));
}

const attr = (span: any, key: string) => span.attributes.find((a: any) => a.key === key)?.value;

describe("OpenTelemetry export", () => {
  it("the gateway posts one span per receipt: trace id is the receipt id, attributes carry tool, status, decision, and log position", async () => {
    const c = await collector();
    process.env.TEST_OTEL_KEY = "otel-secret";
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-otel-")));
    const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
    cfg.otel = { url: c.url, headersEnv: { "x-api-key": "TEST_OTEL_KEY" }, serviceName: "support-agents" };
    cfg.precommit = ["stripe.refund"];
    writeFileSync(fx.configFile, JSON.stringify(cfg));
    const gw = await createGateway(loadConfig(fx.configFile));
    try {
      const ok = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      const denied = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5_000_000 } });
      // the fact lookup inside the refund is not a receipt of its own, so three receipts: refund, and the denial; plus none for lookups
      const ids = [ok, denied].map((r) => String(r._meta?.[RECEIPT_META_KEY]));
      expect(c.received.map((r) => r.path)).toEqual(["/v1/traces", "/v1/traces"]);
      expect(c.received[0]!.headers["x-api-key"]).toBe("otel-secret");
      const spans = c.received.map((r) => r.body.resourceSpans[0].scopeSpans[0].spans[0]);
      expect(spans.map((s) => s.traceId)).toEqual(ids.map((id) => id.replace(/-/g, "")));
      expect(c.received[0]!.body.resourceSpans[0].resource.attributes).toEqual([{ key: "service.name", value: { stringValue: "support-agents" } }]);
      expect(spans[0].name).toBe("stripe.refund");
      expect(attr(spans[0], "agent_custody.execution.status")).toEqual({ stringValue: "executed" });
      expect(attr(spans[0], "agent_custody.policy.decision")).toEqual({ stringValue: "allow" });
      expect(attr(spans[0], "agent_custody.issuer.kind")).toEqual({ stringValue: "gateway" });
      expect(attr(spans[0], "agent_custody.agent")).toEqual({ stringValue: "support-agent" });
      expect(attr(spans[0], "agent_custody.principal")).toEqual({ stringValue: "user_456" });
      expect(Number(attr(spans[0], "agent_custody.authorization.leaf_index").intValue)).toBeLessThan(Number(attr(spans[0], "agent_custody.log.leaf_index").intValue));
      expect(spans[0].status).toEqual({ code: 1 });
      expect(attr(spans[1], "agent_custody.execution.status")).toEqual({ stringValue: "denied" });
      expect(attr(spans[1], "agent_custody.policy.decision")).toEqual({ stringValue: "deny" });
    } finally {
      await gw.close();
      c.server.close();
    }
  });

  it("an exporter that throws does not fail the call or lose the receipt", async () => {
    const fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-otel-throw-")));
    let told = 0;
    const gw = await createGateway(loadConfig(fx.configFile), { exporter: { where: "test", async exported() { told++; throw new Error("exporter down"); } } });
    try {
      const ok = await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 2500 } });
      expect(ok.isError).toBeFalsy();
      expect(told).toBe(1);
      expect(existsSync(join(fx.receiptsDir, `${ok._meta?.[RECEIPT_META_KEY]}.json`))).toBe(true);
    } finally {
      await gw.close();
    }
  });

  it("the SDK issuer exports too, and a collector that refuses or is unreachable costs a warning, never the receipt", async () => {
    const refusing = await collector(500);
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-otel-sdk-"));
    const sfx = buildSdkFixture(dir, undefined, "otel-test");
    const cfg = JSON.parse(readFileSync(sfx.configFile, "utf8"));
    cfg.otel = { url: refusing.url };
    writeFileSync(sfx.configFile, JSON.stringify(cfg));
    const warnings: string[] = [];
    const orig = console.error;
    console.error = (m: string) => warnings.push(String(m));
    try {
      const issuer = createSdkIssuer(loadSdkConfig(sfx.configFile));
      const bundle = await issuer.record({ tool: "crm.lookup", args: { id: 1 } }, { status: "executed", result: { plan: "pro" } });
      expect(bundle.inclusion.leafIndex).toBe(0);
      expect(refusing.received).toHaveLength(1);
      expect(warnings.join("\n")).toMatch(/otel export of receipt .* refused by .*: 500/);
      // unreachable: the port is closed after this
      refusing.server.close();
      await new Promise((r) => setTimeout(r, 50));
      const again = await issuer.record({ tool: "crm.lookup", args: { id: 2 } }, { status: "failed", result: { error: "x" } });
      expect(again.inclusion.leafIndex).toBe(1);
      expect(warnings.join("\n")).toMatch(/otel export of receipt .* failed/);
    } finally {
      console.error = orig;
    }
  });

  it("a door receipt is a SERVER span; every other issuer stays a CLIENT span", () => {
    const base = { receiptId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", timestamp: "2026-09-08T10:00:00.000Z", issuer: { kind: "door" as const, keyid: "k", version: "0" }, principal: { id: null, provenance: "claimed" as const }, agent: { id: "a", provenance: "claimed" as const }, session: { id: null, toolUseId: null, provenance: "claimed" as const }, model: { id: null, provenance: "claimed" as const }, tool: { name: "GET /orders", provenance: "claimed" as const }, request: { args: {}, argsDigest: "d", provenance: "claimed" as const }, facts: {}, policy: null, execution: { status: "executed" as const, result: null, resultDigest: "x", provenance: "claimed" as const } };
    const bundle = { envelope: { payloadType: "", payload: "", signatures: [] }, treeHead: { payloadType: "", payload: "", signatures: [] }, inclusion: { leafIndex: 0, treeSize: 1, hashes: [] } };
    const kind = (issuerKind: string) => (spanFor({ ...base, issuer: { ...base.issuer, kind: issuerKind } } as any, bundle, "svc") as any).resourceSpans[0].scopeSpans[0].spans[0].kind;
    expect(kind("door")).toBe(2);
    for (const other of ["gateway", "sdk", "egress", "guardian"]) expect(kind(other)).toBe(3);
  });

  it("spanFor marks failures and errors as error status, and a missing header variable fails at startup", () => {
    const base = { receiptId: "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0", timestamp: "2026-09-08T10:00:00.000Z", issuer: { kind: "sdk" as const, keyid: "k", version: "0" }, principal: { id: null, provenance: "claimed" as const }, agent: { id: "a", provenance: "claimed" as const }, session: { id: null, toolUseId: null, provenance: "claimed" as const }, model: { id: null, provenance: "claimed" as const }, tool: { name: "t", provenance: "claimed" as const }, request: { args: {}, argsDigest: "d", provenance: "claimed" as const }, facts: {}, policy: null };
    const bundle = { envelope: { payloadType: "", payload: "", signatures: [] }, treeHead: { payloadType: "", payload: "", signatures: [] }, inclusion: { leafIndex: 3, treeSize: 4, hashes: [] } };
    const span = (execution: any) => (spanFor({ ...base, execution }, bundle, "svc") as any).resourceSpans[0].scopeSpans[0].spans[0];
    expect(span({ status: "error", error: "boom", provenance: "claimed" }).status).toEqual({ code: 2, message: "boom" });
    expect(span({ status: "failed", result: null, resultDigest: "x", provenance: "claimed" }).status).toEqual({ code: 2, message: "the upstream reported failure" });
    expect(span({ status: "withheld", reason: "log down", provenance: "observed" }).status).toEqual({ code: 1 });
    expect(span({ status: "executed", result: null, resultDigest: "x", provenance: "claimed" }).traceId).toBe("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    expect(() => otlpExporter({ url: "http://127.0.0.1:1", headersEnv: { authorization: "NOT_SET_ANYWHERE_OTEL" } })).toThrow(/NOT_SET_ANYWHERE_OTEL/);
  });
});
