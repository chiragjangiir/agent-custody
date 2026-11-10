// An agent delegating to an agent over A2A gets what a tool call gets: scope, policy on facts the gateway fetched
// itself (the agent card), a receipt either way. Two front doors: the remote agent as an MCP tool, and the gateway
// speaking A2A itself in front of the remote agent, in both the 1.0 and the 0.3 wire formats. The remote agents
// are node:http stand-ins; nothing leaves the machine.
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { A2A_CARD_PATH, A2A_RECEIPT_METADATA_KEY, a2aUpstream, fetchAgentCard, finalOfStream, parseSse, serveA2a, textOf, type RunningA2aServer } from "../src/a2a.ts";
import { loadConfig } from "../src/config.ts";
import { loadPrivateKey, loadPublicKey, type Envelope } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { createGateway, createGatewayHost, RECEIPT_META_KEY, type Gateway, type GatewayHost } from "../src/gateway.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildFixture, type Fixture } from "../scripts/fixture.ts";

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;

const POLICY = `// The card is a fact the gateway fetched itself: the delegate must be the document agent, with its summarise skill.
permit(principal, action == Action::"docs.card", resource);
permit(principal, action == Action::"docs.send", resource)
when {
  context.facts.card.name == "document_agent" &&
  !(context.args.text like "*privileged*")
};
`;

type Seen = { method: string; path: string; body: unknown; headers: Record<string, string | string[] | undefined> };

/** A stand-in document agent. `version` picks the wire format it speaks: 1.0 (SendMessage, ROLE_USER) or 0.3 (message/send, kind). */
function fakeAgent(version: "1.0" | "0.3"): Promise<{ server: Server; url: string; seen: Seen[] }> {
  const seen: Seen[] = [];
  const legacy = version === "0.3";
  let url = "";
  const card = () =>
    legacy
      ? { name: "document_agent", description: "Reads and summarises engagement documents.", url, protocolVersion: "0.3.0", version: "1", capabilities: { streaming: true }, defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"], skills: [{ id: "summarise", name: "Summarise", description: "Summarise documents", tags: ["docs"] }], signatures: [{ protected: "e30", signature: "AA" }] }
      : { name: "document_agent", description: "Reads and summarises engagement documents.", supportedInterfaces: [{ url, protocolBinding: "JSONRPC", protocolVersion: "1.0" }], version: "1", capabilities: { streaming: true }, defaultInputModes: ["text/plain"], defaultOutputModes: ["text/plain"], skills: [{ id: "summarise", name: "Summarise", description: "Summarise documents", tags: ["docs"] }], signatures: [{ protected: "e30", signature: "AA" }] };
  const text = (parts: { text?: string }[]) => parts.map((p) => p.text ?? "").join("");
  const answer = (s: string) => (legacy ? { kind: "text", text: s } : { text: s });
  const task = (id: string, contextId: string, state: string, out: string) =>
    legacy
      ? { kind: "task", id, contextId, status: { state, timestamp: "2026-10-10T00:00:00Z" }, artifacts: [{ artifactId: "a1", parts: [answer(out)] }] }
      : { id, contextId, status: { state: `TASK_STATE_${state.toUpperCase()}`, timestamp: "2026-10-10T00:00:00Z" }, artifacts: [{ artifactId: "a1", parts: [answer(out)] }] };
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const parsed = body ? JSON.parse(body) : null;
      seen.push({ method: req.method!, path: req.url!, body: parsed, headers: req.headers });
      const json = (status: number, v: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(v));
      };
      if (req.method === "GET" && req.url === A2A_CARD_PATH) return json(200, card());
      if (req.method !== "POST") return json(404, { error: "no" });
      const { method, params, id } = parsed as { method: string; params: { message: { parts: { text?: string }[]; taskId?: string; contextId?: string } }; id: string };
      if (method === "GetTask" || method === "tasks/get") return json(200, { jsonrpc: "2.0", id, result: task((params as unknown as { id: string }).id, "ctx-1", "completed", "earlier") });
      const asked = text(params.message.parts);
      const out = `document agent says: ${asked}`;
      const taskId = params.message.taskId ?? "task-1";
      const contextId = params.message.contextId ?? "ctx-1";
      if (asked.includes("crash")) return json(200, { jsonrpc: "2.0", id, error: { code: -32603, message: "the document store is down" } });
      if (method === "SendMessage" || method === "message/send") return json(200, { jsonrpc: "2.0", id, result: task(taskId, contextId, "completed", out) });
      if (method === "SendStreamingMessage" || method === "message/stream") {
        res.writeHead(200, { "content-type": "text/event-stream" });
        const ev = (v: unknown) => res.write(`data: ${JSON.stringify({ jsonrpc: "2.0", id, result: v })}\r\n\r\n`);
        const submitted = legacy ? { ...task(taskId, contextId, "submitted", ""), artifacts: [] } : { ...task(taskId, contextId, "submitted", ""), artifacts: [] };
        ev(legacy ? submitted : { task: submitted });
        ev(legacy ? { kind: "status-update", taskId, contextId, status: { state: "working" } } : { statusUpdate: { taskId, contextId, status: { state: "TASK_STATE_WORKING" } } });
        ev(legacy ? { kind: "artifact-update", taskId, contextId, artifact: { artifactId: "a1", parts: [answer(out)] }, lastChunk: true } : { artifactUpdate: { taskId, contextId, artifact: { artifactId: "a1", parts: [answer(out)] }, lastChunk: true } });
        ev(legacy ? { kind: "status-update", taskId, contextId, status: { state: "completed" }, final: true } : { statusUpdate: { taskId, contextId, status: { state: "TASK_STATE_COMPLETED" } } });
        return res.end();
      }
      json(200, { jsonrpc: "2.0", id, error: { code: -32601, message: `no method ${method}` } });
    });
  });
  return new Promise((resolve) =>
    server.listen(0, "127.0.0.1", () => {
      url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
      resolve({ server, url, seen });
    }),
  );
}

/** A gateway working directory whose grant covers the delegation tools and whose policy decides on the card. */
function fixtureFor(agentUrl: string): Fixture & { principalKey: string } {
  const fx = buildFixture(mkdtempSync(join(tmpdir(), "agent-custody-a2a-")));
  const principalKey = join(fx.dir, "keys", "principal.key");
  const now = Date.now();
  const grant = createDelegation(loadPrivateKey(principalKey), { version: "0.1", principal: "engagement_lead_12", agent: "engagement-agent", scopes: ["docs.send", "docs.card"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() });
  writeFileSync(join(fx.dir, "grant.json"), JSON.stringify(grant));
  writeFileSync(join(fx.dir, "policy.cedar"), POLICY);
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
  cfg.upstream = { a2a: { url: agentUrl, prefix: "docs" } };
  cfg.facts = [{ name: "card", tool: "docs.card", args: {}, forTools: ["docs.send"] }];
  cfg.precommit = ["docs.send"];
  writeFileSync(fx.configFile, JSON.stringify(cfg));
  return { ...fx, principalKey };
}

const verifyAll = async (fx: Fixture, ids: string[]) => {
  const out: ReceiptStatement[] = [];
  for (const id of ids) {
    const bundle = JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
    const v = await verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
    expect(v.ok, v.checks.filter((c) => !c.ok).map((c) => `${c.name}: ${c.detail}`).join("; ")).toBe(true);
    out.push(decode(bundle));
  }
  return out;
};

describe("pieces", () => {
  it("reads text parts of either format, parses SSE, and folds a stream into its final task", () => {
    expect(textOf({ parts: [{ text: "a" }, { kind: "file", file: {} } as never, { text: "b" }] })).toBe("a\nb");
    const events = parseSse('data: {"jsonrpc":"2.0","id":1,"result":{"task":{"id":"t","status":{"state":"TASK_STATE_SUBMITTED"}}}}\r\n\r\nnot an event\n\ndata: {"jsonrpc":"2.0","id":1,"result":{"artifactUpdate":{"artifact":{"artifactId":"a"}}}}\n\ndata: {"jsonrpc":"2.0","id":1,"result":{"statusUpdate":{"status":{"state":"TASK_STATE_COMPLETED"}}}}\n\n');
    expect(events).toHaveLength(3);
    const final = finalOfStream(events.map((e) => (e as { result: unknown }).result)) as { id: string; status: { state: string }; artifacts: unknown[] };
    expect(final.id).toBe("t");
    expect(final.status.state).toBe("TASK_STATE_COMPLETED");
    expect(final.artifacts).toEqual([{ artifactId: "a" }]);
  });

  it("finds the card from a base URL or a card URL and refuses what is not a card", async () => {
    const agent = await fakeAgent("1.0");
    try {
      const fromBase = await fetchAgentCard(agent.url, {}, fetch, 5000);
      expect(fromBase.card.name).toBe("document_agent");
      expect(fromBase.endpoint).toBe(agent.url);
      expect(fromBase.legacy).toBe(false);
      const fromCard = await fetchAgentCard(`${agent.url}${A2A_CARD_PATH}`, {}, fetch, 5000);
      expect(fromCard.cardUrl).toBe(`${agent.url}${A2A_CARD_PATH}`);
      await expect(fetchAgentCard(`${agent.url}/nothing-here.json`, {}, fetch, 5000)).rejects.toThrow(/no agent card/);
    } finally {
      agent.server.close();
    }
  });
});

describe("a remote agent as an upstream, behind the MCP gateway", () => {
  let agent: Awaited<ReturnType<typeof fakeAgent>>;
  let fx: ReturnType<typeof fixtureFor>;
  let gw: Gateway;
  beforeAll(async () => {
    agent = await fakeAgent("1.0");
    fx = fixtureFor(agent.url);
    gw = await createGateway(loadConfig(fx.configFile));
  });
  afterAll(async () => {
    await gw.close();
    agent.server.close();
  });

  it("offers send and card, reads the card as a fact, delegates an allowed task, refuses one the policy denies, and both receipts verify", async () => {
    expect((await gw.listTools()).map((t) => t.name).sort()).toEqual(["docs.card", "docs.send"]);
    const ok = await gw.handleCall({ name: "docs.send", arguments: { text: "summarise the evidence for matter M-1042" } });
    expect(ok.isError).toBeFalsy();
    const answered = JSON.parse((ok.content[0] as { text: string }).text) as { status: { state: string }; artifacts: { parts: { text: string }[] }[] };
    expect(answered.status.state).toBe("TASK_STATE_COMPLETED");
    expect(answered.artifacts[0]!.parts[0]!.text).toContain("summarise the evidence");
    const sent = agent.seen.filter((s) => s.method === "POST");
    expect(sent).toHaveLength(1);
    expect((sent[0]!.body as { method: string; params: { message: { role: string; parts: { text: string }[] } } }).method).toBe("SendMessage");
    expect((sent[0]!.body as { params: { message: { role: string } } }).params.message.role).toBe("ROLE_USER");
    expect(sent[0]!.headers["a2a-version"]).toBe("1.0");

    const no = await gw.handleCall({ name: "docs.send", arguments: { text: "summarise the privileged memo for matter M-1042" } });
    expect(no.isError).toBe(true);
    expect((no.content[0] as { text: string }).text).toMatch(/Denied by policy/);
    expect(agent.seen.filter((s) => s.method === "POST")).toHaveLength(1);

    const [a, b] = await verifyAll(fx, [String(ok._meta![RECEIPT_META_KEY]), String(no._meta![RECEIPT_META_KEY])]);
    expect(a!.predicate.execution.status).toBe("executed");
    expect(a!.predicate.authorization).toBeDefined();
    expect((a!.predicate.facts.card!.value as { name: string; skills: { id: string }[] }).name).toBe("document_agent");
    expect(a!.predicate.request.args.text).toBe("summarise the evidence for matter M-1042");
    expect(b!.predicate.execution.status).toBe("denied");
  });

  it("records a delegate that errored as failed, not as a refusal", async () => {
    const r = await gw.handleCall({ name: "docs.send", arguments: { text: "summarise and crash" } });
    expect(r.isError).toBe(true);
    expect((r.content[0] as { text: string }).text).toContain("document store is down");
    const [s] = await verifyAll(fx, [String(r._meta![RECEIPT_META_KEY])]);
    expect(s!.predicate.execution.status).toBe("failed");
  });
});

describe("the gateway as an A2A agent in front of a 1.0 agent", () => {
  let agent: Awaited<ReturnType<typeof fakeAgent>>;
  let fx: ReturnType<typeof fixtureFor>;
  let host: GatewayHost;
  let proxy: RunningA2aServer;
  const rpc = async (method: string, params: unknown, headers: Record<string, string> = {}) => {
    const res = await fetch(proxy.url, { method: "POST", headers: { "content-type": "application/json", "a2a-version": "1.0", ...headers }, body: JSON.stringify({ jsonrpc: "2.0", id: "r1", method, params }) });
    return { status: res.status, type: res.headers.get("content-type") ?? "", text: await res.text() };
  };
  const message = (text: string) => ({ message: { messageId: "m1", role: "ROLE_USER", parts: [{ text }] }, configuration: {} });
  beforeAll(async () => {
    agent = await fakeAgent("1.0");
    fx = fixtureFor(agent.url);
    const cfg = loadConfig(fx.configFile);
    host = await createGatewayHost(cfg);
    proxy = await serveA2a(host, (cfg.upstream as { a2a: Parameters<typeof serveA2a>[1] }).a2a, { port: 0, grant: JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope, log: () => {} });
  });
  afterAll(async () => {
    await proxy.close();
    await host.close();
    agent.server.close();
  });

  it("serves the agent card with its own address and without the signatures it invalidated", async () => {
    const card = (await (await fetch(`${proxy.url}${A2A_CARD_PATH}`)).json()) as { name: string; supportedInterfaces: { url: string; protocolBinding: string }[]; signatures?: unknown; skills: unknown[] };
    expect(card.name).toBe("document_agent");
    expect(card.supportedInterfaces).toEqual([{ url: proxy.url, protocolBinding: "JSONRPC", protocolVersion: "1.0" }]);
    expect(card.signatures).toBeUndefined();
    expect(card.skills).toHaveLength(1);
  });

  it("answers SendMessage with the delegate's task carrying the receipt id, and a refused one as a rejected task that never reached the delegate", async () => {
    const ok = await rpc("SendMessage", message("summarise the evidence for matter M-1042"));
    expect(ok.status).toBe(200);
    const okBody = JSON.parse(ok.text) as { id: string; result: { status: { state: string }; metadata: Record<string, string>; artifacts: { parts: { text: string }[] }[] } };
    expect(okBody.id).toBe("r1");
    expect(okBody.result.status.state).toBe("TASK_STATE_COMPLETED");
    expect(okBody.result.artifacts[0]!.parts[0]!.text).toContain("document agent says");
    const okReceipt = okBody.result.metadata[A2A_RECEIPT_METADATA_KEY]!;
    expect(okReceipt).toMatch(/^[0-9a-f-]{36}$/);
    const before = agent.seen.filter((s) => s.method === "POST").length;

    const no = await rpc("SendMessage", message("summarise the privileged memo"));
    const noBody = JSON.parse(no.text) as { result: { status: { state: string; message: { parts: { text: string }[] } }; metadata: Record<string, string> } };
    expect(noBody.result.status.state).toBe("TASK_STATE_REJECTED");
    expect(noBody.result.status.message.parts[0]!.text).toMatch(/no permit policy matched/);
    expect(agent.seen.filter((s) => s.method === "POST")).toHaveLength(before);

    const [a, b] = await verifyAll(fx, [okReceipt, noBody.result.metadata[A2A_RECEIPT_METADATA_KEY]!]);
    expect(a!.predicate.execution.status).toBe("executed");
    expect(a!.predicate.tool.name).toBe("docs.send");
    expect(a!.predicate.request.args.method).toBe("SendMessage");
    expect(b!.predicate.execution.status).toBe("denied");
  });

  it("relays a streamed delegation as the events the delegate produced, each naming the receipt, and streams a refusal as one rejected task", async () => {
    const ok = await rpc("SendStreamingMessage", message("summarise the evidence, streamed"));
    expect(ok.type).toContain("text/event-stream");
    const events = parseSse(ok.text) as { id: string; result: Record<string, { metadata?: Record<string, string> }> }[];
    expect(events.map((e) => Object.keys(e.result)[0])).toEqual(["task", "statusUpdate", "artifactUpdate", "statusUpdate"]);
    const receipt = events[0]!.result.task!.metadata![A2A_RECEIPT_METADATA_KEY]!;
    expect(events[3]!.result.statusUpdate!.metadata![A2A_RECEIPT_METADATA_KEY]).toBe(receipt);
    expect(events.every((e) => e.id === "r1")).toBe(true);
    const [s] = await verifyAll(fx, [receipt]);
    expect((s!.predicate.execution as { result: { content: { text: string }[] } }).result.content[0]!.text).toContain("TASK_STATE_COMPLETED");

    const no = await rpc("SendStreamingMessage", message("summarise the privileged memo, streamed"));
    const refused = parseSse(no.text) as { result: { task: { status: { state: string } } } }[];
    expect(refused).toHaveLength(1);
    expect(refused[0]!.result.task.status.state).toBe("TASK_STATE_REJECTED");
  });

  it("forwards the other methods untouched, answers the HTTP+JSON binding in its own shape, and takes a grant from the request", async () => {
    const got = await rpc("GetTask", { id: "task-9" });
    const body = JSON.parse(got.text) as { result: { id: string; artifacts: { parts: { text: string }[] }[] } };
    expect(body.result.id).toBe("task-9");
    expect(body.result.artifacts[0]!.parts[0]!.text).toContain("earlier");

    const rest = await fetch(`${proxy.url}/message:send`, { method: "POST", headers: { "content-type": "application/a2a+json" }, body: JSON.stringify(message("summarise the evidence, over REST")) });
    const task = (await rest.json()) as { jsonrpc?: string; status: { state: string }; metadata: Record<string, string> };
    expect(task.jsonrpc).toBeUndefined();
    expect(task.status.state).toBe("TASK_STATE_COMPLETED");
    expect(task.metadata[A2A_RECEIPT_METADATA_KEY]).toMatch(/^[0-9a-f-]{36}$/);

    // a reader's grant, signed by the same principal, covers the card and not the delegation
    const now = Date.now();
    const reader = createDelegation(loadPrivateKey(fx.principalKey), { version: "0.1", principal: "engagement_lead_12", agent: "reader-agent", scopes: ["docs.card"], issuedAt: new Date(now - 1000).toISOString(), expiresAt: new Date(now + 3600_000).toISOString() });
    const asReader = await rpc("SendMessage", message("summarise the evidence"), { authorization: `Bearer ${grantHeader(reader)}` });
    const refused = JSON.parse(asReader.text) as { result: { status: { state: string; message: { parts: { text: string }[] } } } };
    expect(refused.result.status.state).toBe("TASK_STATE_REJECTED");
    expect(refused.result.status.message.parts[0]!.text).toMatch(/not in the delegation scopes/);
    const stranger = await rpc("SendMessage", message("x"), { authorization: "Bearer bm90LWEtZ3JhbnQ" });
    expect(stranger.status).toBe(403);
    // reads and cancels carry no receipt but still need a grant in force: an expired one cannot cancel a task (issue #97)
    const expired = createDelegation(loadPrivateKey(fx.principalKey), { version: "0.1", principal: "engagement_lead_12", agent: "reader-agent", scopes: ["docs.send"], issuedAt: new Date(now - 7200_000).toISOString(), expiresAt: new Date(now - 3600_000).toISOString() });
    const late = await rpc("CancelTask", { id: "task-9" }, { authorization: `Bearer ${grantHeader(expired)}` });
    expect(late.status).toBe(403);
    expect(late.text).toMatch(/validity window/);
  });
});

describe("the gateway as an A2A agent in front of a 0.3 agent", () => {
  let agent: Awaited<ReturnType<typeof fakeAgent>>;
  let fx: ReturnType<typeof fixtureFor>;
  let host: GatewayHost;
  let proxy: RunningA2aServer;
  beforeAll(async () => {
    agent = await fakeAgent("0.3");
    fx = fixtureFor(agent.url);
    const cfg = loadConfig(fx.configFile);
    host = await createGatewayHost(cfg);
    proxy = await serveA2a(host, (cfg.upstream as { a2a: Parameters<typeof serveA2a>[1] }).a2a, { port: 0, grant: JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope, log: () => {} });
  });
  afterAll(async () => {
    await proxy.close();
    await host.close();
    agent.server.close();
  });

  it("speaks the 0.3 shapes on both sides: message/send in, kind-tagged task out, and a rejected task for a refusal", async () => {
    const card = (await (await fetch(`${proxy.url}/.well-known/agent.json`)).json()) as { url: string; signatures?: unknown };
    expect(card.url).toBe(proxy.url);
    expect(card.signatures).toBeUndefined();
    const send = async (text: string) => (await fetch(proxy.url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 7, method: "message/send", params: { message: { kind: "message", messageId: "m1", role: "user", parts: [{ kind: "text", text }] } } }) })).json() as Promise<{ id: number; result: { kind: string; status: { state: string }; metadata: Record<string, string> } }>;
    const ok = await send("summarise the evidence");
    expect(ok.id).toBe(7);
    expect(ok.result.kind).toBe("task");
    expect(ok.result.status.state).toBe("completed");
    const forwarded = agent.seen.find((s) => s.method === "POST")!.body as { method: string; params: { message: { role: string } } };
    expect(forwarded.method).toBe("message/send");
    expect(forwarded.params.message.role).toBe("user");
    const no = await send("summarise the privileged memo");
    expect(no.result.kind).toBe("task");
    expect(no.result.status.state).toBe("rejected");
    const [a, b] = await verifyAll(fx, [ok.result.metadata[A2A_RECEIPT_METADATA_KEY]!, no.result.metadata[A2A_RECEIPT_METADATA_KEY]!]);
    expect(a!.predicate.execution.status).toBe("executed");
    expect(b!.predicate.execution.status).toBe("denied");
  });
});

describe("the upstream alone", () => {
  it("fails at startup when a header secret is missing from the environment", () => {
    expect(() => a2aUpstream("x", { url: "http://127.0.0.1:1", timeoutMs: 1000, prefix: "x", headerEnv: { authorization: "A2A_TEST_MISSING" } }, { env: {} })).toThrow(/A2A_TEST_MISSING is not set/);
  });
});

describe("the gateway as an A2A agent when the handler throws", () => {
  it("answers 500 with a JSON-RPC error and logs the cause", async () => {
    const agent = await fakeAgent("1.0");
    const fx = fixtureFor(agent.url);
    const cfg = loadConfig(fx.configFile);
    const host = await createGatewayHost(cfg);
    const logged: string[] = [];
    const proxy = await serveA2a(host, (cfg.upstream as { a2a: Parameters<typeof serveA2a>[1] }).a2a, { port: 0, grant: JSON.parse(readFileSync(join(fx.dir, "grant.json"), "utf8")) as Envelope, log: (m) => logged.push(m) });
    try {
      // the served card is fetched again on each request, so a delegate that has gone away makes the handler throw
      agent.server.closeAllConnections();
      await new Promise((r) => agent.server.close(r));
      const res = await fetch(`${proxy.url}${A2A_CARD_PATH}`);
      expect(res.status).toBe(500);
      const body = (await res.json()) as { jsonrpc: string; id: null; error: { code: number; message: string } };
      expect(body).toMatchObject({ jsonrpc: "2.0", id: null, error: { code: -32603 } });
      expect(body.error.message).not.toBe("");
      expect(logged).toContain(`agent-custody gateway (a2a): ${body.error.message}`);
    } finally {
      await proxy.close();
      await host.close();
    }
  });
});
