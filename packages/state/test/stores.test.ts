// Write-through, against the real client packages and a fake endpoint for each vendor. No network: the fakes record
// what the clients send and answer the way the services do. What matters is that a fact reaches the store with its
// custody metadata, its store id is recorded on the fact, and a retraction reaches the store.
import { createServer, type Server } from "node:http";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { MemoryClient } from "mem0ai";
import { ZepClient } from "@getzep/zep-cloud";
import { Ledger } from "../src/ledger.ts";
import { createMemoryServer } from "../src/server.ts";
import { mem0Store, pgvectorStore, zepStore, type ZepLike } from "../src/stores.ts";
import type { Fact } from "../src/ledger.ts";

interface Seen { method: string; path: string; body: any; auth: string | undefined }
/** A store index that keeps surfacing a deleted item for `lag` searches after the delete: the thing #10 exists to catch. */
function laggingIndex() {
  const live = new Map<string, string>();
  const stale = new Map<string, { text: string; left: number }>();
  const state = { lag: 1 };
  return {
    state,
    put(id: string, text: string) {
      live.set(id, text);
    },
    remove(id: string) {
      const text = live.get(id);
      live.delete(id);
      if (text !== undefined && state.lag > 0) stale.set(id, { text, left: state.lag });
    },
    search(): { id: string; text: string }[] {
      const hits = [...live].map(([id, text]) => ({ id, text }));
      for (const [id, s] of stale) {
        hits.push({ id, text: s.text });
        if (--s.left <= 0) stale.delete(id);
      }
      return hits;
    },
  };
}

function fake(routes: (req: Seen) => { status: number; body: unknown; headers?: Record<string, string> } | undefined): Promise<{ url: string; seen: Seen[]; close(): void; fail: { on: boolean } }> {
  const seen: Seen[] = [];
  const fail = { on: false };
  const server: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const s: Seen = { method: req.method!, path: req.url!, body: raw ? JSON.parse(raw) : null, auth: req.headers.authorization };
    seen.push(s);
    const r = fail.on ? { status: 500, body: { error: "store down" } } : (routes(s) ?? { status: 404, body: { error: "no route" } });
    res.writeHead(r.status, { "content-type": "application/json", ...("headers" in r ? r.headers : {}) });
    res.end(JSON.stringify(r.body));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${(server.address() as any).port}`, seen, close: () => server.close(), fail })));
}

describe("write-through stores", () => {
  let mem0: Awaited<ReturnType<typeof fake>>;
  let zep: Awaited<ReturnType<typeof fake>>;
  let client: Client;
  let ledger: Ledger;
  const mem0Index = laggingIndex();
  const zepIndex = laggingIndex();

  beforeAll(async () => {
    process.env.MEM0_TELEMETRY = "false";
    mem0 = await fake((r) => {
      if (r.method === "GET" && r.path === "/v1/ping/") return { status: 200, body: { status: "ok", org_id: "org_1", project_id: "proj_1" } };
      if (r.method === "POST" && r.path === "/v3/memories/add/") {
        const id = `mem_${mem0.seen.length}`;
        mem0Index.put(id, r.body.messages[0].content);
        return { status: 200, body: [{ id, memory: r.body.messages[0].content, event: "ADD" }] };
      }
      if (r.method === "DELETE" && /^\/v1\/memories\/[^/]+\/$/.test(r.path)) {
        mem0Index.remove(r.path.split("/")[3]!);
        return { status: 200, body: { message: "Memory deleted successfully!" } };
      }
      if (r.method === "POST" && r.path === "/v3/memories/search/") return { status: 200, body: { results: mem0Index.search().map((h) => ({ id: h.id, memory: h.text })) } };
      return undefined;
    });
    zep = await fake((r) => {
      if (r.method === "POST" && r.path === "/graph") {
        const uuid = `ep_${zep.seen.length}`;
        zepIndex.put(uuid, r.body.data);
        return { status: 200, body: { uuid, content: r.body.data, created_at: new Date().toISOString(), processed: false } };
      }
      if (r.method === "DELETE" && /^\/graph\/episodes\/[^/]+$/.test(r.path)) {
        zepIndex.remove(r.path.split("/")[3]!);
        return { status: 200, body: { message: "deleted" } };
      }
      if (r.method === "POST" && r.path === "/graph/search") return { status: 200, body: { episodes: zepIndex.search().map((h) => ({ uuid: h.id, content: h.text, created_at: new Date().toISOString() })), edges: [] } };
      return undefined;
    });
    ledger = new Ledger(join(mkdtempSync(join(tmpdir(), "stores-")), "ledger.jsonl"));
    const stores = [mem0Store(new MemoryClient({ apiKey: "test-key", host: mem0.url }), { userId: "user_42" }), zepStore(new ZepClient({ apiKey: "test-key", baseUrl: zep.url }), { userId: "user_42" })];
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(ledger, { stores, verify: { attempts: 3, delayMs: 1 } }).connect(a);
    client = new Client({ name: "test", version: "0" });
    await client.connect(b);
  });
  afterAll(async () => {
    await client.close();
    mem0.close();
    zep.close();
  });

  const value = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);

  it("a write reaches both stores with the fact's custody metadata, and both ids are recorded on the fact", async () => {
    const r = value((await client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    expect(Object.keys(r.fact.external).sort()).toEqual(["mem0", "zep"]);
    const add = mem0.seen.find((s) => s.path === "/v3/memories/add/")!;
    expect(add.auth).toBe("Token test-key");
    expect(add.body.messages).toEqual([{ role: "user", content: "acct:42 plan: pro" }]);
    expect(add.body.user_id).toBe("user_42");
    expect(add.body.infer).toBe(false);
    expect(add.body.metadata).toMatchObject({ space: "team:support", actor: "support-agent", provenance: "claimed", source: "agent-custody", storedAt: ISO });
    const graph = zep.seen.find((s) => s.path === "/graph")!;
    expect(graph.body.user_id).toBe("user_42");
    expect(graph.body.type).toBe("json");
    expect(JSON.parse(graph.body.data)).toMatchObject({ subject: "acct:42", predicate: "plan", value: "pro", space: "team:support" });
    expect(graph.body.source_description).toBe("agent-custody");
    expect((await new Ledger(ledger.location).asOf())[0]?.external).toEqual(r.fact.external);
  });

  it("a retraction reaches both stores by the recorded ids", async () => {
    const fact = (await ledger.asOf())[0]!;
    const r = value((await client.callTool({ name: "memory.retract", arguments: { factId: fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(r.removedFrom.sort()).toEqual(["mem0", "zep"]);
    expect(r.verification).toEqual({ mem0: "verified", zep: "verified" });
    expect(mem0.seen.some((s) => s.method === "DELETE" && s.path === `/v1/memories/${fact.external!.mem0}/`)).toBe(true);
    expect(zep.seen.some((s) => s.method === "DELETE" && s.path === `/graph/episodes/${fact.external!.zep}`)).toBe(true);
    expect(await ledger.asOf()).toEqual([]);
  });

  it("a store that refuses the write fails the write and nothing is recorded anywhere", async () => {
    const before = await ledger.count();
    zep.fail.on = true;
    const r = (await client.callTool({ name: "memory.write", arguments: { subject: "acct:43", predicate: "plan", value: "free", space: "team:support" } })) as CallToolResult;
    zep.fail.on = false;
    expect(r.isError).toBe(true);
    expect(await ledger.count()).toBe(before);
  });

  it("a write the ledger would refuse never reaches a store", async () => {
    const mem0Before = mem0.seen.length;
    const r = (await client.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "team:support", supersedes: "no-such-fact" } })) as CallToolResult;
    expect(r.isError).toBe(true);
    expect(mem0.seen.length).toBe(mem0Before);
  });

  it("a retraction whose store removal fails is still retracted in the ledger, and says which store still holds it", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "acct:44", predicate: "plan", value: "pro", space: "team:support" } })) as CallToolResult);
    mem0.fail.on = true;
    const r = (await client.callTool({ name: "memory.retract", arguments: { factId: w.fact.factId, reason: "wrong" } })) as CallToolResult;
    mem0.fail.on = false;
    expect(r.isError).toBe(true);
    expect((r.content[0] as any).text).toMatch(/retracted in the ledger, but still held by mem0/);
    expect(await ledger.asOf({ subject: "acct:44" })).toEqual([]);
    expect(JSON.parse((r.content[1] as any).text).removedFrom).toEqual(["zep"]);
  });

  it("forgetting erases the value from the ledger and removes it from both stores; the result is the certificate", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "person:9", predicate: "email", value: "dana@example.com", space: "team:support" } })) as CallToolResult);
    const r = value((await client.callTool({ name: "memory.forget", arguments: { factId: w.fact.factId, reason: "deletion request" } })) as CallToolResult);
    expect(r).toMatchObject({ factId: w.fact.factId, erasedFromLedger: true, stillHeld: [] });
    expect(r.removedFrom.sort()).toEqual(["mem0", "zep"]);
    expect(r.valueDigest).toMatch(/^[0-9a-f]{64}$/);
    expect(readFileSync(ledger.location, "utf8")).not.toContain("dana@example.com");
    expect(mem0.seen.some((s) => s.method === "DELETE" && s.path === `/v1/memories/${w.fact.external.mem0}/`)).toBe(true);
    expect(zep.seen.some((s) => s.method === "DELETE" && s.path === `/graph/episodes/${w.fact.external.zep}`)).toBe(true);
  });

  it("a sweep through the server forgets old facts in the ledger and removes each from both stores, skipping a held one", async () => {
    const a = value((await client.callTool({ name: "memory.write", arguments: { subject: "old:1", predicate: "email", value: "old1@x", space: "team:support" } })) as CallToolResult);
    const b = value((await client.callTool({ name: "memory.write", arguments: { subject: "old:2", predicate: "email", value: "old2@x", space: "team:support" } })) as CallToolResult);
    value((await client.callTool({ name: "memory.hold", arguments: { factId: b.fact.factId, reason: "litigation" } })) as CallToolResult);
    const future = new Date(Date.now() + 60_000).toISOString();
    const r = value((await client.callTool({ name: "memory.sweep", arguments: { before: future, space: "team:support", reason: "retention" } })) as CallToolResult);
    expect(r.forgotten.map((f: any) => f.factId)).toContain(a.fact.factId);
    expect(r.held).toEqual([b.fact.factId]);
    expect(r.stillHeld).toEqual([]);
    expect(mem0.seen.some((s) => s.method === "DELETE" && s.path === `/v1/memories/${a.fact.external.mem0}/`)).toBe(true);
    expect(zep.seen.some((s) => s.method === "DELETE" && s.path === `/graph/episodes/${a.fact.external.zep}`)).toBe(true);
    expect(readFileSync(ledger.location, "utf8")).not.toContain("old1@x");
    expect(readFileSync(ledger.location, "utf8")).toContain("old2@x");
  });

  it("the forget result names the digest kind, and keepDigest false leaves none", async () => {
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "p:8", predicate: "email", value: "x@y", space: "team:support" } })) as CallToolResult);
    const r = value((await client.callTool({ name: "memory.forget", arguments: { factId: w.fact.factId, reason: "request", keepDigest: false } })) as CallToolResult);
    expect(r).toMatchObject({ digestKind: "none", valueDigest: null, erasedFromLedger: true });
  });

  it("removal is verified against the store's search: an index that lags one search still verifies, one that never clears is reported as still indexed", async () => {
    mem0Index.state.lag = 1;
    zepIndex.state.lag = 99;
    const w = value((await client.callTool({ name: "memory.write", arguments: { subject: "p:11", predicate: "email", value: "lag@x", space: "team:support" } })) as CallToolResult);
    const r = value((await client.callTool({ name: "memory.forget", arguments: { factId: w.fact.factId, reason: "request" } })) as CallToolResult);
    expect(r.verification).toEqual({ mem0: "verified", zep: "stillIndexed" });
    expect(r.stillHeld).toEqual([]);
    expect(mem0.seen.filter((s) => s.path === "/v3/memories/search/").length).toBeGreaterThanOrEqual(2);
    zepIndex.state.lag = 1;
  });

  it("a store without search is reported as unverified, never verified", async () => {
    const calls: string[] = [];
    const blind = { name: "blind", async put() { calls.push("put"); return "b1"; }, async delete() { calls.push("delete"); } };
    const [a, b] = InMemoryTransport.createLinkedPair();
    await createMemoryServer(new Ledger(join(mkdtempSync(join(tmpdir(), "blind-")), "l.jsonl")), { stores: [blind] }).connect(a);
    const c = new Client({ name: "t", version: "0" });
    await c.connect(b);
    const w = value((await c.callTool({ name: "memory.write", arguments: { subject: "s", predicate: "p", value: 1, space: "org" } })) as CallToolResult);
    const r = value((await c.callTool({ name: "memory.forget", arguments: { factId: w.fact.factId, reason: "r" } })) as CallToolResult);
    expect(r.verification).toEqual({ blind: "unverified" });
    expect(calls).toEqual(["put", "delete"]);
    await c.close();
  });
});

const aFact = (n: number): Fact => ({ factId: `fact-${n}`, subject: `acct:${n}`, predicate: "plan", value: "pro", space: "org", actor: "agent", source: { receiptId: null }, provenance: "claimed", validFrom: "2026-01-01T00:00:00.000Z", validTo: null, confidence: null });
const ISO = expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
const expected = (f: Fact, externalId: string) => ({ externalId, factId: f.factId, text: `${f.subject} ${f.predicate}: ${f.value}`, storedAt: ISO });

describe("listing what a store holds, through the real clients", () => {
  const servers: { close(): void }[] = [];
  afterAll(() => servers.forEach((s) => s.close()));

  it("mem0 lists the memories of its user that carry custody metadata, across every page", async () => {
    process.env.MEM0_TELEMETRY = "false";
    const mems: { id: string; memory: string; user_id: string; metadata: Record<string, unknown>; created_at?: string }[] = [];
    const srv = await fake((r) => {
      if (r.method === "POST" && r.path === "/v3/memories/add/") {
        const id = `mem_${mems.length}`;
        mems.push({ id, memory: r.body.messages[0].content, user_id: r.body.user_id, metadata: r.body.metadata });
        return { status: 200, body: [{ id, memory: r.body.messages[0].content, event: "ADD" }] };
      }
      const page = r.path.match(/^\/v3\/memories\/\?page=(\d+)&page_size=(\d+)$/);
      if (r.method === "POST" && page) {
        const [n, size] = [Number(page[1]), Number(page[2])];
        const mine = mems.filter((m) => m.user_id === r.body.filters.user_id);
        // DRF answers a page past the end with 404
        if (n > 1 && (n - 1) * size >= mine.length) return { status: 404, body: { detail: "Invalid page." } };
        return { status: 200, body: { count: mine.length, next: n * size < mine.length ? "more" : null, previous: null, results: mine.slice((n - 1) * size, n * size) } };
      }
      return undefined;
    });
    servers.push(srv);
    const store = mem0Store(new MemoryClient({ apiKey: "test-key", host: srv.url }), { userId: "user_42" });
    const f = aFact(0);
    const id = await store.put(f);
    // 150 more custody memories force a second page; the other two carry no custody or belong to another user
    // seed_1 stands for a memory an older version wrote: no storedAt in the metadata, so the memory's created_at answers
    for (let i = 1; i <= 150; i++) mems.push({ id: `seed_${i}`, memory: `seed ${i}`, user_id: "user_42", metadata: { source: "agent-custody", factId: `fact-${i}` }, ...(i === 1 ? { created_at: "2025-03-01T10:00:00Z" } : {}) });
    mems.push({ id: "foreign", memory: "not ours", user_id: "user_42", metadata: {} }, { id: "other-user", memory: "x", user_id: "user_7", metadata: { source: "agent-custody", factId: "fact-x" } });
    const listed = await store.list!();
    expect(listed).toHaveLength(151);
    expect(listed).toContainEqual(expected(f, id));
    expect(listed.map((e) => e.externalId)).not.toContain("foreign");
    expect(listed.map((e) => e.externalId)).not.toContain("other-user");
    expect(listed.find((e) => e.externalId === "seed_1")?.storedAt).toBe("2025-03-01T10:00:00.000Z");
    // exactly one full page: `next` is null, and the page after it would be a 404 that the listing must not ask for
    for (let i = 0; i < 100; i++) mems.push({ id: `full_${i}`, memory: `full ${i}`, user_id: "user_100", metadata: { source: "agent-custody", factId: `fact-f${i}` } });
    expect(await mem0Store(new MemoryClient({ apiKey: "test-key", host: srv.url }), { userId: "user_100" }).list!()).toHaveLength(100);
  });

  it("zep lists the episodes of its user or graph, follows the next-cursor header, and rebuilds the indexed text from the JSON data", async () => {
    const eps: { uuid: string; content: string; created_at?: string }[] = [];
    const srv = await fake((r) => {
      if (r.method === "POST" && r.path === "/graph") {
        const uuid = `ep_${eps.length}`;
        eps.push({ uuid, content: r.body.data });
        return { status: 200, body: { uuid, content: r.body.data, created_at: new Date().toISOString() } };
      }
      const list = r.path.match(/^\/graph\/episodes\/(user|graph)\/([^/]+)$/);
      if (r.method === "POST" && list) {
        if (list[2] !== "user_42" && list[2] !== "g1") return undefined;
        const from = Number(r.body.cursor ?? 0);
        const end = Math.min(from + 2, eps.length);
        return { status: 200, headers: (end < eps.length ? { "Zep-Next-Cursor": String(end) } : {}) as Record<string, string>, body: eps.slice(from, end).map((e) => ({ created_at: new Date().toISOString(), ...e })) };
      }
      return undefined;
    });
    servers.push(srv);
    const client = new ZepClient({ apiKey: "test-key", baseUrl: srv.url });
    const f = aFact(1);
    const byUser = zepStore(client, { userId: "user_42" });
    const id = await byUser.put(f);
    // an episode without custody data, and one that is not JSON, push the second custody episode onto page 2
    eps.push({ uuid: "foreign", content: JSON.stringify({ hello: "world" }) }, { uuid: "plain", content: "free text" });
    const id2 = await byUser.put({ ...aFact(2), value: { tier: 2 } });
    // an episode an older version wrote has no storedAt in its data, so the episode's created_at answers
    eps.push({ uuid: "legacy", content: JSON.stringify({ subject: "acct:3", predicate: "plan", value: "pro", factId: "fact-3", source: "agent-custody" }), created_at: "2025-03-01T10:00:00Z" });
    const listed = await byUser.list!();
    expect(listed).toEqual([expected(f, id), { externalId: id2, factId: "fact-2", text: 'acct:2 plan: {"tier":2}', storedAt: ISO }, { externalId: "legacy", factId: "fact-3", text: "acct:3 plan: pro", storedAt: "2025-03-01T10:00:00.000Z" }]);
    expect(await zepStore(client, { graphId: "g1" }).list!()).toEqual(listed);
  });

  it("zep stops with an error when the cursor does not advance", async () => {
    const srv = await fake((r) => (r.path.startsWith("/graph/episodes/user/") ? { status: 200, headers: { "Zep-Next-Cursor": "same" }, body: [{ uuid: "ep_1", content: "{}", created_at: new Date().toISOString() }] } : undefined));
    servers.push(srv);
    await expect(zepStore(new ZepClient({ apiKey: "test-key", baseUrl: srv.url }), { userId: "user_42" }).list!()).rejects.toThrow("zep: listing does not advance");
  });

  it("a client without a list method gives a store without list", () => {
    expect(mem0Store({ add: async () => [], delete: async () => ({}) }, { userId: "u" }).list).toBeUndefined();
    expect(zepStore({ graph: { add: async () => ({ uuid: "u" }), episode: { delete: async () => ({}) } } }, { userId: "u" }).list).toBeUndefined();
  });
});

describe("verification and refusals, against plain fake clients", () => {
  const entry = { externalId: "ep_1", factId: "fact-1", text: "acct:1 plan: pro" };

  it("a put that gets no id back throws, for mem0 and for zep", async () => {
    await expect(mem0Store({ add: async () => [{}], delete: async () => ({}) }, { userId: "u" }).put(aFact(1))).rejects.toThrow("mem0 returned no memory id");
    await expect(zepStore({ graph: { add: async () => ({}) as { uuid: string }, episode: { delete: async () => ({}) } } }, { userId: "u" }).put(aFact(1))).rejects.toThrow("zep returned no episode uuid");
  });

  it("zep verifyDeleted is false while an edge still cites the episode, and true once nothing does", async () => {
    let edges = [{ uuid: "edge-1", fact: "acct:1 is on pro", episodes: ["ep_0", "ep_1"] }];
    // The graph g1 indexes the entry's text only. Any other graph, user, query or a zero limit finds nothing.
    const search: NonNullable<ZepLike["graph"]["search"]> = async (r) => (r.graphId === "g1" && r.userId === undefined && r.query === entry.text ? { edges: edges.slice(0, r.limit) } : {});
    const store = zepStore({ graph: { add: async () => ({ uuid: "x" }), episode: { delete: async () => ({}) }, search } }, { graphId: "g1" });
    expect(await store.verifyDeleted!(entry)).toBe(false);
    edges = [{ uuid: "edge-1", fact: "acct:1 is on pro", episodes: ["ep_0"] }];
    expect(await store.verifyDeleted!(entry)).toBe(true);
  });

  const zepPages = (pages: { data: { uuid: string; content: string }[]; next?: string }[]): ZepLike => {
    let i = 0;
    const page = () => ({ withRawResponse: async () => { const p = pages[i++]!; return { data: p.data, rawResponse: { headers: { get: (n: string) => (n === "Zep-Next-Cursor" ? (p.next ?? null) : null) } } }; } });
    return { graph: { add: async () => ({ uuid: "x" }), episode: { delete: async () => ({}), listByUserId: page } } };
  };
  const ep = (n: number) => ({ uuid: `ep_${n}`, content: JSON.stringify({ subject: `acct:${n}`, predicate: "plan", value: "pro", factId: `fact-${n}`, source: "agent-custody" }) });

  it("zep listing returns an episode once when a later page repeats it", async () => {
    const listed = await zepStore(zepPages([{ data: [ep(1)], next: "c1" }, { data: [ep(1), ep(2)] }]), { userId: "u" }).list!();
    expect(listed.map((e) => e.externalId)).toEqual(["ep_1", "ep_2"]);
  });

  it("zep listing throws when the backend repeats a cursor, even with new episodes", async () => {
    await expect(zepStore(zepPages([{ data: [ep(1)], next: "c1" }, { data: [ep(2)], next: "c1" }, { data: [] }]), { userId: "u" }).list!()).rejects.toThrow("zep: listing does not advance");
  });

  it("pgvector refuses dimensions that are not a positive integer", () => {
    const client = { query: async () => ({ rows: [] }) };
    for (const dimensions of [0, -3, 1.5, Number.NaN]) expect(() => pgvectorStore(client, { embed: async () => [], dimensions })).toThrow("pgvector: dimensions must be a positive integer");
    expect(() => pgvectorStore(client, { embed: async () => [], dimensions: 3 })).not.toThrow();
  });
});
