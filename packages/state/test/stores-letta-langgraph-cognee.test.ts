// Write-through to Letta, a LangGraph store (where LangMem keeps its memories), and Cognee. Letta is driven through
// its real client against a stand-in of its archival-memory routes; the LangGraph store is the real InMemoryStore,
// no network at all; Cognee has no JavaScript client, so the adapter's own HTTP is checked against a stand-in of the
// three routes it uses. In every case: a fact reaches the store with its custody, the store's id is recorded on the
// fact, retraction and forget reach the store and are verified, and a store that refuses fails the write cleanly.
import { createServer, type Server } from "node:http";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { Letta } from "@letta-ai/letta-client";
import { InMemoryStore } from "@langchain/langgraph";
import { Ledger, type Fact } from "../src/ledger.ts";
import { createMemoryServer } from "../src/server.ts";
import { cogneeStore, langgraphStore, lettaStore, type LettaLike } from "../src/stores.ts";

interface Seen { method: string; path: string; body: string; headers: Record<string, string | string[] | undefined> }
function fake(routes: (req: Seen) => { status: number; body: unknown } | undefined): Promise<{ url: string; seen: Seen[]; close(): void; fail: { on: boolean } }> {
  const seen: Seen[] = [];
  const fail = { on: false };
  const server: Server = createServer(async (req, res) => {
    let raw = "";
    for await (const c of req) raw += c;
    const s: Seen = { method: req.method!, path: req.url!, body: raw, headers: req.headers };
    seen.push(s);
    const r = fail.on ? { status: 500, body: { error: "store down" } } : (routes(s) ?? { status: 404, body: { error: `no route ${s.method} ${s.path}` } });
    res.writeHead(r.status, { "content-type": "application/json" });
    res.end(JSON.stringify(r.body));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ url: `http://127.0.0.1:${(server.address() as { port: number }).port}`, seen, close: () => server.close(), fail })));
}
const value = (r: CallToolResult) => JSON.parse((r.content[0] as { text: string }).text);

const aFact = (n: number): Fact => ({ factId: `fact-${n}`, subject: `acct:${n}`, predicate: "plan", value: "pro", space: "org", actor: "agent", source: { receiptId: null }, provenance: "claimed", validFrom: "2026-01-01T00:00:00.000Z", validTo: null, confidence: null });
const ISO = expect.stringMatching(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
const expected = (n: number, externalId: string) => ({ externalId, factId: `fact-${n}`, text: `acct:${n} plan: pro`, storedAt: ISO });

async function serverWith(stores: NonNullable<Parameters<typeof createMemoryServer>[1]>["stores"]) {
  const ledger = new Ledger(join(mkdtempSync(join(tmpdir(), "stores3-")), "ledger.jsonl"));
  const [a, b] = InMemoryTransport.createLinkedPair();
  await createMemoryServer(ledger, { stores, verify: { attempts: 3, delayMs: 1 } }).connect(a);
  const client = new Client({ name: "test", version: "0" });
  await client.connect(b);
  return { ledger, client };
}

describe("Letta archival memory, through the real client", () => {
  let letta: Awaited<ReturnType<typeof fake>>;
  const passages = new Map<string, { text: string; tags: string[] }>();
  let ctx: Awaited<ReturnType<typeof serverWith>>;
  beforeAll(async () => {
    letta = await fake((r) => {
      const m = r.path.match(/^\/v1\/agents\/([^/]+)\/archival-memory(\/search\?.*|\/([^/?]+))?$/);
      if (!m) return undefined;
      if (r.method === "POST" && !m[2]) {
        const b = JSON.parse(r.body) as { text: string; tags: string[] };
        const id = `passage-${passages.size + 1}`;
        passages.set(id, { text: b.text, tags: b.tags });
        return { status: 200, body: [{ id, text: b.text, tags: b.tags, agent_id: m[1], created_at: new Date().toISOString() }] };
      }
      if (r.method === "DELETE" && m[3]) {
        passages.delete(m[3]);
        return { status: 200, body: { message: "deleted" } };
      }
      if (r.method === "GET" && m[2]?.startsWith("/search")) {
        const results = [...passages].map(([id, p]) => ({ id, content: p.text, timestamp: new Date().toISOString(), tags: p.tags }));
        return { status: 200, body: { count: results.length, results } };
      }
      return undefined;
    });
    ctx = await serverWith([lettaStore(new Letta({ apiKey: "test-key", baseURL: letta.url }), { agentId: "agent-1", tags: ["support"] })]);
  });
  afterAll(async () => {
    await ctx.client.close();
    letta.close();
  });

  it("a write becomes a passage with the custody as tags, the passage id is on the fact, and retract and forget delete it and verify", async () => {
    const w = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    expect(w.fact.external).toEqual({ letta: "passage-1" });
    const create = letta.seen.find((s) => s.method === "POST")!;
    expect(create.headers.authorization).toBe("Bearer test-key");
    const body = JSON.parse(create.body);
    expect(body.text).toBe("acct:42 plan: pro");
    expect(body.tags).toEqual(["agent-custody", `fact:${w.fact.factId}`, "space:team:support", expect.stringMatching(/^stored:\d{4}-\d\d-\d\dT/), "support"]);
    const r = value((await ctx.client.callTool({ name: "memory.retract", arguments: { factId: w.fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(r).toMatchObject({ removedFrom: ["letta"], verification: { letta: "verified" } });
    expect(letta.seen.some((s) => s.method === "DELETE" && s.path === "/v1/agents/agent-1/archival-memory/passage-1")).toBe(true);
    const w2 = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "person:1", predicate: "email", value: "d@example.com", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    const fg = value((await ctx.client.callTool({ name: "memory.forget", arguments: { factId: w2.fact.factId, reason: "deletion request" } })) as CallToolResult);
    expect(fg).toMatchObject({ erasedFromLedger: true, removedFrom: ["letta"], verification: { letta: "verified" } });
    expect(passages.size).toBe(0);
  });

  it("a refusing Letta fails the write and nothing is recorded", async () => {
    const before = await ctx.ledger.count();
    letta.fail.on = true;
    try {
      const r = (await ctx.client.callTool({ name: "memory.write", arguments: { subject: "acct:43", predicate: "plan", value: "free", space: "team:support", actor: "support-agent" } })) as CallToolResult;
      expect(r.isError).toBe(true);
      expect(await ctx.ledger.count()).toBe(before);
    } finally {
      letta.fail.on = false;
    }
  });
});

describe("Letta listing, through the real client", () => {
  it("lists the passages that carry the custody tags, across every page of the cursor, and not the passages without them", async () => {
    const passages: { id: string; text: string; tags: string[]; created_at?: string }[] = [];
    const letta = await fake((r) => {
      const m = r.path.match(/^\/v1\/agents\/agent-1\/archival-memory(\?.*)?$/);
      if (!m) return undefined;
      if (r.method === "POST") {
        const b = JSON.parse(r.body) as { text: string; tags: string[] };
        const id = `passage-${passages.length}`;
        passages.push({ id, text: b.text, tags: b.tags });
        return { status: 200, body: [{ id, text: b.text, tags: b.tags }] };
      }
      const q = new URLSearchParams(m[1]);
      const from = q.has("after") ? passages.findIndex((p) => p.id === q.get("after")) + 1 : 0;
      return { status: 200, body: passages.slice(from, from + Number(q.get("limit"))) };
    });
    try {
      const store = lettaStore(new Letta({ apiKey: "test-key", baseURL: letta.url }), { agentId: "agent-1" });
      const id = await store.put(aFact(0));
      passages.push({ id: "foreign", text: "agent-written note", tags: ["notes"] });
      // seed-1 stands for a passage an older version wrote: no stored tag, so the passage's created_at answers
      for (let i = 1; i <= 120; i++) passages.push({ id: `seed-${i}`, text: `seed ${i}`, tags: ["agent-custody", `fact:fact-${i}`], ...(i === 1 ? { created_at: "2025-03-01T10:00:00Z" } : {}) });
      const listed = await store.list!();
      expect(listed).toHaveLength(121);
      expect(listed[0]).toEqual(expected(0, id));
      expect(listed.at(-1)).toEqual({ externalId: "seed-120", factId: "fact-120", text: "seed 120" }); // written by an older version: no storedAt
      expect(listed.map((e) => e.externalId)).not.toContain("foreign");
      expect(listed.find((e) => e.externalId === "seed-1")?.storedAt).toBe("2025-03-01T10:00:00.000Z");
    } finally {
      letta.close();
    }
  });

  it("lists only the passages that carry every tag of the store, so a repair on one tag-scoped ledger leaves the passages of another on the same agent", async () => {
    const passages: { id: string; text: string; tags: string[] }[] = [];
    const letta = await fake((r) => {
      const m = r.path.match(/^\/v1\/agents\/agent-1\/archival-memory(\?.*)?$/);
      if (!m) return undefined;
      if (r.method === "POST") {
        const b = JSON.parse(r.body) as { text: string; tags: string[] };
        const id = `passage-${passages.length}`;
        passages.push({ id, text: b.text, tags: b.tags });
        return { status: 200, body: [{ id, text: b.text, tags: b.tags }] };
      }
      return { status: 200, body: passages };
    });
    try {
      const client = new Letta({ apiKey: "test-key", baseURL: letta.url });
      const a = lettaStore(client, { agentId: "agent-1", tags: ["tenant:a"] });
      const b = await serverWith([lettaStore(client, { agentId: "agent-1", tags: ["tenant:b"] })]);
      await b.client.callTool({ name: "memory.write", arguments: { subject: "acct:b", predicate: "plan", value: "pro", space: "org" } });
      const hourAgo = new Date(Date.now() - 3_600_000).toISOString();
      for (const p of passages) p.tags = p.tags.map((t) => (t.startsWith("stored:") ? `stored:${hourAgo}` : t));
      expect(passages).toHaveLength(1);
      expect(await a.list!()).toEqual([]);
      const a2 = await serverWith([a]);
      const r = value((await a2.client.callTool({ name: "memory.repair", arguments: { reason: "append failed" } })) as CallToolResult);
      expect(r.repaired).toEqual([]);
      expect(passages).toHaveLength(1);
      expect(await lettaStore(client, { agentId: "agent-1", tags: ["tenant:b"] }).list!()).toHaveLength(1);
      await a2.client.close();
      await b.client.close();
    } finally {
      letta.close();
    }
  });

  it("matches the tag set exactly, so a store whose tags are a subset or a superset of another's does not claim its passages", async () => {
    const custody = ["agent-custody", "fact:f-1", "space:org", `stored:${new Date().toISOString()}`];
    const passages = [{ id: "p-ab", text: "t", tags: [...custody, "tenant:a", "team:b"] }, { id: "p-a", text: "t", tags: [...custody, "tenant:a"] }, { id: "p-none", text: "t", tags: custody }];
    const letta = await fake((r) => (r.path.match(/^\/v1\/agents\/agent-1\/archival-memory(\?.*)?$/) && r.method === "GET" ? { status: 200, body: passages } : undefined));
    try {
      const client = new Letta({ apiKey: "test-key", baseURL: letta.url });
      const ids = async (tags?: string[]) => (await lettaStore(client, { agentId: "agent-1", ...(tags ? { tags } : {}) }).list!()).map((e) => e.externalId);
      expect(await ids(["tenant:a"])).toEqual(["p-a"]);
      expect(await ids(["team:b", "tenant:a"])).toEqual(["p-ab"]);
      expect(await ids()).toEqual(["p-none"]);
      expect(await ids(["tenant:b"])).toEqual([]);
    } finally {
      letta.close();
    }
  });

  it("refuses a tag with a custody prefix, because list() would never match the tag set", () => {
    const client = new Letta({ apiKey: "test-key", baseURL: "http://127.0.0.1:1" });
    for (const tag of ["space:eu", "receipt:r-1", "stored:now", "fact:f-1", "agent-custody"]) {
      expect(() => lettaStore(client, { agentId: "agent-1", tags: ["ok", tag] })).toThrow(`the tag "${tag}" is reserved`);
    }
    expect(() => lettaStore(client, { agentId: "agent-1", tags: ["tenant:a", "spaces"] })).not.toThrow();
  });

  it("stops with an error when the backend ignores the cursor", async () => {
    const page = Array.from({ length: 100 }, (_, i) => ({ id: `p-${i}`, text: `t ${i}`, tags: ["agent-custody", `fact:f-${i}`] }));
    const letta = await fake((r) => (r.method === "GET" ? { status: 200, body: page } : undefined));
    try {
      await expect(lettaStore(new Letta({ apiKey: "test-key", baseURL: letta.url }), { agentId: "agent-1" }).list!()).rejects.toThrow("letta: listing does not advance");
    } finally {
      letta.close();
    }
  });
});

describe("a LangGraph store, where LangMem keeps its memories, the real InMemoryStore", () => {
  const store = new InMemoryStore();
  let ctx: Awaited<ReturnType<typeof serverWith>>;
  beforeAll(async () => {
    ctx = await serverWith([langgraphStore(store, { namespace: ["memories", "user_42"] })]);
  });
  afterAll(async () => {
    await ctx.client.close();
  });

  it("a write is one item keyed by the fact id with content and custody, and retract and forget remove it, verified by get and search", async () => {
    const w = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    expect(w.fact.external).toEqual({ langgraph: w.fact.factId });
    const item = await store.get(["memories", "user_42"], w.fact.factId);
    expect(item?.value).toMatchObject({ content: "acct:42 plan: pro", subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent", provenance: "claimed", source: "agent-custody" });
    expect((await store.search(["memories", "user_42"], { filter: { factId: w.fact.factId } })).map((h) => h.key)).toEqual([w.fact.factId]);
    const r = value((await ctx.client.callTool({ name: "memory.retract", arguments: { factId: w.fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(r).toMatchObject({ removedFrom: ["langgraph"], verification: { langgraph: "verified" } });
    expect(await store.get(["memories", "user_42"], w.fact.factId)).toBeNull();
    const w2 = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "person:1", predicate: "ssn", value: "SSN-1", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    const fg = value((await ctx.client.callTool({ name: "memory.forget", arguments: { factId: w2.fact.factId, reason: "deletion request" } })) as CallToolResult);
    expect(fg).toMatchObject({ erasedFromLedger: true, removedFrom: ["langgraph"], verification: { langgraph: "verified" } });
    expect(await store.search(["memories", "user_42"])).toEqual([]);
  });

  it("lists the items that carry custody, across pages of 100, and not other items or other namespaces", async () => {
    const mine = langgraphStore(store, { namespace: ["memories", "list"] });
    const id = await mine.put(aFact(0));
    for (let i = 1; i <= 120; i++) await store.put(["memories", "list"], `seed-${i}`, { content: `seed ${i}`, source: "agent-custody", factId: `fact-${i}` });
    await store.put(["memories", "list"], "foreign", { content: "no custody here" });
    await store.put(["memories", "elsewhere"], "other", { content: "x", source: "agent-custody", factId: "fact-x" });
    await store.put(["memories", "list", "child"], "nested", { content: "x", source: "agent-custody", factId: "fact-n" });
    const listed = await mine.list!();
    expect(listed).toHaveLength(121);
    expect(listed).toContainEqual(expected(0, id));
    expect(listed.map((e) => e.externalId)).not.toContain("foreign");
    expect(listed.map((e) => e.externalId)).not.toContain("other");
    expect(listed.map((e) => e.externalId)).not.toContain("nested");
    // an item an older version wrote has no storedAt in its value, so the item's creation time answers
    expect(listed.find((e) => e.externalId === "seed-1")?.storedAt).toBe((await store.get(["memories", "list"], "seed-1"))!.createdAt.toISOString());
  });
});

describe("Cognee, through its REST API", () => {
  let cognee: Awaited<ReturnType<typeof fake>>;
  const items: { id: string; name: string; external_metadata: string; createdAt?: string }[] = [];
  let ctx: Awaited<ReturnType<typeof serverWith>>;
  beforeAll(async () => {
    process.env.TEST_COGNEE_KEY = "cognee-key";
    cognee = await fake((r) => {
      if (r.method === "POST" && r.path === "/api/v1/add") {
        // multipart: the fields arrive as parts; keep what the adapter sent so the test can assert on it
        const field = (name: string) => r.body.match(new RegExp(`name="${name}"\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`))?.[1] ?? null;
        const meta = JSON.parse(field("external_metadata") ?? "[]")[0];
        items.push({ id: `data-${items.length + 1}`, name: field("raw_data") ?? "", external_metadata: JSON.stringify(meta) });
        return { status: 200, body: { pipeline_run_id: "run-1", status: "DATASET_PROCESSING_COMPLETED", dataset_id: "ds-1" } };
      }
      if (r.method === "GET" && r.path === "/api/v1/datasets/ds-1/data") return { status: 200, body: items };
      const del = r.path.match(/^\/api\/v1\/datasets\/ds-1\/data\/([^/]+)$/);
      if (r.method === "DELETE" && del) {
        const i = items.findIndex((x) => x.id === del[1]);
        if (i >= 0) items.splice(i, 1);
        return { status: 200, body: {} };
      }
      return undefined;
    });
    ctx = await serverWith([cogneeStore({ url: cognee.url, datasetId: "ds-1", apiKeyEnv: "TEST_COGNEE_KEY" })]);
  });
  afterAll(async () => {
    await ctx.client.close();
    cognee.close();
  });

  it("a write is a multipart add with the text, dataset, and custody metadata; the data id is found by listing; retract and forget delete it and verify", async () => {
    const w = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "acct:42", predicate: "plan", value: "pro", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    expect(w.fact.external).toEqual({ cognee: "data-1" });
    const add = cognee.seen.find((s) => s.path === "/api/v1/add")!;
    expect(add.headers["x-api-key"]).toBe("cognee-key");
    expect(String(add.headers["content-type"])).toMatch(/^multipart\/form-data; boundary=/);
    expect(add.body).toContain('name="raw_data"\r\n\r\nacct:42 plan: pro');
    expect(add.body).toContain('name="datasetId"\r\n\r\nds-1');
    expect(add.body).toMatch(/name="external_metadata"\r\n\r\n\[\{"factId":"[^"]+","space":"team:support"/);
    const r = value((await ctx.client.callTool({ name: "memory.retract", arguments: { factId: w.fact.factId, reason: "wrong" } })) as CallToolResult);
    expect(r).toMatchObject({ removedFrom: ["cognee"], verification: { cognee: "verified" } });
    expect(cognee.seen.some((s) => s.method === "DELETE" && s.path === "/api/v1/datasets/ds-1/data/data-1")).toBe(true);
    const w2 = value((await ctx.client.callTool({ name: "memory.write", arguments: { subject: "person:1", predicate: "email", value: "d@example.com", space: "team:support", actor: "support-agent" } })) as CallToolResult);
    const fg = value((await ctx.client.callTool({ name: "memory.forget", arguments: { factId: w2.fact.factId, reason: "deletion request" } })) as CallToolResult);
    expect(fg).toMatchObject({ erasedFromLedger: true, removedFrom: ["cognee"], verification: { cognee: "verified" } });
    expect(items).toEqual([]);
  });

  it("lists the data items that carry custody metadata, and not the other items of the dataset", async () => {
    const store = cogneeStore({ url: cognee.url, datasetId: "ds-1", apiKeyEnv: "TEST_COGNEE_KEY" });
    const id = await store.put(aFact(0));
    items.push({ id: "data-foreign", name: "a note", external_metadata: "{}" });
    try {
      // the data listing carries no text, so the entry has none
      expect(await store.list!()).toEqual([{ externalId: id, factId: "fact-0", text: "", storedAt: ISO }]);
      // an item an older version wrote has no storedAt in its metadata, so the item's createdAt answers
      items.push({ id: "data-legacy", name: "old", external_metadata: JSON.stringify({ source: "agent-custody", factId: "fact-9" }), createdAt: "2025-03-01T10:00:00Z" });
      expect((await store.list!()).find((e) => e.externalId === "data-legacy")?.storedAt).toBe("2025-03-01T10:00:00.000Z");
    } finally {
      items.length = 0;
    }
  });

  it("a missing credential variable fails at construction, and a refusing Cognee fails the write with nothing recorded", async () => {
    expect(() => cogneeStore({ url: cognee.url, datasetId: "ds-1", apiKeyEnv: "NOT_SET_ANYWHERE_COGNEE" })).toThrow(/NOT_SET_ANYWHERE_COGNEE/);
    const before = await ctx.ledger.count();
    cognee.fail.on = true;
    try {
      const r = (await ctx.client.callTool({ name: "memory.write", arguments: { subject: "acct:43", predicate: "plan", value: "free", space: "team:support", actor: "support-agent" } })) as CallToolResult;
      expect(r.isError).toBe(true);
      expect(await ctx.ledger.count()).toBe(before);
    } finally {
      cognee.fail.on = false;
    }
  });
});

describe("verifyDeleted and listing edges, against plain fake clients", () => {
  const entry = { externalId: "id-1", factId: "fact-1", text: "acct:1 plan: pro" };
  const letta = (passages: Partial<LettaLike["agents"]["passages"]>): LettaLike => ({ agents: { passages: { create: async () => [], delete: async () => ({}), ...passages } } });

  it("letta verifyDeleted is false while search returns the passage by id or by text, and true once it returns neither", async () => {
    let passages = [{ id: "id-1", content: "other", tags: ["fact:fact-1"] }, { id: "id-1", content: entry.text, tags: ["fact:fact-2"] }];
    // Agent a indexes the entry's text only, and a passage matches by its tags.
    const search: NonNullable<LettaLike["agents"]["passages"]["search"]> = async (agentId, q) => ({
      results: agentId === "a" && q.query === entry.text ? passages.filter((p) => (q.tag_match_mode === "all" ? q.tags!.every((t) => p.tags.includes(t)) : q.tags!.some((t) => p.tags.includes(t)))) : [],
    });
    const store = lettaStore(letta({ search }), { agentId: "a" });
    expect(await store.verifyDeleted!(entry)).toBe(false);
    passages = [{ id: "id-9", content: entry.text, tags: ["fact:fact-1"] }];
    expect(await store.verifyDeleted!(entry)).toBe(false);
    passages = [{ id: "id-9", content: "other", tags: ["fact:fact-1"] }, { id: "id-1", content: entry.text, tags: ["fact:fact-2"] }];
    expect(await store.verifyDeleted!(entry)).toBe(true);
  });

  const custody = (id: string | undefined) => ({ ...(id ? { id } : {}), text: `t ${id}`, tags: ["agent-custody", `fact:f-${id}`] });
  const lettaPages = (pages: ReturnType<typeof custody>[][]) => {
    let i = 0;
    return letta({ list: async () => pages[i++] ?? [] });
  };

  it("letta listing skips a passage without an id and a passage an earlier page returned", async () => {
    const first = Array.from({ length: 100 }, (_, i) => custody(`p${i}`));
    const listed = await lettaStore(lettaPages([first, [custody("p0"), custody(undefined), custody("q1")]]), { agentId: "a" }).list!();
    expect(listed.map((e) => e.externalId)).toEqual([...first.map((p) => p.id), "q1"]);
  });

  it("letta listing throws when a full page ends on the cursor it was given", async () => {
    const first = Array.from({ length: 100 }, (_, i) => custody(`p${i}`));
    const second = [...Array.from({ length: 99 }, (_, i) => custody(`q${i}`)), custody("p99")];
    await expect(lettaStore(lettaPages([first, second]), { agentId: "a" }).list!()).rejects.toThrow("letta: listing does not advance");
  });

  it("langgraph verifyDeleted is false while get or search finds the item, and true once neither does", async () => {
    const mem = new InMemoryStore();
    for (let i = 0; i < 12; i++) await mem.put(["m"], `other-${i}`, { factId: `fact-x${i}` });
    await mem.put(["m"], "id-1", { factId: "fact-1" });
    await mem.put(["n"], "id-1", { factId: "fact-1" });
    const base = { put: mem.put.bind(mem), get: mem.get.bind(mem), delete: mem.delete.bind(mem) };
    expect(await langgraphStore(base, { namespace: ["m"] }).verifyDeleted!(entry)).toBe(false);
    // get lags behind the delete here, so only search can see the item.
    const store = langgraphStore({ ...base, get: async () => null, search: mem.search.bind(mem) }, { namespace: ["m"] });
    expect(await store.verifyDeleted!(entry)).toBe(false);
    await mem.delete(["m"], "id-1");
    expect(await store.verifyDeleted!(entry)).toBe(true);
    expect(await langgraphStore({ ...base, get: async () => null }, { namespace: ["m"] }).verifyDeleted!(entry)).toBe(true);
  });

  const cognee = (items: unknown[], env: Record<string, string | undefined> = {}, tokenEnv?: string) => {
    const seen: RequestInit[] = [];
    const fetch = (async (url: URL, init: RequestInit) => {
      seen.push(init);
      if (init.method !== "GET") return new Response("");
      return url.pathname === "/api/v1/datasets/ds-1/data" ? new Response(JSON.stringify(items)) : new Response("not found", { status: 404 });
    }) as typeof globalThis.fetch;
    return { seen, store: cogneeStore({ url: "http://cognee.invalid", datasetId: "ds-1", fetch, env, ...(tokenEnv ? { tokenEnv } : {}) }) };
  };

  it("cognee verifyDeleted is false while the dataset lists an item with the fact id under another id, and true once it is gone", async () => {
    const items = [{ id: "data-7", external_metadata: { source: "agent-custody", factId: "fact-1" } }];
    const { store } = cognee(items);
    expect(await store.verifyDeleted!(entry)).toBe(false);
    items.length = 0;
    expect(await store.verifyDeleted!(entry)).toBe(true);
  });

  it("cognee verifyDeleted is false while the dataset lists an item under the same id, and true once it is gone", async () => {
    const items = [{ id: "id-1", external_metadata: { source: "agent-custody", factId: "fact-other" } }];
    const { store } = cognee(items);
    expect(await store.verifyDeleted!(entry)).toBe(false);
    items.length = 0;
    expect(await store.verifyDeleted!(entry)).toBe(true);
  });

  it("cognee throws when the add succeeds but the dataset lists no item for the fact", async () => {
    await expect(cognee([]).store.put(aFact(3))).rejects.toThrow("cognee accepted the add but the dataset lists no item carrying fact fact-3");
  });

  it("cognee sends the token variable as a bearer token, and throws when the variable is not set", async () => {
    const { seen, store } = cognee([], { TEST_COGNEE_TOKEN: "tok-1" }, "TEST_COGNEE_TOKEN");
    await store.list!();
    expect((seen[0]!.headers as Record<string, string>).authorization).toBe("Bearer tok-1");
    expect(() => cognee([], {}, "TEST_COGNEE_TOKEN")).toThrow("cognee: environment variable TEST_COGNEE_TOKEN is not set");
  });

  it("cognee reads metadata given as an object or as a JSON string, and skips metadata that is not JSON or absent", async () => {
    const items = [
      { id: "obj", external_metadata: { source: "agent-custody", factId: "fact-1", storedAt: "2026-01-01T00:00:00Z" } },
      { id: "str", external_metadata: JSON.stringify({ source: "agent-custody", factId: "fact-2" }) },
      { id: "bad", external_metadata: "{not json" },
      { id: "none" },
    ];
    expect(await cognee(items).store.list!()).toEqual([{ externalId: "obj", factId: "fact-1", text: "", storedAt: "2026-01-01T00:00:00.000Z" }, { externalId: "str", factId: "fact-2", text: "" }]);
  });
});
