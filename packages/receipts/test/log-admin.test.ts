// The admin surface is the operator's, not the tenant's: nothing under /admin answers without the admin token, a
// minted token works on the tenant's path and stops working when revoked, and the page ships with no outside
// requests. Postgres runs in-process through PGlite.
import { Script } from "node:vm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair } from "../src/crypto.ts";
import { postgresResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { welcomeSheet } from "../src/log-admin.ts";
import { PortalStore } from "../src/portal.ts";

let db: PGlite;
let log: RunningLog;
let tenancy: PostgresTenancy;
let portal: PortalStore;
const ADMIN = "admin-secret-for-tests";

beforeAll(async () => {
  db = new PGlite();
  await db.query("SELECT 1");
  tenancy = new PostgresTenancy(db);
  await tenancy.addTenant("default", "log.example.test");
  portal = new PortalStore(db);
  log = await serveLog(postgresResolver(tenancy), generateKeyPair(), { port: 0, admin: { tenancy, token: ADMIN, portal, publicUrl: "https://log.example.test/", checkpointsUrl: "https://checkpoints.example.test/" } });
}, 60_000);
afterAll(async () => {
  await log.close();
  await db.close();
});

const call = (method: string, path: string, body?: unknown, token: string | null = ADMIN) => fetch(new URL(path, log.url), { method, headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body ? { "content-type": "application/json" } : {}) }, body: body ? JSON.stringify(body) : undefined });

describe("the admin surface", () => {
  it("nothing under /admin answers without the token, the page included; the browser's Basic credential and a bearer both work; the page has a strict CSP", async () => {
    const bare = await call("GET", "admin", undefined, null);
    expect(bare.status).toBe(401);
    expect(bare.headers.get("www-authenticate")).toMatch(/^Basic realm=/);
    const basic = await fetch(new URL("admin", log.url), { headers: { authorization: `Basic ${Buffer.from(`anyone:${ADMIN}`).toString("base64")}` } });
    expect(basic.status).toBe(200);
    expect(basic.headers.get("content-type")).toMatch(/text\/html/);
    expect(basic.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
    const html = await basic.text();
    expect(html).toContain("Log admin");
    for (const m of html.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Script(m[1]!); // every inline script parses
    expect(basic.headers.get("content-security-policy")).toContain("img-src 'self'");
    expect(html).not.toMatch(/https?:\/\/(?!agent-custody\.dev)/); // no third-party requests
    expect(html).not.toContain("sessionStorage");
    expect(html).toContain('id="themeToggle"');
    expect(html).toContain(':root[data-theme="dark"]');
    for (const [m, p] of [["GET", "admin/tenants"], ["POST", "admin/tenants"], ["GET", "admin/info"]] as const) {
      expect((await call(m, p, m === "POST" ? { id: "x" } : undefined, null)).status).toBe(401);
    }
    const viaBasic = await fetch(new URL("admin/info", log.url), { headers: { authorization: `Basic ${Buffer.from(`x:${ADMIN}`).toString("base64")}` } });
    expect(viaBasic.status).toBe(200);
  });

  it("behind a trusted proxy the throttle keys on the address the proxy appended, the rightmost, so one client's failures do not lock out another and a forged leftmost entry does not escape", async () => {
    const db2 = new PGlite();
    await db2.query("SELECT 1");
    const t2 = new PostgresTenancy(db2);
    await t2.addTenant("default", "x");
    const proxied = await serveLog(postgresResolver(t2), generateKeyPair(), { port: 0, trustProxy: true, admin: { tenancy: t2, token: ADMIN } });
    try {
      // the proxy appends the real client to whatever the client sent: "<client-supplied>, <real>"
      const attempt = (ip: string, token: string, spoof = "10.0.0.1") => fetch(new URL("admin/info", proxied.url), { headers: { authorization: `Bearer ${token}`, "x-forwarded-for": `${spoof}, ${ip}` } });
      let last = 0;
      for (let i = 0; i < 8; i++) last = (await attempt("203.0.113.5", "wrong", `198.51.100.${i}`)).status; // a rotating forged entry changes nothing
      expect(last).toBe(429);
      expect((await attempt("203.0.113.5", "wrong", "198.51.100.99")).status).toBe(429);
      expect((await attempt("203.0.113.6", "wrong")).status).toBe(401); // a different real client is not throttled
      expect((await attempt("203.0.113.6", ADMIN)).status).toBe(200);
    } finally {
      await proxied.close();
      await db2.close();
    }
    // without trustProxy the header is ignored: every request here is the same socket address
    const spoofed = await fetch(new URL("admin/info", log.url), { headers: { authorization: `Bearer ${ADMIN}`, "x-forwarded-for": "198.51.100.9" } });
    expect(spoofed.status).toBe(200);
  }, 30_000);

  it("wrong tokens from one address are throttled after a handful of tries", async () => {
    let last = 0;
    for (let i = 0; i < 8; i++) last = (await call("GET", "admin/info", undefined, `wrong-${i}`)).status;
    expect(last).toBe(429);
    // the right token still works from the same address: the throttle is on failures, not on the address
    expect((await call("GET", "admin/info")).status).toBe(200);
  });

  it("creates a tenant, mints a token shown once with the welcome sheet, the token appends on the tenant's path, and revocation stops it", async () => {
    const info = (await (await call("GET", "admin/info")).json()) as { publicUrl: string; keyid: string };
    expect(info.publicUrl).toBe("https://log.example.test/");
    expect(info.keyid).toMatch(/^[0-9a-f]{64}$/);
    const made = (await (await call("POST", "admin/tenants", { id: "acme", logId: "acme-eu" })).json()) as { id: string; logId: string };
    expect(made).toMatchObject({ id: "acme", logId: "acme-eu" });
    expect((await call("POST", "admin/tenants", { id: "bad id" })).status).toBe(400);
    const listed = (await (await call("GET", "admin/tenants")).json()) as { id: string; tokens: number }[];
    expect(listed.map((t) => [t.id, t.tokens])).toEqual([["default", 0], ["acme", 0]]);
    const minted = (await (await call("POST", "admin/tenants/acme/tokens", { label: "support fleet" })).json()) as { token: string; tokenHash: string; welcome: string };
    expect(minted.token).toMatch(/^[0-9a-f]{64}$/);
    expect(minted.welcome).toContain("https://log.example.test/t/acme/");
    expect(minted.welcome).toContain("--log-id acme-eu");
    expect(minted.welcome).toContain("https://checkpoints.example.test/acme/latest.json");
    expect(minted.welcome).toContain(info.keyid);
    const append = (token: string) => fetch(new URL("t/acme/append", log.url), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ leafHash: "ab".repeat(32) }) });
    expect((await append(minted.token)).status).toBe(200);
    expect((await append(ADMIN)).status).toBe(401); // the admin token is not a tenant token
    const tokens = (await (await call("GET", "admin/tenants/acme/tokens")).json()) as { label: string; tokenHash: string; revokedAt: string | null }[];
    expect(tokens).toEqual([{ label: "support fleet", tokenHash: minted.tokenHash, createdAt: expect.any(String), revokedAt: null, tenantId: "acme" }]);
    expect(await (await call("POST", `admin/tenants/acme/tokens/${minted.tokenHash.slice(0, 12)}/revoke`)).json()).toEqual({ revoked: 1 });
    expect((await append(minted.token)).status).toBe(401);
    expect((await call("POST", "admin/tenants/nobody/tokens", { label: "x" })).status).toBe(404);
    await call("POST", "admin/tenants/acme/disable");
    expect((await (await call("GET", "admin/tenants")).json() as { id: string; disabledAt: string | null }[]).find((t) => t.id === "acme")?.disabledAt).not.toBeNull();
  });

  it("the welcome sheet is the same text the server script prints, with the tenant's URL, id, and commands", () => {
    const sheet = welcomeSheet({ tenant: "globex", logId: "globex-us", publicUrl: "https://log.example.test", checkpointsUrl: "https://checkpoints.example.test", keyid: "abc" });
    expect(sheet).toContain('"url": "https://log.example.test/t/globex/"');
    expect(sheet).toContain("--log-url https://log.example.test/t/globex/ --log-id globex-us");
    expect(sheet).toContain("https://checkpoints.example.test/globex/latest.json");
    expect(sheet).toContain("(current keyid abc)");
    expect(sheet).toContain("hashOnly");
  });
});

describe("the audit trail", () => {
  it("records every tenant and token change with who made it, shows it on the page and the API, and a tenant sees only their own rows in their export route", async () => {
    const basic = (user: string) => ({ authorization: `Basic ${Buffer.from(`${user}:${ADMIN}`).toString("base64")}`, "content-type": "application/json" });
    expect((await fetch(new URL("admin/tenants", log.url), { method: "POST", headers: basic("dana"), body: JSON.stringify({ id: "audited", logId: "audited-eu" }) })).status).toBe(200);
    const minted = (await (await fetch(new URL("admin/tenants/audited/tokens", log.url), { method: "POST", headers: basic("dana"), body: JSON.stringify({ label: "fleet-a" }) })).json()) as { token: string; tokenHash: string };
    const second = (await (await call("POST", "admin/tenants/audited/tokens", { label: "fleet-b" })).json()) as { token: string; tokenHash: string };
    expect((await call("POST", `admin/tenants/audited/tokens/${second.tokenHash.slice(0, 12)}/revoke`)).status).toBe(200);
    await tenancy.addTenant("bystander", "bystander", "cli:test@host");

    const all = ((await (await call("GET", "admin/audit?limit=10")).json()) as { entries: any[] }).entries;
    expect(all[0]).toMatchObject({ actor: "cli:test@host", action: "tenant.add", tenantId: "bystander", detail: { logId: "bystander" } });
    const mine = all.filter((e) => e.tenantId === "audited");
    expect(mine.map((e) => e.action)).toEqual(["token.revoke", "token.add", "token.add", "tenant.add"]);
    expect(mine[3].actor).toMatch(/^admin:dana@/);
    expect(mine[2].actor).toMatch(/^admin:dana@/);
    expect(mine[1].actor).toMatch(/^admin:bearer@/);
    expect(mine[0].detail).toEqual({ hashPrefix: second.tokenHash.slice(0, 12), revoked: 1 });
    expect(mine[2].detail).toEqual({ label: "fleet-a", tokenHash: minted.tokenHash.slice(0, 12) });
    expect(mine.every((e) => typeof e.at === "string" && !JSON.stringify(e).includes(minted.token))).toBe(true);
    const html = await (await call("GET", "admin")).text();
    expect(html).toContain("<h2>Activity</h2>");
    expect(html).toContain("/admin/audit");

    // the tenant's own view, with their token: their rows and nobody else's
    const own = (await (await fetch(new URL("t/audited/audit", log.url), { headers: { authorization: `Bearer ${minted.token}` } })).json()) as { entries: any[] };
    expect(own.entries.map((e) => e.action)).toEqual(["token.revoke", "token.add", "token.add", "tenant.add"]);
    expect(own.entries.some((e) => e.tenantId !== "audited")).toBe(false);
    expect((await fetch(new URL("t/audited/audit", log.url))).status).toBe(401);
    expect((await call("GET", "admin/audit?limit=0")).status).toBe(400);
  });
});

describe("plans and quotas", () => {
  it("a tenant starts on free, the operator moves it, the move is audited, and an append past the plan's monthly allowance is refused with the numbers until the plan grows", async () => {
    const db2 = new PGlite();
    await db2.query("SELECT 1");
    // quotas overridden so the test does not need ten thousand appends
    const t2 = new PostgresTenancy(db2, { prefix: "plan_", quotas: { free: 2, team: 5 } });
    await t2.addTenant("default", "log.example.test");
    await t2.addTenant("acme", "acme-eu", "cli:test@host");
    const tok = (await t2.addToken("acme", "fleet")).token;
    const srv = await serveLog(postgresResolver(t2), generateKeyPair(), { port: 0, admin: { tenancy: t2, token: ADMIN } });
    try {
      expect((await t2.tenant("acme"))!.plan).toBe("free");
      const append = () => fetch(new URL("t/acme/append", srv.url), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${tok}` }, body: JSON.stringify({ leafHash: "cd".repeat(32) }) });
      expect((await append()).status).toBe(200);
      expect((await append()).status).toBe(200);
      const over = await append();
      expect(over.status).toBe(429);
      expect(Number(over.headers.get("retry-after"))).toBeGreaterThan(0);
      expect(((await over.json()) as { error: string }).error).toMatch(/monthly quota reached: 2 of 2 appends on the free plan/);
      expect(await t2.quota("acme")).toEqual({ plan: "free", used: 2, quota: 2 });
      // the tenant sees its plan and quota on its usage route
      const usage = (await (await fetch(new URL("t/acme/usage", srv.url), { headers: { authorization: `Bearer ${tok}` } })).json()) as { plan: string; quota: number; appends: number };
      expect(usage).toMatchObject({ plan: "free", quota: 2, appends: 2 });
      // the operator moves the tenant up; the next append lands; the change is in the audit trail and the usage table
      const set = await fetch(new URL("admin/tenants/acme/plan", srv.url), { method: "POST", headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" }, body: JSON.stringify({ plan: "team" }) });
      expect(set.status).toBe(200);
      expect(((await set.json()) as { plan: string }).plan).toBe("team");
      expect((await append()).status).toBe(200);
      const audit = ((await (await fetch(new URL("admin/audit?tenant=acme&limit=5", srv.url), { headers: { authorization: `Bearer ${ADMIN}` } })).json()) as { entries: { action: string; detail: unknown }[] }).entries;
      expect(audit[0]).toMatchObject({ action: "tenant.plan", detail: { plan: "team" } });
      const u = (await (await fetch(new URL(`admin/usage?month=${new Date().toISOString().slice(0, 7)}`, srv.url), { headers: { authorization: `Bearer ${ADMIN}` } })).json()) as { tenants: { id: string; plan: string; quota: number | null; appends: number }[] };
      expect(u.tenants.find((x) => x.id === "acme")).toMatchObject({ plan: "team", quota: 5, appends: 3 });
      // an unknown plan is refused
      expect((await fetch(new URL("admin/tenants/acme/plan", srv.url), { method: "POST", headers: { authorization: `Bearer ${ADMIN}`, "content-type": "application/json" }, body: JSON.stringify({ plan: "gold" }) })).status).toBe(400);
      // enterprise has no allowance
      await t2.setPlan("acme", "enterprise");
      expect(await t2.quota("acme")).toMatchObject({ plan: "enterprise", quota: null });
      const html = await (await fetch(new URL("admin", srv.url), { headers: { authorization: `Bearer ${ADMIN}` } })).text();
      expect(html).toContain("<th>plan</th>");
    } finally {
      await srv.close();
      await db2.close();
    }
  });
});

describe("registrations", () => {
  it("lists every tenant with who registered it through the portal, its plan and billing state, appends in the month asked for and leaves in total, with totals; a scripted tenant has no email; the CSV carries the same rows", async () => {
    // the operator wants one screen answering: who signed up, on what plan, paying or not, how much have they logged
    const user = await portal.createUser("ops@buyer.example", "correct horse battery staple", { name: "Ola Buyer", company: "Buyer GmbH", role: "CISO", phone: "+49 30 1234", telegram: "olabuyer" });
    await tenancy.addTenant("buyer", "buyer-eu", "test");
    await portal.addMember(user.id, "buyer");
    // registered earlier than the owner, but not the owner
    const colleague = await portal.createUser("rev@buyer.example", "correct horse battery staple");
    await db.query("UPDATE portal_users SET created_at = created_at - interval '1 day' WHERE id = $1", [colleague.id]);
    await portal.addMember(colleague.id, "buyer", "reviewer");
    await portal.setBilling("buyer", { customerId: "cus_1", subscriptionId: "sub_1", status: "active" });
    await tenancy.setPlan("buyer", "team", "test");
    const { token } = await tenancy.addToken("buyer", "fleet", "test");
    for (const h of ["01", "02", "03"]) expect((await fetch(new URL("t/buyer/append", log.url), { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${token}` }, body: JSON.stringify({ leafHash: h.repeat(32) }) })).status).toBe(200);
    const month = new Date().toISOString().slice(0, 7);
    const r = (await (await call("GET", `admin/registrations?month=${month}`)).json()) as { month: string; rows: Record<string, unknown>[]; totals: Record<string, number> };
    expect(r.month).toBe(month);
    const buyer = r.rows.find((x) => x.tenant === "buyer");
    expect(buyer).toMatchObject({ tenant: "buyer", logId: "buyer-eu", plan: "team", email: "ops@buyer.example", name: "Ola Buyer", company: "Buyer GmbH", role: "CISO", phone: "+49 30 1234", telegram: "olabuyer", billing: "active", appends: 3, quota: 1_000_000, totalLeaves: 3, liveTokens: 1, disabled: false });
    expect(typeof buyer?.registeredAt).toBe("string");
    // "default" was added by the test setup, not through the portal: it is listed, with nothing to say about who
    expect(r.rows.find((x) => x.tenant === "default")).toMatchObject({ email: null, name: null, company: null, registeredAt: null, billing: null });
    expect(r.totals.tenants).toBe(r.rows.length);
    expect(r.totals.registered).toBe(1);
    expect(r.totals.appends).toBe(r.rows.reduce((n, x) => n + (x.appends as number), 0));
    expect(r.totals.totalLeaves).toBe(r.rows.reduce((n, x) => n + (x.totalLeaves as number), 0));
    // a month with no appends shows the same tenants at zero, so a quiet month is visible rather than missing
    const quiet = (await (await call("GET", "admin/registrations?month=2020-01")).json()) as { rows: Record<string, unknown>[]; totals: Record<string, number> };
    expect(quiet.rows.find((x) => x.tenant === "buyer")).toMatchObject({ appends: 0, totalLeaves: 3, email: "ops@buyer.example" });
    expect(quiet.totals.appends).toBe(0);
    const csv = await call("GET", `admin/registrations.csv?month=${month}`);
    expect(csv.headers.get("content-type")).toMatch(/text\/csv/);
    const lines = (await csv.text()).trim().split("\n");
    expect(lines[0]).toBe("month,tenant,log_id,plan,email,name,company,role,phone,telegram,registered_at,billing,appends,quota,total_leaves,live_tokens,disabled");
    expect(lines.find((l) => l.includes(",buyer,"))).toMatch(new RegExp(`^${month},buyer,buyer-eu,team,ops@buyer.example,Ola Buyer,Buyer GmbH,CISO,\\+49 30 1234,olabuyer,\\d{4}-.*,active,3,1000000,3,1,false$`));
    // the usage export is what is billed: a column out of place bills the wrong number
    const usageCsv = await call("GET", `admin/usage.csv?month=${month}`);
    expect(usageCsv.headers.get("content-type")).toBe("text/csv; charset=utf-8");
    expect(usageCsv.headers.get("content-disposition")).toBe(`attachment; filename="agent-custody-usage-${month}.csv"`);
    const usageLines = (await usageCsv.text()).trim().split("\n");
    expect(usageLines[0]).toBe("month,tenant,log_id,plan,quota,appends,total_leaves,live_tokens,disabled");
    expect(usageLines).toContain(`${month},buyer,buyer-eu,team,1000000,3,3,1,false`);
    expect([401, 429]).toContain((await call("GET", "admin/registrations", undefined, null)).status); // no token: refused, or throttled by the earlier wrong attempts from this address
    // the page carries the section and its numbers come from the same route
    const html = await (await call("GET", "admin")).text();
    expect(html).toContain("/admin/registrations?month=");
    expect(html).toContain("registered through the portal");
    expect(html).toContain("<th>who</th><th>reach</th>");
  });
});
