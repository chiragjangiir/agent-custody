// The portal is the tenant's own door: register and get a tenant and a key shown once, sign in, see the numbers
// the log keeps, mint and revoke keys, pay. Nothing here is reachable without a session except the Stripe webhook,
// which is reachable only with Stripe's signature. Postgres runs in-process through PGlite; the log server runs
// beside the portal on the same tenancy so the dashboard's numbers come from real appends; Stripe is a stand-in
// that answers the two calls the portal makes.
import { createHmac, generateKeyPairSync } from "node:crypto";
import { Script } from "node:vm";
import { inflateRawSync } from "node:zlib";
import { SignedXml } from "xml-crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { PGlite } from "@electric-sql/pglite";
import { generateKeyPair } from "../src/crypto.ts";
import { httpLog, postgresResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { PostgresTenancy } from "../src/log-store.ts";
import { founderNote, PortalStore, readSession, readSessionVia, ROLES, sendFollowUps, servePortal, signSession, totp, verifyStripeSignature, type Role, type RunningPortal } from "../src/portal.ts";
import { policyDigest } from "../src/policy.ts";
import { standInIdp } from "../scripts/idp-standin.ts";

let db: PGlite;
let tenancy: PostgresTenancy;
let log: RunningLog;
let portal: RunningPortal;
const stripeCalls: { path: string; body: URLSearchParams }[] = [];
const mails: { to: string[]; subject: string; text: string; from: string }[] = [];
/** who GitHub says the signed-in user is; a test changes it to play another person */
let gh = { id: 4242, email: "Octo@Example.com" };
// GitHub's and Google's endpoints, stood in: a code becomes a token, a token becomes a subject and a verified email
const oauthFetch: typeof fetch = async (url, init) => {
  const u = String(url);
  const j = (body: unknown) => new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
  if (u === "https://github.com/login/oauth/access_token") { const b = JSON.parse(String(init?.body)); return j(b.code === "gh-code" && b.client_secret === "gh_secret" ? { access_token: "gh-token" } : { error: "bad_verification_code" }); }
  if (u === "https://api.github.com/user") return j({ id: gh.id, login: "octo" });
  if (u === "https://api.github.com/user/emails") return j([{ email: "old@example.com", primary: false, verified: false }, { email: gh.email, primary: true, verified: true }]);
  if (u === "https://oauth2.googleapis.com/token") { const b = new URLSearchParams(String(init?.body)); const claims = Buffer.from(JSON.stringify({ sub: "g-1", email: "Gina@Example.com", email_verified: true })).toString("base64url"); return j(b.get("code") === "g-code" ? { id_token: `h.${claims}.s` } : { error: "invalid_grant" }); }
  return new Response("not stood in: " + u, { status: 500 });
};
const mailFetch: typeof fetch = async (_url, init) => { mails.push(JSON.parse(String(init?.body))); return new Response("{}", { status: 200 }); };
const stripeFetch: typeof fetch = async (url, init) => {
  const path = String(url).replace("https://api.stripe.com/v1/", "");
  stripeCalls.push({ path, body: new URLSearchParams(String(init?.body ?? "")) });
  if (path === "checkout/sessions") return new Response(JSON.stringify({ id: "cs_test_1", url: "https://checkout.stripe.com/c/pay/cs_test_1" }), { status: 200, headers: { "content-type": "application/json" } });
  if (path === "billing_portal/sessions") return new Response(JSON.stringify({ url: "https://billing.stripe.com/p/session/x" }), { status: 200, headers: { "content-type": "application/json" } });
  return new Response(JSON.stringify({ error: { message: "no such route" } }), { status: 404 });
};
const SECRET = "portal-secret-for-tests-at-least-32-chars-long";
const WHSEC = "whsec_test_secret";

beforeAll(async () => {
  db = new PGlite();
  await db.query("SELECT 1");
  tenancy = new PostgresTenancy(db, { quotas: { free: 3 } });
  await tenancy.addTenant("default", "log.example.test");
  log = await serveLog(postgresResolver(tenancy), generateKeyPair(), { port: 0 });
  portal = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: log.url, checkpointsUrl: "https://checkpoints.example.test/", keyid: "abc123", portalUrl: "https://app.example.test/", stripe: { secretKey: "sk_test_x", webhookSecret: WHSEC, priceTeam: "price_team", fetch: stripeFetch }, mail: { apiKey: "re_test", from: "hello@example.test", notify: "sales@example.test", fetch: mailFetch }, oauth: { github: { clientId: "gh_id", clientSecret: "gh_secret" }, google: { clientId: "g_id", clientSecret: "g_secret" }, fetch: oauthFetch }, log: () => {} }, { port: 0 });
}, 60_000);

afterAll(async () => {
  await portal?.close();
  await log?.close();
  await db?.close();
});

/** a browser: keeps the cookie, sends JSON */
function browser() {
  let cookie = "";
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await fetch(new URL(path, portal.url), { method, headers: { ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    const set = res.headers.get("set-cookie");
    if (set) cookie = set.split(";")[0]!;
    return { status: res.status, json: (await res.json().catch(() => ({}))) as any };
  };
  return { call, cookieValue: () => cookie };
}

describe("the tenant portal", () => {
  it("registers an account with a tenant and a first key shown once, then the dashboard shows the log's numbers as appends land", async () => {
    const b = browser();
    const bad = await b.call("POST", "/api/register", { email: "dana@example.com", password: "short", tenant: "acme" });
    expect(bad.status).toBe(400);
    const taken = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "default" });
    expect(taken.status).toBe(400); // reserved
    // who is registering is part of the record: a name and an organisation are required, the rest is optional and checked for shape
    const nameless = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "acme", company: "Acme" });
    expect(nameless.status).toBe(400);
    expect(nameless.json.error).toMatch(/your name/);
    const badHandle = await b.call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "acme", name: "Dana", company: "Acme", telegram: "@no spaces" });
    expect(badHandle.status).toBe(400);
    const r = await b.call("POST", "/api/register", { email: "Dana@Example.com", password: "a-long-enough-password", tenant: "acme", name: "Dana Ortiz", company: "Acme Ltd", role: "Head of Platform", phone: "+44 20 7946 0000", telegram: "@dana_ortiz" });
    expect(r.status).toBe(200);
    expect(await new PortalStore(db).registrations()).toEqual([{ tenantId: "acme", email: "dana@example.com", registeredAt: expect.any(String), billing: null, name: "Dana Ortiz", company: "Acme Ltd", role: "Head of Platform", phone: "+44 20 7946 0000", telegram: "dana_ortiz" }]);
    expect(r.json).toMatchObject({ tenant: "acme", logId: "acme", plan: "free" });
    expect(r.json.token).toMatch(/^[0-9a-f]{64}$/);
    expect(r.json.welcome).toContain("t/acme/");
    // the same sheet as data, so the page can show it as steps at registration and again under Setup
    expect(r.json.setup).toMatchObject({ log: expect.stringContaining("t/acme/"), logId: "acme", checkpoints: "https://checkpoints.example.test/acme/latest.json", keyid: "abc123", config: expect.stringContaining('"hashOnly": true'), verify: expect.stringContaining("--log-id acme"), export: expect.stringContaining("--tenant acme") });
    expect(r.json.exportCommand).toContain("--tenant acme");
    expect(readSession(SECRET, b.cookieValue().split("=")[1])).toBeTruthy();
    // the same email or tenant again is refused
    expect((await browser().call("POST", "/api/register", { email: "dana@example.com", password: "a-long-enough-password", tenant: "other", name: "Someone", company: "Somewhere" })).status).toBe(409);
    expect((await browser().call("POST", "/api/register", { email: "x@example.com", password: "a-long-enough-password", tenant: "acme", name: "Someone", company: "Somewhere" })).status).toBe(409);

    // one email to the person with the sheet and never the key, one to the operator with the contact details
    await new Promise((r) => setTimeout(r, 50));
    expect(mails.map((m) => [m.to[0], m.subject])).toEqual([["dana@example.com", 'Your agent-custody log "acme" is ready'], ["sales@example.test", "New registration: Acme Ltd (acme)"], ["dana@example.com", "Verify your email address for agent-custody"]]);
    expect(mails[2]!.text).toMatch(/verify-email\?token=/);
    expect(mails[0]!.text).toContain("t/acme/");
    expect(mails[0]!.text).toContain("Hello Dana Ortiz");
    expect(mails[0]!.text).not.toContain(r.json.token);
    expect(mails[1]!.text).toContain("+44 20 7946 0000");
    expect(mails[1]!.text).toContain("@dana_ortiz");
    const pageRes = await fetch(portal.url);
    const page = await pageRes.text();
    // the page's own script must parse: a quote escaped once inside the TypeScript template literal once left the page blank
    for (const m of page.matchAll(/<script>([\s\S]*?)<\/script>/g)) new Script(m[1]!);
    // browsers compile a pattern attribute with the v flag, and drop one that does not compile
    for (const m of page.matchAll(/ pattern="([^"]*)"/g)) new RegExp(`^(?:${m[1]})$`, "v");
    expect(pageRes.headers.get("content-security-policy")).toContain("img-src 'self'");
    expect(page).toContain('data-view="setup"');
    expect(page).toContain('rel="icon" href="/favicon.svg"');
    expect(page).toContain('id="themeToggle"');
    expect(page).toContain(':root[data-theme="dark"]');
    const icon = await fetch(new URL("favicon.svg", portal.url));
    expect(icon.status).toBe(200);
    expect(icon.headers.get("content-type")).toBe("image/svg+xml");
    const me = await b.call("GET", "/api/me");
    expect(me.json).toMatchObject({ email: "dana@example.com", tenant: "acme", plan: "free", used: 0, quota: 3, billing: true });
    // the key works on the log; the dashboard reflects the appends
    const sink = httpLog(`${log.url}t/acme/`, { token: r.json.token, hashOnly: true });
    await sink.append("one");
    await sink.append("two");
    const o = await b.call("GET", "/api/overview");
    expect(o.json).toMatchObject({ tenant: "acme", used: 2, quota: 3, treeSize: 2, latestCheckpoint: null });
    expect(o.json.months.at(-1)).toMatchObject({ appends: 2 });
    expect(o.json.keys).toHaveLength(1);
    expect(o.json.audit.map((e: any) => e.action)).toEqual(["token.add", "tenant.add"]);
    expect(o.json.audit[1].actor).toBe("portal:dana@example.com");
    expect(o.json.urls.checkpoints).toBe("https://checkpoints.example.test/acme/latest.json");
  });

  it("signs in and out, throttles wrong passwords, and refuses every tenant route without a session or with a forged cookie", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/login", { email: "dana@example.com", password: "wrong-password!" })).status).toBe(401);
    expect((await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" })).status).toBe(200);
    expect((await b.call("GET", "/api/me")).status).toBe(200);
    expect((await b.call("POST", "/api/logout", {})).status).toBe(200);
    expect((await b.call("GET", "/api/me")).status).toBe(401);
    const forged = await fetch(new URL("/api/me", portal.url), { headers: { cookie: `custody_session=${signSession("another-secret-that-is-not-the-one", "someone")}` } });
    expect(forged.status).toBe(401);
    // a write without a JSON body is refused even with a session, which is the cross-site guard
    const c = browser();
    await c.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const noJson = await fetch(new URL("/api/keys", portal.url), { method: "POST", headers: { cookie: c.cookieValue() }, body: "label=x" });
    expect(noJson.status).toBe(415);
    const page = await fetch(portal.url);
    expect(page.headers.get("content-security-policy")).toMatch(/default-src 'none'/);
    const html = await page.text();
    expect(html).toContain("API keys");
    expect(html).toContain("https://docs.agent-custody.dev/reference/");
    expect(html).toContain("https://agent-custody.dev/verify");
  });

  it("mints and revokes keys with the portal user as the actor, and a revoked key stops appending", async () => {
    const b = browser();
    await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const m = await b.call("POST", "/api/keys", { label: "second fleet" });
    expect(m.status).toBe(200);
    expect(m.json.token).toMatch(/^[0-9a-f]{64}$/);
    const keys = (await b.call("GET", "/api/keys")).json.keys;
    expect(keys.map((k: any) => k.label)).toEqual(["first key", "second fleet"]);
    const sink = httpLog(`${log.url}t/acme/`, { token: m.json.token, hashOnly: true, retries: 1 });
    await sink.append("three");
    expect((await b.call("POST", `/api/keys/${m.json.tokenHash}/revoke`, {})).json).toEqual({ revoked: 1 });
    await expect(sink.append("four")).rejects.toThrow(/401/);
    const o = await b.call("GET", "/api/overview");
    expect(o.json.audit[0]).toMatchObject({ action: "token.revoke", actor: "portal:dana@example.com" });
    // and the free allowance is now used up: the dashboard says so
    expect(o.json).toMatchObject({ used: 3, quota: 3 });
  });

  it("checkout sends the tenant to Stripe with the right price and reference; the signed webhook moves the plan to team; a cancellation moves it back; a bad signature, a replayed event, and an out-of-order event change nothing", async () => {
    const b = browser();
    await b.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    const c = await b.call("POST", "/api/checkout", {});
    expect(c.json.url).toBe("https://checkout.stripe.com/c/pay/cs_test_1");
    const call = stripeCalls.find((x) => x.path === "checkout/sessions")!;
    expect(call.body.get("mode")).toBe("subscription");
    expect(call.body.get("line_items[0][price]")).toBe("price_team");
    expect(call.body.get("client_reference_id")).toBe("acme");
    expect(call.body.get("success_url")).toBe("https://app.example.test/?upgraded=1");
    const t0 = Math.floor(Date.now() / 1000);
    const event = (id: string, created: number, type: string, object: Record<string, unknown>) => JSON.stringify({ id, created, type, data: { object } });
    const signed = (payload: string, secret = WHSEC) => { const t = Math.floor(Date.now() / 1000); return `t=${t},v1=${createHmac("sha256", secret).update(`${t}.${payload}`).digest("hex")}`; };
    const post = (payload: string, sig: string) => fetch(new URL("/stripe/webhook", portal.url), { method: "POST", headers: { "content-type": "application/json", "stripe-signature": sig }, body: payload });
    const completed = event("evt_1", t0, "checkout.session.completed", { id: "cs_test_1", client_reference_id: "acme", customer: "cus_1", subscription: "sub_1" });
    expect((await post(completed, signed(completed, "whsec_wrong"))).status).toBe(400);
    expect((await post(completed, signed(completed))).status).toBe(200);
    expect((await tenancy.tenant("acme"))!.plan).toBe("team");
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ plan: "team", quota: 1_000_000 });
    expect((await b.call("GET", "/api/overview")).json.billing).toEqual({ status: "active" });
    // paying again is refused; managing billing goes to Stripe's portal for the customer on record
    expect((await b.call("POST", "/api/checkout", {})).status).toBe(409);
    expect((await b.call("POST", "/api/billing-portal", {})).json.url).toBe("https://billing.stripe.com/p/session/x");
    expect(stripeCalls.find((x) => x.path === "billing_portal/sessions")!.body.get("customer")).toBe("cus_1");
    const deleted = event("evt_2", t0 + 10, "customer.subscription.deleted", { id: "sub_1", status: "canceled" });
    expect((await post(deleted, signed(deleted))).status).toBe(200);
    expect((await tenancy.tenant("acme"))!.plan).toBe("free");
    // Stripe redelivers the checkout: the event id was applied already, so the plan stays free (issue #105)
    expect(await (await post(completed, signed(completed))).json()).toEqual({ received: true, duplicate: true });
    expect((await tenancy.tenant("acme"))!.plan).toBe("free");
    // an update created before the cancellation arrives after it: older than the stored state, so ignored
    const late = event("evt_3", t0 + 5, "customer.subscription.updated", { id: "sub_1", status: "active" });
    expect((await post(late, signed(late))).status).toBe(200);
    expect((await tenancy.tenant("acme"))!.plan).toBe("free");
    expect((await b.call("GET", "/api/overview")).json.billing).toEqual({ status: "canceled" });
    // an event without an id or a created time is refused
    const bare = JSON.stringify({ type: "customer.subscription.updated", data: { object: { id: "sub_1", status: "active" } } });
    expect((await post(bare, signed(bare))).status).toBe(400);
    const audit = (await b.call("GET", "/api/overview")).json.audit;
    expect(audit.slice(0, 2).map((e: any) => [e.action, e.actor, e.detail.plan])).toEqual([["tenant.plan", "stripe:customer.subscription.deleted", "free"], ["tenant.plan", "stripe:checkout", "team"]]);
    // an old timestamp is refused even with a valid mac
    const stale = `t=${Math.floor(Date.now() / 1000) - 3600},v1=${createHmac("sha256", WHSEC).update(`${Math.floor(Date.now() / 1000) - 3600}.${deleted}`).digest("hex")}`;
    expect(verifyStripeSignature(stale, deleted, WHSEC)).toBe(false);
  });

  it("password hashing is scrypt with a fresh salt, and a stored hash never verifies the wrong password", () => {
    const h1 = PortalStore.hashPassword("correct horse battery");
    const h2 = PortalStore.hashPassword("correct horse battery");
    expect(h1).not.toBe(h2);
    expect(h1.startsWith("scrypt$")).toBe(true);
    expect(PortalStore.checkPassword("correct horse battery", h1)).toBe(true);
    expect(PortalStore.checkPassword("correct horse batter", h1)).toBe(false);
    expect(PortalStore.checkPassword("x", "garbage")).toBe(false);
  });
});

describe("policies", () => {
  it("a tenant publishes named policy versions whose digest is exactly the policyDigest the gateway writes, matches a receipt's digest to a name, sees the text, removes a version, and every change is in the audit trail; the same text twice is refused", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/register", { email: "pol@example.com", password: "a-long-enough-password", tenant: "polco", name: "Pol", company: "Polco" })).status).toBe(200);
    const text = 'permit(principal, action == Action::"stripe.refund", resource) when { context.args.amount <= 100000 };\n';
    const published = await b.call("POST", "/api/policies", { name: "refunds-v1", text });
    expect(published.status).toBe(200);
    expect(published.json.policy).toMatchObject({ name: "refunds-v1", digest: policyDigest(text), bytes: text.length, createdBy: "portal:pol@example.com" });
    const id = published.json.policy.id as string;
    expect((await b.call("POST", "/api/policies", { name: "refunds-v1-again", text })).status).toBe(409); // same bytes, already named
    expect((await b.call("POST", "/api/policies", { name: "", text })).status).toBe(400);
    const listed = await b.call("GET", "/api/policies");
    expect(listed.json.policies.map((p: { name: string }) => p.name)).toEqual(["refunds-v1"]);
    // the digest a receipt carries reads as the name; a digest nobody published reads as nothing, not an error
    expect((await b.call("GET", `/api/policies?digest=${policyDigest(text)}`)).json.match).toMatchObject({ id, name: "refunds-v1" });
    expect((await b.call("GET", `/api/policies?digest=${"0".repeat(64)}`)).json.match).toBeNull();
    expect((await b.call("GET", "/api/policies?digest=nope")).status).toBe(400);
    expect((await b.call("GET", `/api/policies/${id}`)).json.policy.text).toBe(text);
    expect((await b.call("POST", `/api/policies/${id}/remove`, {})).json).toEqual({ removed: true });
    expect((await b.call("GET", "/api/policies")).json.policies).toEqual([]);
    const audit = (await tenancy.audit({ tenant: "polco" })).map((e) => e.action);
    expect(audit.slice(0, 2)).toEqual(["policy.remove", "policy.add"]);
    // another tenant's session never sees it
    const page = await (await fetch(portal.url)).text();
    expect(page).toContain('data-view="policies"');
  });
});

describe("two-step registration and provider sign-in", () => {
  it("an account first, the tenant on the next screen: register with email and password, /api/me says no tenant, the tenant routes refuse, onboard creates the tenant and the first key and sends the two emails", async () => {
    const b = browser();
    const r = await b.call("POST", "/api/register", { email: "Two@Example.com", password: "a-long-enough-password" });
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ email: "two@example.com", tenant: null, emailVerified: false });
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ email: "two@example.com", tenant: null, profile: { name: null, company: null } });
    expect((await b.call("GET", "/api/overview")).status).toBe(409);
    expect((await b.call("POST", "/api/onboard", { tenant: "twoco", company: "Two Co" })).status).toBe(400); // a name is needed
    const before = mails.length;
    const on = await b.call("POST", "/api/onboard", { tenant: "twoco", name: "Tu Two", company: "Two Co", role: "CTO" });
    expect(on.status).toBe(200);
    expect(on.json).toMatchObject({ tenant: "twoco", logId: "twoco", plan: "free" });
    expect(on.json.token).toMatch(/^[0-9a-f]{64}$/);
    expect(on.json.setup.log).toContain("t/twoco/");
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ email: "two@example.com", tenant: "twoco", plan: "free" });
    expect((await b.call("POST", "/api/onboard", { tenant: "twoco2", name: "Tu", company: "Two" })).status).toBe(409); // one tenant per account
    await new Promise((r) => setTimeout(r, 50));
    expect(mails.slice(before).map((m) => [m.to[0], m.subject])).toEqual([["two@example.com", 'Your agent-custody log "twoco" is ready'], ["sales@example.test", "New registration: Two Co (twoco)"]]);
    expect(mails[before]!.text).toContain("Hello Tu Two");
    const store = new PortalStore(db);
    expect((await store.registrations()).find((x) => x.tenantId === "twoco")).toMatchObject({ email: "two@example.com", name: "Tu Two", company: "Two Co", role: "CTO" });
  });

  it("GitHub and Google sign-in: the start sets a signed state and redirects to the provider; the callback with that state exchanges the code, takes the verified email, links or creates the account, and sets the session; a wrong state is refused; the same subject twice is the same account; the page offers both", async () => {
    const start = await fetch(new URL("auth/github", portal.url), { redirect: "manual" });
    expect(start.status).toBe(302);
    const to = new URL(start.headers.get("location")!);
    expect(to.origin + to.pathname).toBe("https://github.com/login/oauth/authorize");
    expect(to.searchParams.get("client_id")).toBe("gh_id");
    expect(to.searchParams.get("redirect_uri")).toBe("https://app.example.test/auth/github/callback");
    const state = to.searchParams.get("state")!;
    const stateCookie = start.headers.get("set-cookie")!.split(";")[0]!;
    expect(stateCookie).toBe(`custody_oauth=${state}`);
    // a callback whose state is not the one in the cookie is refused before any exchange
    expect((await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}x`, portal.url), { headers: { cookie: stateCookie } })).status).toBe(400);
    expect((await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url))).status).toBe(400); // no cookie
    const cb = await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url), { headers: { cookie: stateCookie } });
    expect(cb.status).toBe(200);
    expect(cb.headers.get("content-type")).toMatch(/text\/html/);
    const setCookies = cb.headers.getSetCookie();
    const session = setCookies.find((c) => c.startsWith("custody_session="))!;
    expect(session).toContain("SameSite=Strict");
    expect(setCookies.find((c) => c.startsWith("custody_oauth="))).toContain("Max-Age=0");
    const meRes = await fetch(new URL("api/me", portal.url), { headers: { cookie: session.split(";")[0]! } });
    expect(await meRes.json()).toMatchObject({ email: "octo@example.com", tenant: null });
    // again with the same subject: the same account, not a second one
    const again = await fetch(new URL("auth/github", portal.url), { redirect: "manual" });
    const st2 = new URL(again.headers.get("location")!).searchParams.get("state")!;
    const cb2 = await fetch(new URL(`auth/github/callback?code=gh-code&state=${st2}`, portal.url), { headers: { cookie: `custody_oauth=${st2}` } });
    const s2 = cb2.headers.getSetCookie().find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    const uid1 = readSession(SECRET, session.split(";")[0]!.split("=")[1]!);
    expect(readSession(SECRET, s2.split("=")[1]!)).toBe(uid1);
    // a bad code is a provider failure, reported, no session
    const st3 = new URL((await fetch(new URL("auth/github", portal.url), { redirect: "manual" })).headers.get("location")!).searchParams.get("state")!;
    expect((await fetch(new URL(`auth/github/callback?code=wrong&state=${st3}`, portal.url), { headers: { cookie: `custody_oauth=${st3}` } })).status).toBe(502);
    // Google, through the id token
    const g = await fetch(new URL("auth/google", portal.url), { redirect: "manual" });
    const gto = new URL(g.headers.get("location")!);
    expect(gto.origin + gto.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(gto.searchParams.get("scope")).toBe("openid email");
    const gstate = gto.searchParams.get("state")!;
    const gcb = await fetch(new URL(`auth/google/callback?code=g-code&state=${gstate}`, portal.url), { headers: { cookie: `custody_oauth=${gstate}` } });
    expect(gcb.status).toBe(200);
    const gs = gcb.headers.getSetCookie().find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(await (await fetch(new URL("api/me", portal.url), { headers: { cookie: gs } })).json()).toMatchObject({ email: "gina@example.com", tenant: null });
    const page = await (await fetch(portal.url)).text();
    expect(page).toContain('["github","google"]');
    expect(page).toContain('id="onboardForm"');
  });
});

describe("email verification and account linking (issue #103)", () => {
  const verifyLinkFor = (email: string) => { const m = [...mails].reverse().find((x) => x.to[0] === email && /Verify your email/.test(x.subject))!; return new URL(/(https?:\S+verify-email\?token=\S+)/.exec(m.text)![1]!); };
  const ghSignIn = async (cookie?: string, link = false) => {
    const start = await fetch(new URL(`auth/github${link ? "?link=1" : ""}`, portal.url), { redirect: "manual", headers: cookie ? { cookie } : {} });
    if (start.status !== 302) return { status: start.status, setCookies: [] as string[], text: await start.text() };
    const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
    // the callback is a cross-site redirect: the Strict session cookie is not sent, only the state cookie
    const cb = await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, portal.url), { headers: { cookie: `custody_oauth=${state}` } });
    return { status: cb.status, setCookies: cb.headers.getSetCookie(), text: await cb.text() };
  };

  it("a password account is unverified until its link is used; a provider sign-in for that address is refused and links only once the address is verified", async () => {
    const b = browser();
    expect((await b.call("POST", "/api/register", { email: "vera@example.com", password: "a-long-enough-password" })).json).toEqual({ email: "vera@example.com", tenant: null, emailVerified: false });
    await new Promise((r) => setTimeout(r, 50));
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ emailVerified: false, identities: [], providers: ["github", "google"], mail: true });
    const uid = readSession(SECRET, b.cookieValue().split("=")[1]!);
    // an attacker-shaped situation: GitHub vouches for vera@example.com, but the password account never verified it
    gh = { id: 777, email: "Vera@Example.com" };
    const refused = await ghSignIn();
    expect(refused.status).toBe(409);
    expect(refused.text).toMatch(/Sign in with its password/);
    expect(refused.text).not.toMatch(/verify the address/);
    expect(refused.setCookies.find((c) => c.startsWith("custody_session="))).toBeUndefined();
    // a bad link does nothing
    expect((await fetch(new URL("verify-email?token=nope", portal.url))).status).toBe(400);
    // the attack path: the victim opens the link the attacker's registration caused to be mailed; with no session of the account it verifies nothing
    const link = verifyLinkFor("vera@example.com");
    const opened = await fetch(new URL(link.pathname + link.search, portal.url));
    expect(opened.status).toBe(200);
    const token = link.searchParams.get("token")!;
    const post = (cookie?: string) => fetch(new URL("api/verify-email", portal.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify({ token }) });
    expect((await post()).status).toBe(401);
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ emailVerified: false });
    expect((await ghSignIn()).status).toBe(409);
    // another account's session does not verify it either
    const other = browser();
    await other.call("POST", "/api/login", { email: "dana@example.com", password: "a-long-enough-password" });
    expect((await post(other.cookieValue())).status).toBe(403);
    // the owner's own session does
    expect((await post(b.cookieValue())).status).toBe(200);
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ emailVerified: true });
    // now the provider sign-in links to the verified account and signs it in: same account, no second one
    const ok = await ghSignIn();
    expect(ok.status).toBe(200);
    const session = ok.setCookies.find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(readSession(SECRET, session.split("=")[1]!)).toBe(uid);
    // resend is a no-op once verified
    expect((await b.call("POST", "/api/verify-email/resend", {})).json).toEqual({ ok: true, emailVerified: true });
    gh = { id: 4242, email: "Octo@Example.com" };
  });

  it("a signed-in account links a provider from its session even when the provider's email differs, and that identity then signs into the same account", async () => {
    // the verified account from the previous test, signed in with its password (a sixth registration would hit the throttle)
    const b = browser();
    expect((await b.call("POST", "/api/login", { email: "vera@example.com", password: "a-long-enough-password" })).status).toBe(200);
    const uid = readSession(SECRET, b.cookieValue().split("=")[1]!);
    gh = { id: 888, email: "Someone@Else.com" };
    expect((await ghSignIn(undefined, true)).status).toBe(401); // linking needs a session
    const linked = await ghSignIn(b.cookieValue(), true);
    expect(linked.status, linked.text).toBe(200);
    expect(linked.text).toMatch(/GitHub is linked to vera@example.com/);
    expect((await b.call("GET", "/api/me")).json).toMatchObject({ identities: ["github"], emailVerified: true });
    const again = await ghSignIn();
    expect(again.status).toBe(200);
    const session = again.setCookies.find((c) => c.startsWith("custody_session="))!.split(";")[0]!;
    expect(readSession(SECRET, session.split("=")[1]!)).toBe(uid);
    gh = { id: 4242, email: "Octo@Example.com" };
  });
});

describe("the founder's note", () => {
  it("goes once to each registration between an hour and a week old, by name and tenant, never to the operator's own domains, is retried after a provider failure, and a dry run sends nothing", async () => {
    const store = new PortalStore(db);
    const t0 = new Date("2026-09-29T07:00:00Z");
    const mk = async (email: string, name: string, tenant: string, at: Date) => {
      const u = await store.createUser(email, "a-long-enough-password", { name, company: "Co " + tenant });
      await tenancy.addTenant(tenant, tenant, "test");
      await store.addMember(u.id, tenant);
      await db.query("UPDATE portal_users SET created_at = $2 WHERE id = $1", [u.id, at.toISOString()]);
      return u;
    };
    await mk("burak@example.com", "Burak Yilmaz", "zyai", new Date(t0.getTime() - 2 * 3_600_000));     // two hours old: due
    await mk("fresh@example.com", "Fresh One", "fresh", new Date(t0.getTime() - 10 * 60_000));           // ten minutes old: not yet
    await mk("old@example.com", "Old One", "oldco", new Date(t0.getTime() - 9 * 86_400_000));           // nine days old: too late, left alone
    await mk("ops@example.test", "Us", "usco", new Date(t0.getTime() - 3 * 3_600_000));                  // our own domain: marked, not written to
    const captured: { to: string[]; subject: string; text: string }[] = [];
    let refuse = false;
    const mailFetch: typeof fetch = async (_u, init) => { if (refuse) return new Response("nope", { status: 500 }); captured.push(JSON.parse(String(init?.body))); return new Response("{}", { status: 200 }); };
    const mail = { apiKey: "re", from: "Partha <partha@example.test>", notify: "partha@example.test", fetch: mailFetch };
    const dry = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, dryRun: true, log: () => {} });
    expect(dry.sent).toEqual(["burak@example.com"]);
    expect(captured).toHaveLength(0);
    refuse = true;
    const first = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} });
    expect(first).toEqual({ sent: [], skipped: ["ops@example.test"], failed: ["burak@example.com"] });
    refuse = false;
    const second = await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} });
    expect(second).toEqual({ sent: ["burak@example.com"], skipped: [], failed: [] });
    expect(captured).toHaveLength(1);
    expect(captured[0]!.to).toEqual(["burak@example.com"]);
    expect(captured[0]!.subject).toBe("Welcome to agent-custody, and one question");
    expect(captured[0]!.text).toContain("Hi Burak,");
    expect(captured[0]!.text).toContain("registering zyai");
    expect(captured[0]!.text).toContain("at Co zyai?");
    expect(captured[0]!.text).toContain('"mode": "observe"');
    expect(captured[0]!.text).toContain("partha@example.test");
    // once only, and the ten-minute-old one becomes due later
    expect((await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: t0, log: () => {} })).sent).toEqual([]);
    expect((await sendFollowUps(store, mail, { portalUrl: "https://app.example.test/", now: new Date(t0.getTime() + 2 * 3_600_000), log: () => {} })).sent).toContain("fresh@example.com"); // other tests' registrations may be due too
    expect(founderNote({ name: "Solo", tenant: "t", company: null, portalUrl: "https://p/", from: "x@y.z" }).text).toContain("What are you building?");
  });
});

// A second portal behind a "proxy": each test plays its own address, so it has its own throttle bucket.
describe("roles, invites, and two-step sign-in", () => {
  let p2: RunningPortal;
  const hit = async (method: string, path: string, body?: unknown, cookie?: string, ip = "10.9.9.9") => {
    const res = await fetch(new URL(path, p2.url), { method, headers: { "x-forwarded-for": ip, ...(cookie ? { cookie } : {}), ...(body !== undefined ? { "content-type": "application/json" } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
    return { status: res.status, json: (await res.json().catch(() => ({}))) as any, cookies: res.headers.getSetCookie() };
  };
  const as = (id: string) => `custody_session=${signSession(SECRET, id)}`;
  const account = async (email: string, tenant?: string, role: Role = "owner", verified = true) => {
    const u = await new PortalStore(db).createUser(email, "a-long-enough-password");
    if (verified) await new PortalStore(db).markEmailVerified(u.id);
    if (tenant) await new PortalStore(db).addMember(u.id, tenant, role);
    return { ...u, cookie: as(u.id) };
  };
  const b32decode = (s: string) => Buffer.from([...s].map((c) => "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".indexOf(c).toString(2).padStart(5, "0")).join("").match(/.{8}/g)!.map((b) => parseInt(b, 2)));
  const cookieOf = (cookies: string[], name: string) => cookies.find((c) => c.startsWith(`${name}=`));

  beforeAll(async () => {
    p2 = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: log.url, portalUrl: "https://app.example.test/", trustProxy: true, stripe: { secretKey: "sk_test_x", webhookSecret: WHSEC, priceTeam: "price_team", fetch: stripeFetch }, mail: { apiKey: "re_test", from: "hello@example.test", fetch: mailFetch }, oauth: { github: { clientId: "gh_id", clientSecret: "gh_secret" }, fetch: oauthFetch }, log: () => {} }, { port: 0 });
  }, 60_000);
  afterAll(async () => { await p2?.close(); });
  afterEach(() => { vi.restoreAllMocks(); });

  it("each role may do its tier and the tiers below it, and a refusal is a 403 that names the role needed", async () => {
    await tenancy.addTenant("rbac", "rbac", "test");
    await new PortalStore(db).setBilling("rbac", { customerId: "cus_rbac", status: "active" });
    const writes: { least: Role; call: (cookie: string, who: Role) => ReturnType<typeof hit> }[] = [
      { least: "readonly", call: (c) => hit("GET", "/api/members", undefined, c) },
      { least: "reviewer", call: (c, who) => hit("POST", "/api/policies", { name: `v-${who}`, text: `permit(principal, action, resource); // ${who}` }, c) },
      { least: "reviewer", call: async (c, who) => hit("POST", `/api/policies/${(await tenancy.addPolicy("rbac", `rm-${who}`, `permit(principal, action, resource); // rm ${who}`, "test")).id}/remove`, {}, c) },
      { least: "admin", call: (c, who) => hit("POST", "/api/keys", { label: who }, c) },
      { least: "owner", call: (c) => hit("POST", "/api/checkout", {}, c) },
      { least: "owner", call: (c) => hit("POST", "/api/billing-portal", {}, c) },
    ];
    for (const role of ROLES) {
      const { cookie } = await account(`${role}@rbac.example`, "rbac", role);
      for (const w of writes) {
        const r = await w.call(cookie, role);
        expect([role, w.least, r.status]).toEqual([role, w.least, ROLES.indexOf(role) >= ROLES.indexOf(w.least) ? 200 : 403]);
        if (r.status === 403) expect(r.json.error).toContain(`${w.least} role`);
      }
      expect((await hit("GET", "/api/me", undefined, cookie)).json.role).toBe(role);
    }
  });

  it("an admin never touches an owner or grants owner, the last owner stays, and an owner can hand the tenant over", async () => {
    await tenancy.addTenant("rbac2", "rbac2", "test");
    const owner = await account("o1@rbac2.example", "rbac2", "owner");
    const admin = await account("ad@rbac2.example", "rbac2", "admin");
    const reviewer = await account("rv@rbac2.example", "rbac2", "reviewer");
    const roleOf = (id: string, role: string, who: { cookie: string }) => hit("POST", `/api/members/${id}/role`, { role }, who.cookie);
    expect((await roleOf(owner.id, "reviewer", admin)).status).toBe(403);
    expect((await roleOf(reviewer.id, "owner", admin)).status).toBe(403);
    expect((await hit("POST", `/api/members/${owner.id}/remove`, {}, admin.cookie)).status).toBe(403);
    expect((await hit("POST", "/api/members", { email: "x@rbac2.example", role: "owner" }, admin.cookie)).status).toBe(403);
    expect((await hit("POST", "/api/members", { email: "x2@rbac2.example", role: "owner" }, owner.cookie)).status).toBe(200);
    expect((await hit("POST", "/api/invites/remove", { email: "x2@rbac2.example" }, admin.cookie)).status).toBe(403);
    expect((await hit("POST", "/api/members", { email: "x2@rbac2.example", role: "readonly" }, admin.cookie)).status).toBe(403);
    expect((await hit("POST", "/api/invites/remove", { email: "x2@rbac2.example" }, owner.cookie)).json).toEqual({ removed: true });
    expect((await roleOf(reviewer.id, "admin", admin)).status).toBe(200);
    expect((await roleOf(owner.id, "admin", owner)).status).toBe(409);
    expect((await hit("POST", `/api/members/${owner.id}/remove`, {}, owner.cookie)).status).toBe(409);
    expect((await roleOf(admin.id, "owner", owner)).status).toBe(200);
    expect((await roleOf(owner.id, "admin", owner)).status).toBe(200);
    expect((await roleOf(admin.id, "reviewer", admin)).status).toBe(409);
    const list = (await hit("GET", "/api/members", undefined, admin.cookie)).json;
    expect(list.members.map((m: any) => [m.email, m.role, m.mfa])).toEqual([["o1@rbac2.example", "admin", false], ["ad@rbac2.example", "owner", false], ["rv@rbac2.example", "admin", false]]);
    expect(list.members[0].joinedAt).toEqual(expect.any(String));
  });

  it("an invite mails the invitee; accepting needs a verified address and an account with no tenant; an old invite is gone; a removed member loses access on its next request", async () => {
    await tenancy.addTenant("rbac3", "rbac3", "test");
    const owner = await account("o@rbac3.example", "rbac3", "owner");
    const before = mails.length;
    expect((await hit("POST", "/api/members", { email: "New@Rbac3.example", role: "reviewer" }, owner.cookie)).json).toEqual({ invited: "new@rbac3.example", role: "reviewer" });
    expect((await hit("POST", "/api/members", { email: "new@rbac3.example", role: "readonly" }, owner.cookie)).status).toBe(200);
    await new Promise((r) => setTimeout(r, 50));
    expect(mails.slice(before).map((m) => m.to[0])).toEqual(["new@rbac3.example", "new@rbac3.example"]);
    expect(mails[before]!.text).toContain("https://app.example.test/");
    expect((await hit("GET", "/api/members", undefined, owner.cookie)).json.invites).toMatchObject([{ email: "new@rbac3.example", role: "readonly", invitedBy: "o@rbac3.example" }]);

    const invitee = await account("new@rbac3.example", undefined, "owner", false);
    expect((await hit("GET", "/api/me", undefined, invitee.cookie)).json).toMatchObject({ tenant: null, invites: [{ tenant: "rbac3", role: "readonly" }] });
    const refused = await hit("POST", "/api/invites/accept", { tenant: "rbac3" }, invitee.cookie);
    expect(refused.status).toBe(403);
    expect(refused.json.error).toMatch(/verify your email/);
    await new PortalStore(db).markEmailVerified(invitee.id);
    expect((await hit("POST", "/api/invites/accept", { tenant: "rbac3" }, invitee.cookie)).json).toEqual({ tenant: "rbac3", role: "readonly" });
    expect((await hit("GET", "/api/me", undefined, invitee.cookie)).json).toMatchObject({ tenant: "rbac3", role: "readonly" });
    expect((await hit("GET", "/api/members", undefined, owner.cookie)).json.invites).toEqual([]);

    const busy = await account("busy@rbac3.example", "rbac", "owner");
    await hit("POST", "/api/members", { email: "busy@rbac3.example", role: "admin" }, owner.cookie);
    expect((await hit("POST", "/api/invites/accept", { tenant: "rbac3" }, busy.cookie)).status).toBe(409);
    const late = await account("late@rbac3.example");
    await hit("POST", "/api/members", { email: "late@rbac3.example", role: "admin" }, owner.cookie);
    await db.query("UPDATE portal_invites SET created_at = now() - interval '8 days' WHERE email = 'late@rbac3.example'");
    expect((await hit("GET", "/api/me", undefined, late.cookie)).json.invites).toEqual([]);
    expect((await hit("POST", "/api/invites/accept", { tenant: "rbac3" }, late.cookie)).status).toBe(404);
    expect((await hit("POST", "/api/invites/remove", { email: "late@rbac3.example" }, owner.cookie)).json).toEqual({ removed: true });

    expect((await hit("GET", "/api/overview", undefined, invitee.cookie)).status).toBe(200);
    expect((await hit("POST", `/api/members/${invitee.id}/remove`, {}, owner.cookie)).json).toEqual({ removed: true });
    expect((await hit("GET", "/api/overview", undefined, invitee.cookie)).status).toBe(409);
  });

  it("an invite sent before the tenant enforced single sign-on cannot be accepted afterwards", async () => {
    await tenancy.addTenant("rbac4", "rbac4", "test");
    const owner = await account("o@rbac4.example", "rbac4", "owner");
    expect((await hit("POST", "/api/members", { email: "late@rbac4.example", role: "admin" }, owner.cookie)).status).toBe(200);
    await new PortalStore(db).setSso({ tenant: "rbac4", protocol: "oidc", config: { issuer: "https://idp.rbac4.example", clientId: "c", clientSecret: "s" }, domains: ["rbac4.example"], defaultRole: "readonly", enforced: true });
    const invitee = await account("late@rbac4.example");
    const refused = await hit("POST", "/api/invites/accept", { tenant: "rbac4" }, invitee.cookie);
    expect(refused.status).toBe(409);
    expect(refused.json.error).toMatch(/identity provider/);
    expect(await new PortalStore(db).roleOf(invitee.id, "rbac4")).toBeNull();
  });

  // Time stands still in the middle of a step, so the window does not move during a test.
  const midStep = () => { const t = Math.floor(Date.now() / 30_000) * 30_000 + 15_000; vi.spyOn(Date, "now").mockReturnValue(t); return Math.floor(t / 30_000); };

  it("TOTP matches the RFC 6238 vectors", () => {
    const key = Buffer.from("12345678901234567890");
    // the last six digits of the RFC's eight-digit codes
    expect([1, 37037036, 37037037, 41152263, 66666666].map((step) => totp(key, step))).toEqual(["287082", "081804", "050471", "005924", "279037"]);
  });

  it("turns on with a code from the secret it shows, signs in in two steps with no session in between, refuses a replayed code, and turns off with a current code", async () => {
    const step = midStep();
    await tenancy.addTenant("mfa1", "mfa1", "test");
    const user = await account("mfa1@example.com", "mfa1");
    const ip = "10.1.0.1";
    const plain = await hit("POST", "/api/login", { email: "mfa1@example.com", password: "a-long-enough-password" }, undefined, ip);
    expect(cookieOf(plain.cookies, "custody_session")).toBeDefined();
    const setup = await hit("POST", "/api/mfa/setup", {}, user.cookie, ip);
    expect(setup.json.uri).toMatch(/^otpauth:\/\/totp\/agent-custody:mfa1%40example\.com\?secret=[A-Z2-7]{32}&issuer=agent-custody$/);
    expect(setup.json.uri).toContain(`secret=${setup.json.secret}`);
    const key = b32decode(setup.json.secret);
    expect(key).toHaveLength(20);
    expect((await hit("POST", "/api/mfa/enable", { code: totp(key, step + 5) }, user.cookie, ip)).status).toBe(401);
    expect((await hit("POST", "/api/mfa/enable", { code: totp(key, step - 1) }, user.cookie, ip)).json).toEqual({ mfa: true });
    expect((await hit("POST", "/api/mfa/setup", {}, user.cookie, ip)).status).toBe(409);

    const first = await hit("POST", "/api/login", { email: "mfa1@example.com", password: "a-long-enough-password" }, undefined, ip);
    expect(first.json).toEqual({ mfa: true });
    expect(cookieOf(first.cookies, "custody_session")).toBeUndefined();
    const half = cookieOf(first.cookies, "custody_mfa")!;
    expect(half).toMatch(/Path=\/api\/login; HttpOnly; SameSite=Strict; Secure/);
    const halfCookie = half.split(";")[0]!;
    expect((await hit("GET", "/api/me", undefined, halfCookie.replace("custody_mfa", "custody_session"), ip)).status).toBe(401);
    expect((await hit("POST", "/api/login/mfa", { code: totp(key, step) }, undefined, ip)).status).toBe(401);
    const second = await hit("POST", "/api/login/mfa", { code: totp(key, step) }, halfCookie, ip);
    expect(second.status).toBe(200);
    const session = cookieOf(second.cookies, "custody_session")!;
    expect(session).toMatch(/HttpOnly; SameSite=Strict/);
    expect(cookieOf(second.cookies, "custody_mfa")).toContain("Max-Age=0");
    expect((await hit("GET", "/api/me", undefined, session.split(";")[0], ip)).json).toMatchObject({ mfa: true, tenant: "mfa1" });
    const again = await hit("POST", "/api/login", { email: "mfa1@example.com", password: "a-long-enough-password" }, undefined, ip);
    expect((await hit("POST", "/api/login/mfa", { code: totp(key, step) }, cookieOf(again.cookies, "custody_mfa")!.split(";")[0], ip)).status).toBe(401);

    expect((await hit("POST", "/api/mfa/disable", { code: totp(key, step + 1) }, user.cookie, ip)).json).toEqual({ mfa: false });
    expect(cookieOf((await hit("POST", "/api/login", { email: "mfa1@example.com", password: "a-long-enough-password" }, undefined, ip)).cookies, "custody_session")).toBeDefined();
  });

  it("a stolen session cannot turn MFA off: no code, a wrong code, and the code that just signed in are all refused, and MFA stays on", async () => {
    const step = midStep();
    await tenancy.addTenant("mfa3", "mfa3", "test");
    const user = await account("mfa3@example.com", "mfa3");
    const key = Buffer.from("s".repeat(20));
    await new PortalStore(db).setMfaSecret(user.id, key.toString("hex"));
    await new PortalStore(db).enableMfa(user.id);
    const ip = "10.5.0.1";
    const half = cookieOf((await hit("POST", "/api/login", { email: "mfa3@example.com", password: "a-long-enough-password" }, undefined, ip)).cookies, "custody_mfa")!.split(";")[0];
    expect((await hit("POST", "/api/login/mfa", { code: totp(key, step) }, half, ip)).status).toBe(200);
    for (const body of [{}, { code: "000000" }, { code: totp(key, step) }]) {
      expect([JSON.stringify(body), (await hit("POST", "/api/mfa/disable", body, user.cookie, ip)).status]).toEqual([JSON.stringify(body), 401]);
    }
    expect((await new PortalStore(db).mfa(user.id)).enabled).toBe(true);
    expect((await hit("POST", "/api/mfa/disable", { code: totp(key, step + 1) }, user.cookie, ip)).json).toEqual({ mfa: false });
  });

  it("a code only moves MFA to the state it asks for: enabling when it is on, and disabling when it was never turned on, are refused with a valid code", async () => {
    const step = midStep();
    await tenancy.addTenant("mfa4", "mfa4", "test");
    const on = await account("mfa4@example.com", "mfa4");
    const onKey = Buffer.from("o".repeat(20));
    await new PortalStore(db).setMfaSecret(on.id, onKey.toString("hex"));
    await new PortalStore(db).enableMfa(on.id);
    expect((await hit("POST", "/api/mfa/enable", { code: totp(onKey, step) }, on.cookie, "10.6.0.1")).status).toBe(409);

    const half = await account("mfa5@example.com", "mfa4");
    const halfKey = Buffer.from("h".repeat(20));
    await new PortalStore(db).setMfaSecret(half.id, halfKey.toString("hex"));
    expect((await hit("POST", "/api/mfa/disable", { code: totp(halfKey, step) }, half.cookie, "10.6.0.2")).status).toBe(409);
    expect((await new PortalStore(db).mfa(half.id)).secret).toBe(halfKey.toString("hex"));
  });

  it("wrong codes are throttled per account whatever the address, and per address whatever the account", async () => {
    const step = midStep();
    const user = await account("mfa2@example.com");
    const key = Buffer.from("k".repeat(20));
    await new PortalStore(db).setMfaSecret(user.id, key.toString("hex"));
    await new PortalStore(db).enableMfa(user.id);
    const half = cookieOf((await hit("POST", "/api/login", { email: "mfa2@example.com", password: "a-long-enough-password" }, undefined, "10.2.0.0")).cookies, "custody_mfa")!.split(";")[0]!;
    for (let i = 1; i <= 5; i++) expect((await hit("POST", "/api/login/mfa", { code: totp(key, step + 5) }, half, `10.2.0.${i}`)).status).toBe(401);
    const locked = await hit("POST", "/api/login/mfa", { code: totp(key, step) }, half, "10.2.0.6");
    expect(locked.status).toBe(429);
    expect(cookieOf(locked.cookies, "custody_session")).toBeUndefined();
    const statuses: number[] = [];
    for (let i = 0; i < 9; i++) statuses.push((await hit("POST", "/api/login/mfa", { code: "000000" }, undefined, "10.3.0.1")).status);
    expect(statuses).toEqual([401, 401, 401, 401, 401, 401, 401, 401, 429]);
  });

  it("a provider sign-in for an account with MFA on sets no session, only the half-signed-in cookie, and the code finishes it", async () => {
    const step = midStep();
    gh = { id: 5151, email: "Mfa-Octo@Example.com" };
    try {
      await tenancy.addTenant("mfa1", "mfa1", "test");
      const u = await new PortalStore(db).findOrCreateOAuthUser("github", "5151", "mfa-octo@example.com");
      await new PortalStore(db).addMember(u.id, "mfa1", "readonly");
      const key = Buffer.from("m".repeat(20));
      await new PortalStore(db).setMfaSecret(u.id, key.toString("hex"));
      await new PortalStore(db).enableMfa(u.id);
      const start = await fetch(new URL("auth/github", p2.url), { redirect: "manual" });
      const state = new URL(start.headers.get("location")!).searchParams.get("state")!;
      const cb = await fetch(new URL(`auth/github/callback?code=gh-code&state=${state}`, p2.url), { headers: { cookie: `custody_oauth=${state}`, "x-forwarded-for": "10.4.0.1" } });
      const cookies = cb.headers.getSetCookie();
      expect(cookieOf(cookies, "custody_session")).toBeUndefined();
      expect(await cb.text()).toContain("url=/?mfa=1");
      const done = await hit("POST", "/api/login/mfa", { code: totp(key, step) }, cookieOf(cookies, "custody_mfa")!.split(";")[0], "10.4.0.1");
      expect((await hit("GET", "/api/me", undefined, cookieOf(done.cookies, "custody_session")!.split(";")[0], "10.4.0.1")).json).toMatchObject({ email: "mfa-octo@example.com", role: "readonly" });
    } finally {
      gh = { id: 4242, email: "Octo@Example.com" };
    }
  });
});

describe("enterprise sign-in", () => {
  let p3: RunningPortal;
  const idp = standInIdp("https://idp.sso.example", "client-1", "s3cret");
  const oidc = { issuer: "https://idp.sso.example", clientId: "client-1", clientSecret: "s3cret" };
  let store: PortalStore;
  const setup = (tenant: string, domain: string, o: { enforced?: boolean; defaultRole?: Role } = {}) =>
    store.setSso({ tenant, protocol: "oidc", config: oidc, domains: [domain], defaultRole: o.defaultRole ?? "readonly", enforced: o.enforced ?? false });
  const get = (path: string, cookie?: string) => fetch(new URL(path, p3.url), { redirect: "manual", headers: cookie ? { cookie } : {} });
  const post = (path: string, body: unknown, cookie?: string) => fetch(new URL(path, p3.url), { method: "POST", headers: { "content-type": "application/json", ...(cookie ? { cookie } : {}) }, body: JSON.stringify(body) });
  const sessionOf = (r: Response) => r.headers.getSetCookie().find((c) => c.startsWith("custody_session="))?.split(";")[0];
  const me = async (cookie: string) => {
    const r = await get("api/me", cookie);
    return { status: r.status, ...((await r.json()) as any) };
  };
  /** a full browser round trip through the stand-in provider; the options break one step of it */
  const signIn = async (tenant: string, who: { email: string; sub?: string }, o: { state?: string; callbackTenant?: string } = {}) => {
    const start = await get(`auth/sso/${tenant}`);
    const back = new URL(idp.signIn(start.headers.get("location")!, { sub: who.sub ?? who.email, email: who.email }));
    if (o.state) back.searchParams.set("state", o.state);
    return get(back.pathname.replace(`/sso/${tenant}/`, `/sso/${o.callbackTenant ?? tenant}/`) + back.search, start.headers.get("set-cookie")!.split(";")[0]!);
  };
  const verifiedUser = async (email: string, tenant?: string, role?: Role) => {
    const u = await store.createUser(email, "a-long-enough-password");
    await store.markEmailVerified(u.id);
    if (tenant) await store.addMember(u.id, tenant, role);
    return u;
  };

  beforeAll(async () => {
    p3 = await servePortal({ tenancy, client: db, secret: SECRET, publicUrl: log.url, portalUrl: "https://app.example.test/", ssoFetch: idp.fetch, oauth: { github: { clientId: "gh_id", clientSecret: "gh_secret" }, fetch: oauthFetch }, log: () => {} }, { port: 0 });
    store = new PortalStore(db);
    await tenancy.addTenant("sso-co", "sso-co", "test");
    await tenancy.addTenant("other-co", "other-co", "test");
  }, 60_000);
  afterAll(async () => { await p3?.close(); });

  it("finds the tenant by the address's domain, signs a member in through the provider with the default role, and that role limits a write", async () => {
    await setup("sso-co", "sso.example");
    const found = await get("auth/sso?email=Ann@SSO.example");
    expect([found.status, found.headers.get("location")]).toEqual([302, "/auth/sso/sso-co"]);
    const none = await get("auth/sso?email=ann@nowhere.example");
    expect(none.status).toBe(404);
    expect(await none.text()).toContain("No single sign-on is set up for nowhere.example");

    const start = await get("auth/sso/sso-co");
    const to = new URL(start.headers.get("location")!);
    expect(to.origin + to.pathname).toBe("https://idp.sso.example/authorize");
    expect(to.searchParams.get("redirect_uri")).toBe("https://app.example.test/auth/sso/sso-co/callback");
    expect(to.searchParams.get("code_challenge_method")).toBe("S256");
    expect(start.headers.get("set-cookie")).toMatch(/^custody_sso=[^;]+; Path=\/auth; HttpOnly; SameSite=Lax; Max-Age=600$/);

    const cb = await signIn("sso-co", { email: "Ann@SSO.example", sub: "ann-1" });
    expect(cb.status).toBe(200);
    const cookies = cb.headers.getSetCookie();
    expect(cookies.find((c) => c.startsWith("custody_session="))).toContain("SameSite=Strict");
    expect(cookies.find((c) => c.startsWith("custody_sso="))).toContain("Max-Age=0");
    const session = sessionOf(cb)!;
    expect(readSessionVia(SECRET, session.split("=")[1])).toBe("sso:sso-co");
    expect(await me(session)).toMatchObject({ email: "ann@sso.example", tenant: "sso-co", role: "readonly", sso: { protocol: "oidc", enforced: false } });
    const write = await post("api/keys", { label: "x" }, session);
    expect(write.status).toBe(403);
    expect(((await write.json()) as any).error).toMatch(/admin role/);
    // the same subject again is the same account
    await signIn("sso-co", { email: "ann@sso.example", sub: "ann-1" });
    expect((await store.members("sso-co")).map((m) => m.email)).toEqual(["ann@sso.example"]);
  });

  it("refuses an address outside the tenant's domains, a state that is not the cookie's, a cookie from another tenant's flow, a member of another tenant, and an unverified member of the same tenant", async () => {
    await setup("sso-co", "sso.example");
    await setup("other-co", "other.example");
    const outside = await signIn("sso-co", { email: "eve@evil.example" });
    expect([outside.status, sessionOf(outside)]).toEqual([403, undefined]);
    expect(await store.userByEmail("eve@evil.example")).toBeNull();

    const before = idp.tokenCalls;
    const forged = await signIn("sso-co", { email: "mal@sso.example" }, { state: "forged" });
    expect([forged.status, sessionOf(forged), idp.tokenCalls]).toEqual([400, undefined, before]);
    const wrongTenant = await signIn("sso-co", { email: "mal@sso.example" }, { callbackTenant: "other-co" });
    expect([wrongTenant.status, idp.tokenCalls]).toEqual([400, before]);

    const bob = await verifiedUser("bob@sso.example", "other-co", "admin");
    const moved = await signIn("sso-co", { email: "bob@sso.example" });
    expect([moved.status, sessionOf(moved)]).toEqual([403, undefined]);
    expect(await store.roleOf(bob.id, "sso-co")).toBeNull();

    const own = await store.createUser("own@sso.example", "a-long-enough-password");
    await store.addMember(own.id, "sso-co", "owner");
    const unverified = await signIn("sso-co", { email: "own@sso.example" });
    expect([unverified.status, sessionOf(unverified)]).toEqual([409, undefined]);
    expect(await store.user(own.id)).not.toBeNull();

    const twoAts = await signIn("sso-co", { email: "a@evil.example@sso.example" });
    expect([twoAts.status, sessionOf(twoAts)]).toEqual([403, undefined]);
  });

  it("an address registered first never locks the person out: a bare account, an account that created a tenant, and an account with a linked provider all lose the address to the provider's sign-in", async () => {
    await setup("sso-co", "sso.example");
    const bare = await store.createUser("cy@sso.example", "a-long-enough-password");
    const bareSession = `custody_session=${signSession(SECRET, bare.id)}`;
    const tenantOwner = await post("api/register", { email: "new.hire@sso.example", password: "a-long-enough-password", tenant: "squat-co", name: "Sam Squat", company: "Squat Co" });
    expect(tenantOwner.status).toBe(200);
    const squat = (await store.userByEmail("new.hire@sso.example"))!;
    const linked = await store.createUser("lin@sso.example", "a-long-enough-password");
    await store.linkIdentity("github", "gh-lin", "someone@elsewhere.example", linked.id);

    for (const [email, old] of [["cy@sso.example", bare], ["new.hire@sso.example", squat], ["lin@sso.example", linked]] as const) {
      const cb = await signIn("sso-co", { email });
      expect([email, cb.status]).toEqual([email, 200]);
      const fresh = (await store.userByEmail(email))!;
      expect(fresh.id).not.toBe(old.id);
      expect(await store.roleOf(fresh.id, "sso-co")).toBe("readonly");
      expect(await store.authenticate(email, "a-long-enough-password")).toBeNull();
      expect(await store.user(old.id)).toBeNull();
      expect(await store.identities(old.id)).toEqual([]);
    }
    expect((await get("api/me", bareSession)).status).toBe(401);
    // the tenant that the squatter created stays, with no member, for the operator
    expect((await tenancy.tenant("squat-co"))?.id).toBe("squat-co");
    expect(await store.members("squat-co")).toEqual([]);
  });

  it("a member that an admin removed does not come back through the provider, until an admin invites the address again", async () => {
    await setup("sso-co", "sso.example");
    const boss = await verifiedUser("boss@sso.example", "sso-co", "owner");
    const owner = `custody_session=${signSession(SECRET, boss.id)}`;
    const mal = sessionOf(await signIn("sso-co", { email: "mal@sso.example" }))!;
    expect((await me(mal)).role).toBe("readonly");
    const malId = (await store.userByEmail("mal@sso.example"))!.id;
    expect((await post(`api/members/${malId}/remove`, {}, owner)).status).toBe(200);
    expect((await me(mal)).tenant).toBeNull();

    const again = await signIn("sso-co", { email: "mal@sso.example" });
    expect([again.status, sessionOf(again)]).toEqual([403, undefined]);
    expect(await store.roleOf(malId, "sso-co")).toBeNull();

    expect((await post("api/members", { email: "mal@sso.example", role: "reviewer" }, owner)).status).toBe(200);
    const back = sessionOf(await signIn("sso-co", { email: "mal@sso.example" }))!;
    expect(await me(back)).toMatchObject({ tenant: "sso-co", role: "reviewer" });
    expect(await store.invitesFor("mal@sso.example")).toEqual([]);
  });

  it("a removed member that never verified the address does not come back through the provider either, until an admin invites the address again", async () => {
    await setup("sso-co", "sso.example");
    const boss = await verifiedUser("boss2@sso.example", "sso-co", "owner");
    const owner = `custody_session=${signSession(SECRET, boss.id)}`;
    const uv = await store.createUser("uv@sso.example", "a-long-enough-password");
    await store.addMember(uv.id, "sso-co", "admin");
    expect((await post(`api/members/${uv.id}/remove`, {}, owner)).status).toBe(200);

    const again = await signIn("sso-co", { email: "uv@sso.example" });
    expect([again.status, sessionOf(again)]).toEqual([403, undefined]);
    expect(await store.roleOf(uv.id, "sso-co")).toBeNull();
    expect(await store.userByEmail("uv@sso.example")).toMatchObject({ id: uv.id });
    expect(await store.user(uv.id)).not.toBeNull();

    expect((await post("api/members", { email: "uv@sso.example", role: "reviewer" }, owner)).status).toBe(200);
    const back = sessionOf(await signIn("sso-co", { email: "uv@sso.example" }))!;
    expect(await me(back)).toMatchObject({ tenant: "sso-co", role: "reviewer" });
  });

  it("a removed member that never verified the address cannot come back by first creating a tenant of their own", async () => {
    await setup("sso-co", "sso.example");
    const boss = await verifiedUser("boss3@sso.example", "sso-co", "owner");
    const owner = `custody_session=${signSession(SECRET, boss.id)}`;
    const reg = await post("api/register", { email: "uv2@sso.example", password: "a-long-enough-password" });
    expect(reg.status).toBe(200);
    const uvCookie = sessionOf(reg)!;
    const uv = (await store.userByEmail("uv2@sso.example"))!;
    await store.addMember(uv.id, "sso-co", "admin");
    expect((await post(`api/members/${uv.id}/remove`, {}, owner)).status).toBe(200);

    expect((await post("api/onboard", { tenant: "uv-own", name: "Uv Two", company: "Uv Own" }, uvCookie)).status).toBe(200);
    expect(await store.roleOf(uv.id, "uv-own")).toBe("owner");

    const again = await signIn("sso-co", { email: "uv2@sso.example" });
    expect([again.status, sessionOf(again)]).toEqual([403, undefined]);
    expect(await store.userByEmail("uv2@sso.example")).toMatchObject({ id: uv.id });
    expect(await store.roleOf(uv.id, "uv-own")).toBe("owner");
    expect(await store.roleOf(uv.id, "sso-co")).toBeNull();

    expect((await post("api/members", { email: "uv2@sso.example", role: "reviewer" }, owner)).status).toBe(200);
    const back = sessionOf(await signIn("sso-co", { email: "uv2@sso.example" }))!;
    expect(await me(back)).toMatchObject({ tenant: "sso-co", role: "reviewer" });
  });

  it("a removal holds by address after the account is made again under a new id", async () => {
    await setup("sso-co", "sso.example");
    const gone = await verifiedUser("gone@sso.example", "sso-co", "reviewer");
    await store.removeMember("sso-co", gone.id);
    await db.query("DELETE FROM portal_users WHERE id = $1", [gone.id]);
    const again = await signIn("sso-co", { email: "gone@sso.example" });
    expect([again.status, sessionOf(again)]).toEqual([403, undefined]);
    expect(await store.userByEmail("gone@sso.example")).toBeNull();
  });

  it("an unverified owner of another tenant with other members is refused and keeps the account; a sole member of another tenant loses the address", async () => {
    await setup("sso-co", "sso.example");
    await tenancy.addTenant("dom-labs", "dom-labs", "test");
    const lab = await store.createUser("lab@sso.example", "a-long-enough-password");
    await store.addMember(lab.id, "dom-labs", "owner");
    const mate = await verifiedUser("mate@elsewhere.example", "dom-labs", "reviewer");
    const refused = await signIn("sso-co", { email: "lab@sso.example" });
    expect([refused.status, sessionOf(refused)]).toEqual([403, undefined]);
    expect(await store.user(lab.id)).not.toBeNull();
    expect(await store.roleOf(lab.id, "dom-labs")).toBe("owner");
    expect(await store.roleOf(mate.id, "dom-labs")).toBe("reviewer");

    await store.removeMember("dom-labs", mate.id);
    expect((await signIn("sso-co", { email: "lab@sso.example" })).status).toBe(200);
    expect(await store.user(lab.id)).toBeNull();
    expect(await store.roleOf((await store.userByEmail("lab@sso.example"))!.id, "sso-co")).toBe("readonly");
  });

  it("an enforced tenant refuses a member's password and GitHub sign-in, ends their password session, and takes members from the provider only", async () => {
    await setup("sso-co", "sso.example", { enforced: true });
    const pat = await verifiedUser("pat@sso.example", "sso-co", "reviewer");
    expect((await me(`custody_session=${signSession(SECRET, pat.id)}`)).status).toBe(401);
    const login = await post("api/login", { email: "pat@sso.example", password: "a-long-enough-password" });
    expect(login.status).toBe(403);
    expect(((await login.json()) as any).error).toMatch(/identity provider/);
    gh = { id: 7001, email: "Pat@SSO.example" };
    try {
      const state = new URL((await get("auth/github")).headers.get("location")!).searchParams.get("state")!;
      const viaGithub = await get(`auth/github/callback?code=gh-code&state=${state}`, `custody_oauth=${state}`);
      expect([viaGithub.status, sessionOf(viaGithub)]).toEqual([403, undefined]);
    } finally {
      gh = { id: 4242, email: "Octo@Example.com" };
    }
    // the provider is the way in, and the role the account had is kept
    const sso = sessionOf(await signIn("sso-co", { email: "pat@sso.example" }))!;
    expect(await me(sso)).toMatchObject({ email: "pat@sso.example", role: "reviewer", sso: { enforced: true } });
    await store.setRole("sso-co", pat.id, "owner");
    const invite = await post("api/members", { email: "new@sso.example", role: "readonly" }, sso);
    expect(invite.status).toBe(409);
    expect(((await invite.json()) as any).error).toMatch(/identity provider/);
    // not enforced: the password works again
    await setup("sso-co", "sso.example");
    expect((await post("api/login", { email: "pat@sso.example", password: "a-long-enough-password" })).status).toBe(200);
  });

  it("a member with MFA on gets a session from the provider without a code", async () => {
    await setup("sso-co", "sso.example");
    const dee = await verifiedUser("dee@sso.example");
    await store.setMfaSecret(dee.id, Buffer.from("d".repeat(20)).toString("hex"));
    await store.enableMfa(dee.id);
    const cb = await signIn("sso-co", { email: "dee@sso.example" });
    expect(cb.headers.getSetCookie().some((c) => c.startsWith("custody_mfa=") && !c.includes("Max-Age=0"))).toBe(false);
    expect(await me(sessionOf(cb)!)).toMatchObject({ email: "dee@sso.example", role: "readonly", mfa: true });
  });

  it("signs in through SAML: the request id travels in a cookie that the identity provider's cross-site post carries back", async () => {
    const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const idpIssuer = "https://idp.saml.example/meta";
    await tenancy.addTenant("saml-co", "saml-co", "test");
    await store.setSso({ tenant: "saml-co", protocol: "saml", config: { entryPoint: "https://idp.saml.example/sso", idpCert: keys.publicKey.export({ format: "pem", type: "spki" }) as string, idpIssuer }, domains: ["saml.example"], defaultRole: "reviewer", enforced: false });
    const sp = "https://app.example.test/auth/sso/saml-co/saml";
    const acs = `${sp}/acs`;
    const meta = await (await get("auth/sso/saml-co/saml")).text();
    expect(meta).toContain(`entityID="${sp}"`);
    expect(meta).toContain(`Location="${acs}"`);

    const start = await get("auth/sso/saml-co");
    const to = new URL(start.headers.get("location")!);
    expect(to.origin + to.pathname).toBe("https://idp.saml.example/sso");
    const cookie = start.headers.get("set-cookie")!;
    expect(cookie).toMatch(/^custody_saml=[^;]+; Path=\/auth\/sso; HttpOnly; SameSite=None; Secure; Max-Age=600$/);
    const requestId = /ID="([^"]+)"/.exec(inflateRawSync(Buffer.from(to.searchParams.get("SAMLRequest")!, "base64")).toString())![1]!;

    const iso = (ms: number) => new Date(Date.now() + ms).toISOString();
    const response = (inResponseTo: string, email: string) => {
      const assertion = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="${iso(0)}"><saml:Issuer>${idpIssuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">${email}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="${inResponseTo}" Recipient="${acs}" NotOnOrAfter="${iso(300_000)}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore="${iso(-60_000)}" NotOnOrAfter="${iso(300_000)}"><saml:AudienceRestriction><saml:Audience>${sp}</saml:Audience></saml:AudienceRestriction></saml:Conditions></saml:Assertion>`;
      const s = new SignedXml({ privateKey: keys.privateKey.export({ format: "pem", type: "pkcs8" }) as string, signatureAlgorithm: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", canonicalizationAlgorithm: "http://www.w3.org/2001/10/xml-exc-c14n#" });
      s.addReference({ xpath: "//*[local-name(.)='Assertion']", transforms: ["http://www.w3.org/2000/09/xmldsig#enveloped-signature", "http://www.w3.org/2001/10/xml-exc-c14n#"], digestAlgorithm: "http://www.w3.org/2001/04/xmlenc#sha256" });
      s.computeSignature(assertion, { location: { reference: "//*[local-name(.)='Issuer']", action: "after" } });
      const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" IssueInstant="${iso(0)}" InResponseTo="${inResponseTo}"><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>${s.getSignedXml()}</samlp:Response>`;
      return new URLSearchParams({ SAMLResponse: Buffer.from(xml).toString("base64") }).toString();
    };
    const acsPost = (body: string, cookieHeader?: string) => fetch(new URL("auth/sso/saml-co/saml/acs", p3.url), { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...(cookieHeader ? { cookie: cookieHeader } : {}) }, body });
    const flow = cookie.split(";")[0]!;
    expect((await acsPost(response(requestId, "sam@saml.example"))).status).toBe(400); // the cookie did not come back
    expect((await acsPost(response("_other", "sam@saml.example"), flow)).status).toBe(401); // an answer to another request
    expect((await acsPost(response(requestId, "sam@elsewhere.example"), flow)).status).toBe(403); // the wrong domain
    const done = await acsPost(response(requestId, "Sam@SAML.example"), flow);
    expect(done.status).toBe(200);
    expect(done.headers.getSetCookie().find((c) => c.startsWith("custody_saml="))).toContain("Max-Age=0");
    expect(readSessionVia(SECRET, sessionOf(done)!.split("=")[1])).toBe("sso:saml-co");
    expect(await me(sessionOf(done)!)).toMatchObject({ email: "sam@saml.example", role: "reviewer", sso: { protocol: "saml" } });
  });

  it("a domain belongs to one tenant: a second tenant cannot claim it, the owner of it can change it, and removing frees it", async () => {
    await store.setSso({ tenant: "other-co", protocol: "oidc", config: oidc, domains: ["Held.example", "also.example"], defaultRole: "readonly", enforced: false });
    await expect(store.setSso({ tenant: "sso-co", protocol: "oidc", config: oidc, domains: ["sso.example", "HELD.example"], defaultRole: "readonly", enforced: false })).rejects.toThrow(/held\.example belongs to tenant other-co/);
    expect((await store.ssoByDomain("held.example"))?.tenant).toBe("other-co");
    await store.setSso({ tenant: "other-co", protocol: "oidc", config: oidc, domains: ["held.example"], defaultRole: "admin", enforced: true });
    expect(await store.ssoByDomain("also.example")).toBeNull();
    await expect(store.setSso({ tenant: "sso-co", protocol: "oidc", config: oidc, domains: ["sso.example"], defaultRole: "owner", enforced: false })).rejects.toThrow(/default role/);
    expect(await store.removeSso("other-co")).toBe(true);
    await setup("sso-co", "held.example");
    expect((await store.ssoByDomain("held.example"))?.tenant).toBe("sso-co");
  });
});

describe("request validation and features that are not configured", () => {
  // bare has no Stripe, mail, or OAuth, and a log URL with characters that HTML must escape
  let bare: RunningPortal;
  let paid: RunningPortal;
  let store: PortalStore;
  const send = async (p: RunningPortal, method: string, path: string, o: { body?: string; type?: string; cookie?: string; ip?: string } = {}) => {
    const res = await fetch(new URL(path, p.url), { method, headers: { "x-forwarded-for": o.ip ?? "10.7.7.7", ...(o.type ? { "content-type": o.type } : {}), ...(o.cookie ? { cookie: o.cookie } : {}) }, body: o.body });
    const text = await res.text();
    let json: any = {};
    try { json = JSON.parse(text); } catch {}
    return { status: res.status, text, json };
  };
  const post = (p: RunningPortal, path: string, body: unknown, cookie?: string, ip?: string) => send(p, "POST", path, { body: JSON.stringify(body), type: "application/json", cookie, ip });
  const owner = async (email: string, tenant: string) => {
    const u = await store.createUser(email, "a-long-enough-password");
    await store.addMember(u.id, tenant);
    return `custody_session=${signSession(SECRET, u.id)}`;
  };
  const reg = { email: "val@guards.example", password: "a-long-enough-password", tenant: "guards-reg", name: "Val", company: "Guards" };

  beforeAll(async () => {
    store = new PortalStore(db);
    const common = { tenancy, client: db, secret: SECRET, portalUrl: "https://app.example.test/", trustProxy: true, log: () => {} };
    bare = await servePortal({ ...common, publicUrl: 'https://log.example.test/a<b>"c&d/' }, { port: 0 });
    paid = await servePortal({ ...common, publicUrl: log.url, stripe: { secretKey: "sk_test_x", webhookSecret: WHSEC, priceTeam: "price_team", fetch: stripeFetch } }, { port: 0 });
    await tenancy.addTenant("guards-a", "guards-a");
  }, 60_000);
  afterAll(async () => { await bare?.close(); await paid?.close(); });

  it("answers /health and serves the page with the log URL escaped", async () => {
    expect((await send(bare, "GET", "/health")).json).toEqual({ ok: true, stripe: false });
    const h = await send(paid, "GET", "/health");
    expect(h.status).toBe(200);
    expect(h.json).toEqual({ ok: true, stripe: true });
    const page = (await send(bare, "GET", "/")).text;
    expect(page).toContain("https://log.example.test/a&lt;b&gt;&quot;c&amp;d/t/&lt;tenant&gt;/");
    expect(page).not.toContain("a<b>");
  });

  it("refuses a body that is too large, not JSON, or not parseable, through the catch-all 500", async () => {
    const big = await send(bare, "POST", "/api/register", { body: JSON.stringify({ ...reg, pad: "x".repeat(70_000) }), type: "application/json" });
    expect(big.status).toBe(500);
    expect(big.json.error).toBe("body too large");
    const form = await send(bare, "POST", "/api/register", { body: "email=a", type: "application/x-www-form-urlencoded" });
    expect(form.status).toBe(500);
    expect(form.json.error).toBe("expected a JSON body");
    expect((await send(bare, "POST", "/api/register", { body: "{not json", type: "application/json" })).status).toBe(500);
  });

  it.each([
    ["an email with no domain", { email: "val@" }, /valid email/],
    ["no company", { company: " " }, /company or organisation/],
    ["a phone with letters", { phone: "call me" }, /phone number/],
  ])("registration refuses %s", async (_, change, error) => {
    const r = await post(bare, "/api/register", { ...reg, ...change });
    expect(r.status).toBe(400);
    expect(r.json.error).toMatch(error);
  });

  it("throttles registrations and logins per address", async () => {
    const regs = [];
    for (let i = 0; i < 6; i++) regs.push((await post(bare, "/api/register", { email: `r${i}@guards.example`, password: "a-long-enough-password" }, undefined, "10.7.0.1")).status);
    expect(regs).toEqual([200, 200, 200, 200, 200, 429]);
    // another address still registers
    expect((await post(bare, "/api/register", { email: "r9@guards.example", password: "a-long-enough-password" }, undefined, "10.7.0.2")).status).toBe(200);
    const logins = [];
    for (let i = 0; i < 9; i++) logins.push((await post(bare, "/api/login", { email: "r0@guards.example", password: "wrong-password!" }, undefined, "10.7.0.3")).status);
    expect(logins).toEqual([401, 401, 401, 401, 401, 401, 401, 401, 429]);
  });

  it("refuses a bad or orphaned verify link, and a resend when mail is not configured", async () => {
    const bad = await send(bare, "GET", "/verify-email?token=forged");
    expect(bad.status).toBe(400);
    expect(bad.text).toContain("not valid or has expired");
    const orphan = await send(bare, "GET", `/verify-email?token=${signSession(SECRET, "verify:no-such-user")}`);
    expect(orphan.status).toBe(400);
    expect(orphan.text).toContain("belongs to no account");
    const cookie = `custody_session=${signSession(SECRET, (await store.createUser("unverified@guards.example", "a-long-enough-password")).id)}`;
    expect((await post(bare, "/api/verify-email", { token: "forged" }, cookie)).status).toBe(400);
    const resend = await post(bare, "/api/verify-email/resend", {}, cookie);
    expect(resend.status).toBe(503);
    expect(resend.json.error).toMatch(/mail is not configured/);
  });

  it("answers 503 for every billing route when Stripe is not configured, and 409 when the tenant has no billing record", async () => {
    const cookie = await owner("billing@guards.example", "guards-a");
    for (const [path, c] of [["/stripe/webhook", undefined], ["/api/checkout", cookie], ["/api/billing-portal", cookie]] as const) {
      const r = await post(bare, path, {}, c);
      expect([path, r.status]).toEqual([path, 503]);
      expect(r.json.error).toMatch(/billing is not configured/);
    }
    const none = await post(paid, "/api/billing-portal", {}, cookie);
    expect(none.status).toBe(409);
    expect(none.json.error).toBe("no billing record for this tenant");
  });

  it("refuses a tenant that no longer exists, a bad invite, an unknown member, a bad role, empty policy text, and an unknown path", async () => {
    const ghost = await owner("ghost@guards.example", "guards-gone");
    const gone = await send(bare, "GET", "/api/me", { cookie: ghost });
    expect(gone.status).toBe(409);
    expect(gone.json.error).toBe("the tenant no longer exists");
    const cookie = await owner("admin@guards.example", "guards-a");
    const invite = await post(bare, "/api/members", { email: "not-an-address", role: "readonly" }, cookie);
    expect(invite.status).toBe(400);
    expect(invite.json.error).toMatch(/valid email/);
    const unknown = await post(bare, "/api/members/00000000-0000-0000-0000-000000000000/role", { role: "admin" }, cookie);
    expect(unknown.status).toBe(404);
    expect(unknown.json.error).toBe("no such member");
    const self = (await store.members("guards-a")).find((m) => m.email === "admin@guards.example")!;
    const role = await post(bare, `/api/members/${self.id}/role`, { role: "superuser" }, cookie);
    expect(role.status).toBe(400);
    expect(role.json.error).toMatch(/role must be one of/);
    expect(await store.roleOf(self.id, "guards-a")).toBe("owner");
    const policy = await post(bare, "/api/policies", { name: "empty", text: "  \n" }, cookie);
    expect(policy.status).toBe(400);
    expect(policy.json.error).toBe("the policy text is empty");
    expect((await send(bare, "GET", "/nowhere")).status).toBe(404);
    expect((await send(bare, "GET", "/api/nowhere", { cookie })).status).toBe(404);
  });

  it("refuses a table prefix that is not a plain identifier and an SSO domain that is not a domain", async () => {
    expect(() => new PortalStore(db, "portal; DROP TABLE x;--")).toThrow(/plain identifier/);
    await expect(store.setSso({ tenant: "guards-a", protocol: "oidc", config: { issuer: "https://idp.example", clientId: "c", clientSecret: "s" } as any, domains: ["not a domain"], defaultRole: "readonly", enforced: false })).rejects.toThrow(/email domains/);
  });
});
