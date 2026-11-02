// The operator's admin surface for a hosted log: tenants and their tokens, over HTTP behind an admin token, and a
// single page at /admin that drives it. It is for whoever runs the log, never for tenants. Everything under /admin,
// the page included, needs the admin token: the browser's own prompt supplies it as HTTP Basic (any user name,
// the token as the password) and an API client sends it as a bearer. Failed attempts from one address are
// throttled. A minted token is shown once, beside the welcome sheet the tenant gets. Nothing here touches
// receipts; the log holds hashes and the panel holds names.
import { timingSafeEqual } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";
import { RateLimiter, type PostgresTenancy, PLANS, type Plan } from "./log-store.ts";
import { clientAddress } from "./log-sink.ts";
import type { PortalStore } from "./portal.ts";

export interface AdminOptions {
  tenancy: PostgresTenancy;
  /** the admin token; every /admin route needs it as a bearer */
  token: string;
  /** the log's public base URL, for the welcome sheet, e.g. https://log.example.com/ */
  publicUrl?: string;
  /** the checkpoints host, e.g. https://checkpoints.example.com/ */
  checkpointsUrl?: string;
  /** the current signing keyid, for the sheet */
  keyid?: string;
  /** key the failure throttle by X-Forwarded-For's first address; only behind a proxy you run */
  trustProxy?: boolean;
  /** the portal's tables on the same database, read only, so the registrations list can say who signed up */
  portal?: PortalStore;
}

const same = (a: string, b: string) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

/** The welcome sheet as text, the same one deploy/onboard-tenant.sh prints. */
export function welcomeSheet(o: { tenant: string; logId: string; publicUrl: string; checkpointsUrl?: string; keyid?: string }): string {
  const base = o.publicUrl.endsWith("/") ? o.publicUrl : `${o.publicUrl}/`;
  const url = `${base}t/${o.tenant}/`;
  const lines = [
    `agent-custody log: welcome sheet for tenant "${o.tenant}"`,
    "",
    `Your log            ${url}`,
    `Your log id         ${o.logId}`,
    ...(o.checkpointsUrl ? [`Your checkpoints    ${o.checkpointsUrl.replace(/\/?$/, "/")}${o.tenant}/latest.json`] : []),
    `The log's keys      ${base}.well-known/agent-custody-log.json${o.keyid ? `  (current keyid ${o.keyid})` : ""}`,
    "",
    "Your token was shown once when it was made; the log keeps only its hash. Lose it and ask for a new one.",
    "",
    "In your gateway or SDK config:",
    `  "log": { "url": "${url}", "tokenEnv": "AGENT_CUSTODY_LOG_TOKEN", "hashOnly": true }`,
    "hashOnly means this log never receives your receipts, only their hashes.",
    "",
    "For whoever verifies your receipts:",
    `  npx @agent-custody/receipts verify receipts/<id>.json --issuer-key <your gateway.pub> --principal-key <your principal.pub> --log-url ${url} --log-id ${o.logId}`,
    `  npx @agent-custody/receipts audit --older receipts/<earlier>.json --newer receipts/<later>.json --log-url ${url} --log-id ${o.logId}`,
    "--log-url fetches this log's published keys and pins them; --log-id makes sure the tree heads are this log's.",
    "",
    "Your log is yours to take, any time, with your token:",
    `  npx @agent-custody/receipts log-export --log-url ${url} --tenant ${o.tenant} --token-env AGENT_CUSTODY_LOG_TOKEN --out custody-export/`,
    "It fetches every leaf hash, the signed head, the keys, the checkpoints, and your usage, checks they add up, and writes",
    "a log copy that verify --log and audit --log read with no server.",
    "",
    "What this log does not do: hold receipt contents, forge a receipt (your gateway key signs those), or, today,",
    "countersign with a second independent witness. The proof table: https://agent-custody.dev/receipts/#what-a-receipt-proves-and-what-it-does-not",
  ];
  return lines.join("\n");
}

/**
 * Routes under /admin. Returns true when it handled the request.
 *   GET  /admin                                   the page
 *   GET  /admin/info                              { publicUrl, checkpointsUrl, keyid }
 *   GET  /admin/tenants                           [{ id, logId, createdAt, disabledAt, tokens }]
 *   POST /admin/tenants        { id, logId? }     the tenant
 *   POST /admin/tenants/:id/disable
 *   GET  /admin/tenants/:id/tokens                [{ label, tokenHash, createdAt, revokedAt }]
 *   POST /admin/tenants/:id/tokens { label }      { token, tokenHash, welcome }   token shown once
 *   POST /admin/tenants/:id/tokens/:prefix/revoke { revoked }
 *   GET  /admin/usage?month=YYYY-MM              { month, tenants: [{ id, logId, appends, totalLeaves, liveTokens, disabled }] }
 *   GET  /admin/usage.csv?month=YYYY-MM          the same as CSV, for an invoice
 *   GET  /admin/registrations?month=YYYY-MM      { month, rows: [{ tenant, logId, plan, email, name, company, role, phone, telegram, registeredAt, billing, appends, quota, totalLeaves, liveTokens, disabled }], totals }
 *   GET  /admin/registrations.csv?month=YYYY-MM  the same as CSV
 */
/** One row per tenant: who registered it through the portal (null when it was onboarded by script), its plan and billing
 *  state, appends in the month asked for, and leaves in total; plus the totals across tenants. */
export async function registrations(tenancy: PostgresTenancy, portal: PortalStore | undefined, month: string): Promise<{ month: string; rows: RegistrationRow[]; totals: { tenants: number; registered: number; appends: number; totalLeaves: number } }> {
  const usage = await tenancy.usage(month);
  const who = new Map<string, { email: string; registeredAt: string; billing: string | null; name?: string | null; company?: string | null; role?: string | null; phone?: string | null; telegram?: string | null }>();
  for (const r of portal ? await portal.registrations() : []) if (!who.has(r.tenantId)) who.set(r.tenantId, r);
  const rows = usage.tenants.map((t) => {
    const w = who.get(t.id);
    return { tenant: t.id, logId: t.logId, plan: t.plan, email: w?.email ?? null, name: w?.name ?? null, company: w?.company ?? null, role: w?.role ?? null, phone: w?.phone ?? null, telegram: w?.telegram ?? null, registeredAt: w?.registeredAt ?? null, billing: w?.billing ?? null, appends: t.appends, quota: t.quota, totalLeaves: t.totalLeaves, liveTokens: t.liveTokens, disabled: t.disabled };
  });
  return { month: usage.month, rows, totals: { tenants: rows.length, registered: rows.filter((r) => r.email).length, appends: rows.reduce((n, r) => n + r.appends, 0), totalLeaves: rows.reduce((n, r) => n + r.totalLeaves, 0) } };
}
export interface RegistrationRow { tenant: string; logId: string; plan: Plan; email: string | null; name: string | null; company: string | null; role: string | null; phone: string | null; telegram: string | null; registeredAt: string | null; billing: string | null; appends: number; quota: number | null; totalLeaves: number; liveTokens: number; disabled: boolean }

export function adminRoutes(opts: AdminOptions): (req: IncomingMessage, res: ServerResponse, url: URL) => Promise<boolean> {
  // Five wrong tokens from one address, then one more a minute: enough to stop guessing, not enough to lock out a typo.
  const failures = new RateLimiter({ perSecond: 1 / 60, burst: 5 });
  const presented = (req: IncomingMessage): { token: string; user: string | null } | null => {
    const h = req.headers.authorization ?? "";
    if (h.startsWith("Bearer ") && h.length > 7) return { token: h.slice(7), user: null };
    if (h.startsWith("Basic ") && h.length > 6) {
      const pair = Buffer.from(h.slice(6), "base64").toString();
      const at = pair.indexOf(":");
      return at >= 0 ? { token: pair.slice(at + 1), user: pair.slice(0, at) } : { token: pair, user: null };
    }
    return null;
  };
  return async (req, res, url) => {
    if (url.pathname !== "/admin" && !url.pathname.startsWith("/admin/")) return false;
    const json = (status: number, body: unknown, headers: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...headers });
      res.end(JSON.stringify(body));
    };
    const addr = clientAddress(req, opts.trustProxy);
    const given = presented(req);
    if (given === null || !same(given.token, opts.token)) {
      if (!failures.take(`admin:${addr}`)) return json(429, { error: "too many attempts; wait a minute" }, { "retry-after": "60" }), true;
      // The challenge makes the browser ask; the same 401 tells an API client what is missing.
      return json(401, { error: "admin token required" }, { "www-authenticate": 'Basic realm="agent-custody log admin", charset="UTF-8"' }), true;
    }
    if (req.method === "GET" && url.pathname === "/admin") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-frame-options": "DENY", "content-security-policy": "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self'; connect-src 'self'" });
      res.end(ADMIN_PAGE);
      return true;
    }
    const body = async (): Promise<Record<string, unknown>> => {
      let text = "";
      for await (const chunk of req) {
        text += chunk;
        if (text.length > 16_384) throw new Error("body too large");
      }
      return text ? (JSON.parse(text) as Record<string, unknown>) : {};
    };
    // Who did it, for the audit trail: the user name the browser prompt asked for (any name, but it is recorded), or
    // "bearer" for an API client, and the address either came from. There is one admin token; the name is what
    // tells two operators apart.
    const actor = `admin:${given.user?.replace(/[^\w.@-]/g, "").slice(0, 64) || "bearer"}@${addr}`;
    try {
      const t = opts.tenancy;
      const parts = url.pathname.split("/").filter(Boolean); // ["admin", ...]
      const month = url.searchParams.get("month") ?? new Date().toISOString().slice(0, 7);
      if (req.method === "GET" && parts.length === 2 && parts[1] === "usage") {
        json(200, await t.usage(month));
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "usage.csv") {
        const u = await t.usage(month);
        const csv = ["month,tenant,log_id,plan,quota,appends,total_leaves,live_tokens,disabled", ...u.tenants.map((x) => [u.month, x.id, x.logId, x.plan, x.quota ?? "", x.appends, x.totalLeaves, x.liveTokens, x.disabled].join(","))].join("\n") + "\n";
        res.writeHead(200, { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="agent-custody-usage-${u.month}.csv"`, "cache-control": "no-store" });
        res.end(csv);
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "registrations") {
        json(200, await registrations(t, opts.portal, month));
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "registrations.csv") {
        const r = await registrations(t, opts.portal, month);
        const cell = (v: unknown) => (v === null ? "" : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v));
        const csv = ["month,tenant,log_id,plan,email,name,company,role,phone,telegram,registered_at,billing,appends,quota,total_leaves,live_tokens,disabled", ...r.rows.map((x) => [r.month, x.tenant, x.logId, x.plan, x.email, x.name, x.company, x.role, x.phone, x.telegram, x.registeredAt, x.billing, x.appends, x.quota, x.totalLeaves, x.liveTokens, x.disabled].map(cell).join(","))].join("\n") + "\n";
        res.writeHead(200, { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="agent-custody-registrations-${r.month}.csv"`, "cache-control": "no-store" });
        res.end(csv);
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "audit") {
        const tenant = url.searchParams.get("tenant");
        const limit = url.searchParams.has("limit") ? Number(url.searchParams.get("limit")) : 200;
        if (!Number.isInteger(limit) || limit < 1 || limit > 1000) return json(400, { error: "limit must be an integer in 1..1000" }), true;
        json(200, { entries: await t.audit({ ...(tenant ? { tenant } : {}), limit }) });
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "info") {
        json(200, { publicUrl: opts.publicUrl ?? null, checkpointsUrl: opts.checkpointsUrl ?? null, keyid: opts.keyid ?? null });
      } else if (req.method === "GET" && parts.length === 2 && parts[1] === "tenants") {
        const tenants = await t.listTenants();
        json(200, await Promise.all(tenants.map(async (x) => ({ ...x, tokens: (await t.listTokens(x.id)).filter((k) => !k.revokedAt).length }))));
      } else if (req.method === "POST" && parts.length === 2 && parts[1] === "tenants") {
        const b = await body();
        if (typeof b.id !== "string" || !/^[A-Za-z0-9_.-]+$/.test(b.id)) return json(400, { error: "id must be a plain identifier" }), true;
        json(200, await t.addTenant(b.id, typeof b.logId === "string" && b.logId ? b.logId : b.id, actor));
      } else if (req.method === "POST" && parts.length === 4 && parts[1] === "tenants" && parts[3] === "plan") {
        const b = await body();
        if (typeof b.plan !== "string" || !(PLANS as readonly string[]).includes(b.plan)) return json(400, { error: `plan must be one of ${PLANS.join(", ")}` }), true;
        json(200, await t.setPlan(parts[2]!, b.plan as Plan, actor));
      } else if (req.method === "POST" && parts.length === 4 && parts[1] === "tenants" && parts[3] === "disable") {
        await t.disableTenant(parts[2]!, actor);
        json(200, { disabled: parts[2] });
      } else if (req.method === "GET" && parts.length === 4 && parts[1] === "tenants" && parts[3] === "tokens") {
        json(200, await t.listTokens(parts[2]!));
      } else if (req.method === "POST" && parts.length === 4 && parts[1] === "tenants" && parts[3] === "tokens") {
        const b = await body();
        const label = typeof b.label === "string" && b.label.trim() ? b.label.trim() : "fleet";
        const tenant = await t.tenant(parts[2]!);
        if (!tenant) return json(404, { error: "unknown tenant" }), true;
        const minted = await t.addToken(tenant.id, label, actor);
        const welcome = opts.publicUrl ? welcomeSheet({ tenant: tenant.id, logId: tenant.logId, publicUrl: opts.publicUrl, ...(opts.checkpointsUrl ? { checkpointsUrl: opts.checkpointsUrl } : {}), ...(opts.keyid ? { keyid: opts.keyid } : {}) }) : null;
        json(200, { ...minted, welcome });
      } else if (req.method === "POST" && parts.length === 6 && parts[1] === "tenants" && parts[3] === "tokens" && parts[5] === "revoke") {
        json(200, { revoked: await t.revokeToken(parts[2]!, parts[4]!, actor) });
      } else {
        json(404, { error: "not found" });
      }
    } catch (e) {
      json(400, { error: e instanceof Error ? e.message : String(e) });
    }
    return true;
  };
}

/** The page. One file, no framework, no third-party requests; the browser holds the admin credential it prompted for. */
const ADMIN_PAGE = `<!doctype html>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>agent-custody log admin</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script>(() => { try { const t = localStorage.getItem("agent-custody-theme"); if (t === "dark" || t === "light") document.documentElement.dataset.theme = t; } catch {} })();</script>
<style>
  :root { color-scheme: light dark; --ink: #1b2430; --ink2: #5b6b7a; --line: #d7dfe5; --bg: #fafbfc; --panel: #ffffff; --accent: #0f6e63; --warn: #8a5a00; --warnbg: #fbf1dc; --mono: ui-monospace, Menlo, monospace; }
  @media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { --ink: #e6ecf0; --ink2: #9fb0bd; --line: #27333c; --bg: #0e1418; --panel: #151d23; --accent: #4fc3b0; --warn: #e2b862; --warnbg: #2d2412; } }
  :root[data-theme="dark"] { --ink: #e6ecf0; --ink2: #9fb0bd; --line: #27333c; --bg: #0e1418; --panel: #151d23; --accent: #4fc3b0; --warn: #e2b862; --warnbg: #2d2412; }
  body { margin: 0; background: var(--bg); color: var(--ink); font: 15px/1.5 system-ui, sans-serif; }
  main { max-width: 72rem; margin: 0 auto; padding: 2rem 1.25rem 4rem; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; } h2 { font-size: 1.05rem; margin: 2rem 0 .75rem; }
  .sub { color: var(--ink2); margin: 0 0 1.5rem; }
  .row { display: flex; gap: .6rem; flex-wrap: wrap; align-items: end; }
  label { display: grid; gap: .25rem; font-size: .85rem; color: var(--ink2); }
  input { font: inherit; padding: .45rem .6rem; border: 1px solid var(--line); border-radius: 4px; background: var(--panel); color: var(--ink); min-width: 14rem; }
  button { font: inherit; padding: .5rem .9rem; border: 1px solid var(--accent); border-radius: 4px; background: var(--accent); color: #fff; cursor: pointer; }
  button.quiet { background: transparent; color: var(--accent); }
  button:disabled { opacity: .5; cursor: default; }
  table { border-collapse: collapse; width: 100%; font-size: .93rem; }
  th, td { text-align: left; padding: .5rem .6rem; border-bottom: 1px solid var(--line); vertical-align: top; }
  th { font-size: .78rem; letter-spacing: .04em; text-transform: uppercase; color: var(--ink2); }
  code, pre { font-family: var(--mono); font-size: .86em; }
  pre { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: .9rem 1rem; overflow-x: auto; white-space: pre-wrap; }
  .once { border-left: 3px solid var(--warn); background: var(--warnbg); padding: .8rem 1rem; border-radius: 0 4px 4px 0; margin: 1rem 0; }
  .muted { color: var(--ink2); } .err { color: #b3261e; } .ok { color: var(--accent); }
  .tok { font-family: var(--mono); font-size: 1.05rem; word-break: break-all; user-select: all; }
  .head { display: flex; justify-content: space-between; align-items: start; gap: 1rem; }
  button.theme { background: transparent; color: var(--ink2); border: 1px solid var(--line); padding: .25rem .6rem; font-size: .8rem; border-radius: 4px; } button.theme:hover { color: var(--ink); }
  [hidden] { display: none !important; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(9rem, 1fr)); gap: .6rem; margin: 0 0 1rem; }
  .stat { background: var(--panel); border: 1px solid var(--line); border-radius: 4px; padding: .6rem .8rem; }
  .stat b { display: block; font-size: 1.4rem; font-variant-numeric: tabular-nums; } .stat span { color: var(--ink2); font-size: .8rem; }
</style>
<main>
  <div class="head"><div><h1>Log admin</h1>
  <p class="sub" id="where">Tenants and tokens on this log.</p></div><button class="theme" id="themeToggle" type="button">Dark mode</button></div>
  <section id="app">
    <h2>Registrations</h2>
    <div class="row"><label>month<input id="rmonth" type="month"></label><button class="quiet" id="loadRegs">Show</button><a id="rcsv" class="quiet" href="#" style="align-self:center">Download CSV</a></div>
    <div class="stats"><div class="stat"><b id="sTenants">–</b><span>tenants</span></div><div class="stat"><b id="sRegistered">–</b><span>registered through the portal</span></div><div class="stat"><b id="sAppends">–</b><span>appends this month</span></div><div class="stat"><b id="sLeaves">–</b><span>leaves in total</span></div></div>
    <table><thead><tr><th>who</th><th>reach</th><th>tenant</th><th>plan</th><th>registered</th><th>billing</th><th>appends this month</th><th>leaves in total</th><th>live tokens</th></tr></thead><tbody id="regs"></tbody></table>
    <h2>Tenants</h2>
    <table><thead><tr><th>tenant</th><th>log id</th><th>plan</th><th>live tokens</th><th>created</th><th></th></tr></thead><tbody id="tenants"></tbody></table>
    <h2>New tenant</h2>
    <div class="row">
      <label>tenant id (in the URL)<input id="tid" placeholder="acme" autocomplete="off"></label>
      <label>log id (on tree heads; default = tenant id)<input id="lid" placeholder="acme-eu" autocomplete="off"></label>
      <button id="addTenant">Create</button>
    </div>
    <h2>New token</h2>
    <div class="row">
      <label>tenant<input id="ttid" placeholder="acme" autocomplete="off"></label>
      <label>label (which fleet)<input id="label" placeholder="support fleet" autocomplete="off"></label>
      <button id="mint">Mint token</button>
    </div>
    <div id="minted" class="once" hidden>
      <p><b>Shown once.</b> Hand it over by a channel you trust; the log keeps only its hash.</p>
      <p class="tok" id="tokval"></p>
      <button class="quiet" id="copyTok">Copy token</button> <button class="quiet" id="copySheet">Copy welcome sheet</button>
      <pre id="sheet"></pre>
    </div>
    <h2>Usage</h2>
    <div class="row"><label>month<input id="month" type="month"></label><button class="quiet" id="loadUsage">Show</button><a id="csv" class="quiet" href="#" style="align-self:center">Download CSV</a></div>
    <table><thead><tr><th>tenant</th><th>log id</th><th>plan</th><th>appends this month</th><th>quota</th><th>leaves in total</th><th>live tokens</th></tr></thead><tbody id="usage"></tbody></table>
    <h2>Tokens of a tenant</h2>
    <div class="row"><label>tenant<input id="ltid" placeholder="acme" autocomplete="off"></label><button class="quiet" id="listTokens">List</button></div>
    <table><thead><tr><th>label</th><th>hash</th><th>created</th><th>state</th><th></th></tr></thead><tbody id="tokens"></tbody></table>
    <h2>Activity</h2>
    <p class="muted">Every tenant and token change on this log, newest first, with who made it: the name entered at the sign-in prompt, or the command line on the server. Tenants see their own rows in their export.</p>
    <table><thead><tr><th>when</th><th>who</th><th>action</th><th>tenant</th><th>detail</th></tr></thead><tbody id="audit"></tbody></table>
    <p class="muted" id="msg"></p>
  </section>
</main>
<script>
(() => {
  const $ = (id) => document.getElementById(id);
  // The browser sends the credential it prompted for on every request under /admin; nothing is stored by this page.
  const api = async (method, path, body) => {
    const r = await fetch(path, { method, headers: body ? { "content-type": "application/json" } : {}, body: body ? JSON.stringify(body) : undefined, credentials: "same-origin" });
    const j = await r.json().catch(() => ({}));
    if (r.status === 401) throw new Error("the admin token was not accepted; reload the page and enter it again");
    if (!r.ok) throw new Error(j.error || r.statusText);
    return j;
  };
  const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  const say = (t, cls) => { $("msg").textContent = t; $("msg").className = cls || "muted"; };
  // Light or dark by choice, kept in this browser; unset, the page follows the system. The button says where it is going.
  const themeNow = () => document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const themeLabel = () => { $("themeToggle").textContent = themeNow() === "dark" ? "Light mode" : "Dark mode"; };
  $("themeToggle").onclick = () => { const next = themeNow() === "dark" ? "light" : "dark"; document.documentElement.dataset.theme = next; try { localStorage.setItem("agent-custody-theme", next); } catch {} themeLabel(); };
  themeLabel();
  const loadTenants = async () => {
    const list = await api("GET", "/admin/tenants");
    const planPick = (t) => "<select data-plan=\\"" + esc(t.id) + "\\">" + ["free", "team", "enterprise"].map((p) => "<option" + (p === t.plan ? " selected" : "") + ">" + p + "</option>").join("") + "</select>";
    $("tenants").innerHTML = list.map((t) => "<tr><td><code>" + esc(t.id) + "</code></td><td><code>" + esc(t.logId) + "</code></td><td>" + planPick(t) + "</td><td>" + t.tokens + "</td><td>" + esc(t.createdAt.slice(0, 10)) + "</td><td>" + (t.disabledAt ? "<span class=muted>disabled</span>" : "<button class=quiet data-disable=\\"" + esc(t.id) + "\\">Disable</button>") + "</td></tr>").join("") || "<tr><td colspan=6 class=muted>none yet</td></tr>";
  };
  const loadTokens = async (id) => {
    const list = await api("GET", "/admin/tenants/" + encodeURIComponent(id) + "/tokens");
    $("tokens").innerHTML = list.map((k) => "<tr><td>" + esc(k.label) + "</td><td><code>" + esc(k.tokenHash.slice(0, 12)) + "</code></td><td>" + esc(k.createdAt.slice(0, 10)) + "</td><td>" + (k.revokedAt ? "revoked " + esc(k.revokedAt.slice(0, 10)) : "<span class=ok>live</span>") + "</td><td>" + (k.revokedAt ? "" : "<button class=quiet data-revoke=\\"" + esc(id) + "|" + esc(k.tokenHash.slice(0, 12)) + "\\">Revoke</button>") + "</td></tr>").join("") || "<tr><td colspan=5 class=muted>no tokens</td></tr>";
  };
  const enter = async () => {
    try {
      const info = await api("GET", "/admin/info");
      $("where").textContent = (info.publicUrl || location.origin) + " · keyid " + (info.keyid ? info.keyid.slice(0, 12) : "?") + (info.checkpointsUrl ? " · checkpoints at " + info.checkpointsUrl : "");
      await loadRegs();
      await loadTenants();
      await loadUsage();
      await loadAudit();
    } catch (e) { say(e.message, "err"); }
  };
  $("addTenant").onclick = async () => { try { const t = await api("POST", "/admin/tenants", { id: $("tid").value.trim(), logId: $("lid").value.trim() }); say("tenant " + t.id + " created; reached at /t/" + t.id + "/", "ok"); $("ttid").value = t.id; await loadTenants(); await loadAudit(); } catch (e) { say(e.message, "err"); } };
  $("mint").onclick = async () => {
    try {
      const r = await api("POST", "/admin/tenants/" + encodeURIComponent($("ttid").value.trim()) + "/tokens", { label: $("label").value.trim() });
      $("tokval").textContent = r.token; $("sheet").textContent = r.welcome || "(set --public-url on the server for the welcome sheet)"; $("minted").hidden = false;
      say("token minted for " + $("ttid").value.trim() + "; stored as hash " + r.tokenHash.slice(0, 12), "ok");
      await loadTenants();
      await loadAudit();
    } catch (e) { say(e.message, "err"); }
  };
  $("copyTok").onclick = () => navigator.clipboard.writeText($("tokval").textContent).then(() => say("token copied", "ok"));
  $("copySheet").onclick = () => navigator.clipboard.writeText($("sheet").textContent).then(() => say("welcome sheet copied", "ok"));
  $("listTokens").onclick = () => loadTokens($("ltid").value.trim()).catch((e) => say(e.message, "err"));
  const loadUsage = async () => {
    const month = $("month").value || new Date().toISOString().slice(0, 7);
    const u = await api("GET", "/admin/usage?month=" + encodeURIComponent(month));
    $("csv").href = "/admin/usage.csv?month=" + encodeURIComponent(month);
    $("usage").innerHTML = u.tenants.map((t) => "<tr><td><code>" + esc(t.id) + "</code>" + (t.disabled ? " <span class=muted>disabled</span>" : "") + "</td><td><code>" + esc(t.logId) + "</code></td><td>" + esc(t.plan) + "</td><td>" + t.appends + "</td><td>" + (t.quota === null ? "none" : t.quota) + "</td><td>" + t.totalLeaves + "</td><td>" + t.liveTokens + "</td></tr>").join("") || "<tr><td colspan=7 class=muted>no tenants</td></tr>";
  };
  const loadRegs = async () => {
    const month = $("rmonth").value || new Date().toISOString().slice(0, 7);
    const r = await api("GET", "/admin/registrations?month=" + encodeURIComponent(month));
    $("rcsv").href = "/admin/registrations.csv?month=" + encodeURIComponent(month);
    $("sTenants").textContent = r.totals.tenants; $("sRegistered").textContent = r.totals.registered; $("sAppends").textContent = r.totals.appends; $("sLeaves").textContent = r.totals.totalLeaves;
    const who = (x) => x.email ? esc(x.name || "") + (x.company ? " <span class=muted>· " + esc(x.company) + (x.role ? ", " + esc(x.role) : "") + "</span>" : "") : "<span class=muted>onboarded by script</span>";
    const reach = (x) => [x.email ? "<a href=\\"mailto:" + esc(x.email) + "\\">" + esc(x.email) + "</a>" : "", x.phone ? esc(x.phone) : "", x.telegram ? "telegram @" + esc(x.telegram) : ""].filter(Boolean).join("<br>");
    $("regs").innerHTML = r.rows.map((x) => "<tr><td>" + who(x) + "</td><td>" + reach(x) + "</td><td><code>" + esc(x.tenant) + "</code>" + (x.disabled ? " <span class=muted>disabled</span>" : "") + "</td><td>" + esc(x.plan) + "</td><td>" + (x.registeredAt ? esc(x.registeredAt.slice(0, 10)) : "") + "</td><td>" + (x.billing ? esc(x.billing) : "<span class=muted>none</span>") + "</td><td>" + x.appends + (x.quota === null ? "" : " <span class=muted>/ " + x.quota + "</span>") + "</td><td>" + x.totalLeaves + "</td><td>" + x.liveTokens + "</td></tr>").join("") || "<tr><td colspan=9 class=muted>no tenants</td></tr>";
  };
  const loadAudit = async () => {
    const a = await api("GET", "/admin/audit?limit=100");
    $("audit").innerHTML = a.entries.map((e) => "<tr><td>" + esc(e.at.replace("T", " ").slice(0, 19)) + "</td><td><code>" + esc(e.actor) + "</code></td><td>" + esc(e.action) + "</td><td><code>" + esc(e.tenantId || "") + "</code></td><td class=muted>" + esc(Object.entries(e.detail).map(([k, v]) => k + "=" + v).join(" ")) + "</td></tr>").join("") || "<tr><td colspan=5 class=muted>nothing yet</td></tr>";
  };
  $("loadUsage").onclick = () => loadUsage().catch((e) => say(e.message, "err"));
  $("loadRegs").onclick = () => loadRegs().catch((e) => say(e.message, "err"));
  $("month").value = $("rmonth").value = new Date().toISOString().slice(0, 7);
  document.addEventListener("change", async (e) => {
    const s = e.target.closest("select[data-plan]"); if (!s) return;
    try { await api("POST", "/admin/tenants/" + encodeURIComponent(s.dataset.plan) + "/plan", { plan: s.value }); say("plan of " + s.dataset.plan + " set to " + s.value, "ok"); await loadRegs(); await loadUsage(); await loadAudit(); } catch (err) { say(err.message, "err"); await loadTenants(); }
  });
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("button"); if (!b) return;
    if (b.dataset.disable && confirm("Disable tenant " + b.dataset.disable + "? Its paths answer 404 within ten seconds.")) { try { await api("POST", "/admin/tenants/" + encodeURIComponent(b.dataset.disable) + "/disable"); await loadTenants(); await loadAudit(); say("disabled " + b.dataset.disable, "ok"); } catch (err) { say(err.message, "err"); } }
    if (b.dataset.revoke) { const [id, prefix] = b.dataset.revoke.split("|"); if (confirm("Revoke token " + prefix + " of " + id + "?")) { try { await api("POST", "/admin/tenants/" + encodeURIComponent(id) + "/tokens/" + prefix + "/revoke"); await loadTokens(id); await loadTenants(); await loadAudit(); say("revoked", "ok"); } catch (err) { say(err.message, "err"); } } }
  });
  enter();
})();
</script>
`;
