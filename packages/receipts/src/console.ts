// The gateway console: a small admin service, separate from the gateway, for the person who runs it. It shows what the
// gateway is configured to do and what it has done, validates and simulates a policy change before it is saved, and
// revokes a grant. It never holds a principal's private key and never signs; everything it shows is read from the
// gateway's own config, receipts, and revocation file, and everything it changes is the policy file or the revocation
// file, both of which the gateway reads. Every change is recorded in an append-only audit file.
import * as cedar from "@cedar-policy/cedar-wasm/nodejs";
import { createHash, timingSafeEqual } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, statSync, unlinkSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { basename, dirname, join } from "node:path";
import { checkConfig } from "./check.ts";
import { loadConfig, type GatewayConfig } from "./config.ts";
import { loadPrivateKey, loadPublicKey, type Envelope, type PublicKeyRef } from "./crypto.ts";
import { decodeDelegation, delegationValidAt, grantDigest, verifyDelegation } from "./delegation.ts";
import { writeRevokedGrants } from "./gateway.ts";
import { CONSOLE_CSP, CONSOLE_HTML } from "./console-page.ts";
import { hasPermitRule, policyDigest } from "./policy.ts";
import { isRegoFile } from "./policy-rego.ts";
import type { ReceiptBundle, ReceiptPredicate, ReceiptStatement } from "./receipt.ts";
import { simulatePolicy } from "./simulate.ts";
import { verifyBundle } from "./verify.ts";

export interface ConsoleOptions {
  /** the gateway's config file; read again on every request, so an edit shows at once */
  configFile: string;
  /** the shared secret every API request must present as `Authorization: Bearer`; read from the environment by the CLI */
  token: string;
  port?: number;
  host?: string;
  /** the running gateway's base URL, for its health; omitted means the console does not look */
  gatewayUrl?: string;
  /** where the console keeps its audit file and the history of saved policies; default beside the receipts directory */
  stateDir?: string;
  /** how long a --connect check may take before it is stopped and the upstreams it started are closed; default 60 seconds */
  checkTimeoutMs?: number;
  log?: (message: string) => void;
}

export interface RunningConsole {
  url: string;
  close(): Promise<void>;
}

const MAX_BODY = 1_000_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

class HttpError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

/** The console edits Cedar files. A Rego file is edited where it lives, and an OPA server's policy in its bundles. */
function cedarPolicyFile(cfg: GatewayConfig): string {
  if (!cfg.policyFile) throw new HttpError(409, `this gateway asks the OPA server at ${cfg.opa?.url} for its decisions; edit the policy in the server's bundles`);
  if (isRegoFile(cfg.policyFile)) throw new HttpError(409, `${basename(cfg.policyFile)} is a Rego policy; the console edits Cedar policies only, so edit it in place and the gateway compiles it on its next call`);
  return cfg.policyFile;
}

const sha = (s: string) => createHash("sha256").update(s).digest();

function atomicWrite(path: string, text: string): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, text);
  renameSync(tmp, path);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new HttpError(413, "the request body is too large");
    chunks.push(chunk as Buffer);
  }
  if (!size) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "the body is not JSON");
  }
}

const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new HttpError(400, "the body must be a JSON object");
  return v as Record<string, unknown>;
};

const decodePredicate = (bundle: ReceiptBundle): ReceiptPredicate | null => {
  try {
    return (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement).predicate;
  } catch {
    return null;
  }
};

/**
 * What an operator should be asked to confirm before a policy is saved: no permit rule at all, or a permit rule that has no
 * condition and names no action, which allows every tool in a grant's scopes. Replaying recorded calls cannot show the
 * second one: it changes nothing for a history that never used what it allows.
 */
function policyIssues(text: string): string[] {
  const issues: string[] = [];
  if (!hasPermitRule(text)) issues.push("The policy has no permit rule, so every call would be denied.");
  const parts = cedar.policySetTextToParts(text);
  if (parts.type === "success") {
    for (const p of parts.policies) {
      const j = cedar.policyToJson(p);
      if (j.type === "success" && j.json.effect === "permit" && j.json.action?.op === "All" && !(j.json.conditions?.length)) {
        const who = j.json.principal?.op === "All" ? "for every agent" : "for the agent it names";
        issues.push(`A permit rule has no action and no condition: it allows every tool in a grant's scopes, ${who}. A replay cannot show this, because it only re-decides calls that already happened.`);
      }
    }
  }
  return issues;
}

export async function serveConsole(options: ConsoleOptions): Promise<RunningConsole> {
  const log = options.log ?? ((m: string) => console.error(m));
  const tokenHash = sha(options.token);
  if (!options.token) throw new Error("the console needs a token");
  loadConfig(options.configFile);
  const state = options.stateDir ?? join(dirname(loadConfig(options.configFile).receiptsDir), "console");
  mkdirSync(join(state, "policy-history"), { recursive: true });
  const auditFile = join(state, "audit.jsonl");
  let connecting = false;

  const audit = (action: string, detail: Record<string, unknown>, by: string) => {
    appendFileSync(auditFile, JSON.stringify({ at: new Date().toISOString(), by, action, ...detail }) + "\n");
  };

  /** the keys the console verifies receipts with: the gateway's own public key and the trusted principals' */
  const keysOf = (cfg: GatewayConfig): { issuerKeys: PublicKeyRef[]; principalKeys: PublicKeyRef[]; problems: string[] } => {
    const problems: string[] = [];
    const issuerKeys: PublicKeyRef[] = [];
    try {
      if (existsSync(cfg.identity.keyFile)) {
        const k = loadPrivateKey(cfg.identity.keyFile);
        issuerKeys.push({ publicKey: k.publicKey, keyid: k.keyid });
      } else problems.push("the gateway key does not exist yet, so receipts cannot be verified");
    } catch (e) {
      problems.push(`the gateway key: ${e instanceof Error ? e.message : String(e)}`);
    }
    const principalKeys: PublicKeyRef[] = [];
    for (const f of cfg.trustedPrincipalKeys) {
      try {
        principalKeys.push(loadPublicKey(f));
      } catch (e) {
        problems.push(`${f}: ${e instanceof Error ? e.message : String(e)}`);
      }
    }
    return { issuerKeys, principalKeys, problems };
  };

  const revokedList = (cfg: GatewayConfig): string[] => {
    if (!cfg.revokedGrants || !existsSync(cfg.revokedGrants)) return [];
    const list = JSON.parse(readFileSync(cfg.revokedGrants, "utf8")) as unknown;
    return Array.isArray(list) ? list.filter((d): d is string => typeof d === "string") : [];
  };

  /** the receipt files, newest first; an authorization that has no receipt is not one */
  const receiptFiles = (cfg: GatewayConfig): { id: string; file: string; mtime: number }[] => {
    if (!existsSync(cfg.receiptsDir)) return [];
    return readdirSync(cfg.receiptsDir)
      .filter((n) => n.endsWith(".json") && !n.endsWith(".authorization.json") && UUID.test(n.slice(0, -5)))
      .map((n) => ({ id: n.slice(0, -5), file: join(cfg.receiptsDir, n), mtime: statSync(join(cfg.receiptsDir, n)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
  };

  const verifyOptionsFor = (cfg: GatewayConfig, keys: ReturnType<typeof keysOf>) => ({
    issuerKeys: keys.issuerKeys,
    principalKeys: keys.principalKeys,
    ...(cfg.logFile && existsSync(cfg.logFile) ? { logFile: cfg.logFile } : {}),
  });

  const summarize = (id: string, file: string, cfg: GatewayConfig, keys: ReturnType<typeof keysOf>) => {
    let bundle: ReceiptBundle;
    try {
      bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
    } catch {
      return { id, readable: false, verified: false, failing: ["the file is not readable JSON"] };
    }
    const p = decodePredicate(bundle);
    const v = keys.issuerKeys.length ? verifyBundle(bundle, verifyOptionsFor(cfg, keys)) : null;
    const execution = (p?.execution ?? {}) as { status?: string; reason?: string };
    return {
      id,
      readable: true,
      timestamp: p?.timestamp ?? null,
      tool: p?.tool?.name ?? null,
      agent: p?.agent?.id ?? null,
      principal: p?.principal?.id ?? null,
      decision: p?.policy?.decision ?? null,
      enforced: p?.policy?.enforced !== false,
      status: execution.status ?? null,
      reason: execution.reason ?? null,
      issuer: p?.issuer?.kind ?? null,
      verified: v ? v.ok : false,
      failing: v ? v.checks.filter((c) => !c.ok).map((c) => c.name) : ["no gateway key to verify with"],
    };
  };

  const gatewayHealth = async (): Promise<Record<string, unknown> | null> => {
    if (!options.gatewayUrl) return null;
    try {
      const r = await fetch(new URL("health", options.gatewayUrl.endsWith("/") ? options.gatewayUrl : `${options.gatewayUrl}/`), { signal: AbortSignal.timeout(2000) });
      const body = (await r.json()) as Record<string, unknown>;
      return { reachable: r.ok, sessions: body.sessions ?? null, keyid: body.keyid ?? null };
    } catch (e) {
      return { reachable: false, error: e instanceof Error ? e.message : String(e) };
    }
  };

  const upstreamsOf = (cfg: GatewayConfig) =>
    (cfg.upstreams ?? (cfg.upstream ? [{ name: "upstream", ...cfg.upstream }] : [])).map((u) => {
      const name = "name" in u ? u.name : "upstream";
      if ("rest" in u) return { name, kind: "rest", target: u.rest.baseUrl, tools: u.rest.tools.map((t) => t.name) };
      if ("a2a" in u) return { name, kind: "a2a", target: u.a2a.url, tools: [`${u.a2a.prefix}.send`, `${u.a2a.prefix}.card`] };
      if ("url" in u) return { name, kind: "mcp-http", target: u.url, tools: null };
      return { name, kind: "mcp-stdio", target: [u.command, ...u.args].join(" "), tools: null };
    });

  // saves are serialised in this process, and a lock file in the state directory serialises another console on the same one
  const lockFile = join(state, "policy.lock");
  let saving: Promise<unknown> = Promise.resolve();
  const withPolicyLock = <T,>(fn: () => T): Promise<T> => {
    const run = saving.then(async () => {
      const deadline = Date.now() + 5_000;
      for (;;) {
        try {
          closeSync(openSync(lockFile, "wx"));
          break;
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
          try {
            if (Date.now() - statSync(lockFile).mtimeMs > 30_000) {
              unlinkSync(lockFile);
              continue;
            }
          } catch {
            continue;
          }
          if (Date.now() > deadline) throw new HttpError(409, "another save is in progress; try again");
          await new Promise((r) => setTimeout(r, 50));
        }
      }
      try {
        return fn();
      } finally {
        try {
          unlinkSync(lockFile);
        } catch {
          /* already gone */
        }
      }
    });
    saving = run.catch(() => {});
    return run;
  };

  // ---- the API ----

  type Handler = (req: IncomingMessage, url: URL, by: string) => Promise<unknown>;
  const routes: Record<string, Handler> = {
    "GET /api/overview": async () => {
      const cfg = loadConfig(options.configFile);
      const keys = keysOf(cfg);
      const receipts = receiptFiles(cfg);
      return {
        configFile: options.configFile,
        mode: cfg.mode ?? "enforce",
        precommit: cfg.precommit,
        log: cfg.log ? { kind: "remote", url: cfg.log.url, hashOnly: !!cfg.log.hashOnly } : { kind: "local", file: cfg.logFile },
        upstreams: upstreamsOf(cfg),
        facts: cfg.facts.map((f) => ({ name: f.name, tool: f.tool, forTools: f.forTools })),
        gatewayKeyid: keys.issuerKeys[0]?.keyid ?? null,
        principals: keys.principalKeys.map((k) => k.keyid),
        keyProblems: keys.problems,
        revokedCount: revokedList(cfg).length,
        revocationFile: cfg.revokedGrants ?? null,
        receiptCount: receipts.length,
        lastReceiptAt: receipts[0] ? new Date(receipts[0].mtime).toISOString() : null,
        gateway: await gatewayHealth(),
        findings: await checkConfig(options.configFile, { environment: "skip" }),
      };
    },

    "POST /api/check": async (req) => {
      const connect = object(await readBody(req)).connect === true;
      if (connect) {
        if (connecting) throw new HttpError(409, "a connect check is already running");
        connecting = true;
      }
      const stop = new AbortController();
      const timer = connect ? setTimeout(() => stop.abort(), options.checkTimeoutMs ?? 60_000) : undefined;
      try {
        const findings = await checkConfig(options.configFile, { connect, environment: "skip", signal: stop.signal });
        if (stop.signal.aborted) throw new HttpError(504, "the check took too long and was stopped; the upstreams it started were closed");
        return { findings };
      } finally {
        clearTimeout(timer);
        if (connect) connecting = false;
      }
    },

    "GET /api/policy": async () => {
      const policyFile = cedarPolicyFile(loadConfig(options.configFile));
      const text = readFileSync(policyFile, "utf8");
      return { path: policyFile, text, digest: policyDigest(text), history: readdirSync(join(state, "policy-history")).sort().reverse().slice(0, 20) };
    },

    "POST /api/policy/validate": async (req) => {
      const text = String(object(await readBody(req)).text ?? "");
      const r = cedar.checkParsePolicySet({ staticPolicies: text });
      const errors = r.type === "success" ? [] : r.errors.map((e) => e.message);
      return { ok: r.type === "success", errors, digest: policyDigest(text), issues: r.type === "success" ? policyIssues(text) : [] };
    },

    "POST /api/policy/simulate": async (req) => {
      const text = String(object(await readBody(req)).text ?? "");
      const cfg = loadConfig(options.configFile);
      const keys = keysOf(cfg);
      if (!keys.issuerKeys.length) throw new HttpError(409, "there is no gateway key to verify receipts with, so there is nothing to replay");
      const predicates: ReceiptPredicate[] = [];
      let unverified = 0;
      for (const f of receiptFiles(cfg).slice(0, 1000)) {
        try {
          const bundle = JSON.parse(readFileSync(f.file, "utf8")) as ReceiptBundle;
          const p = decodePredicate(bundle);
          if (p && verifyBundle(bundle, verifyOptionsFor(cfg, keys)).ok) predicates.push(p);
          else unverified++;
        } catch {
          unverified++;
        }
      }
      let report;
      try {
        report = simulatePolicy(text, predicates);
      } catch (e) {
        throw new HttpError(400, e instanceof Error ? e.message : String(e));
      }
      return {
        replayed: predicates.length,
        unverified,
        report: {
          policyDigest: report.policyDigest,
          total: report.total,
          evaluated: report.evaluated,
          unchanged: report.unchanged,
          reconciliations: report.reconciliations,
          complete: report.complete,
          changes: report.changes.slice(0, 200).map((c) => ({ receiptId: c.receiptId, tool: c.tool, from: c.previous.decision, to: c.proposed.decision })),
          changeCount: report.changes.length,
          skipped: report.skipped.slice(0, 50),
        },
      };
    },

    "PUT /api/policy": async (req, _url, by) => {
      const body = object(await readBody(req));
      const text = String(body.text ?? "");
      const parsed = cedar.checkParsePolicySet({ staticPolicies: text });
      if (parsed.type !== "success") throw new HttpError(400, `the policy does not parse: ${parsed.errors.map((e) => e.message).join("; ")}`);
      const issues = policyIssues(text);
      if (issues.length && body.confirm !== true) throw new HttpError(400, `confirm before saving: ${issues.join(" ")}`);
      // from reading the digest to the rename, nothing else may save: two tabs that loaded the same digest would otherwise both pass the
      // check, the later rename would win, and the history of the lost edit would not even be the version it replaced
      return withPolicyLock(() => {
        const policyFile = cedarPolicyFile(loadConfig(options.configFile));
        const current = readFileSync(policyFile, "utf8");
        if (body.expectDigest !== policyDigest(current)) throw new HttpError(409, "the policy file changed since you loaded it; reload and try again");
        writeFileSync(join(state, "policy-history", `${new Date().toISOString().replace(/[:.]/g, "-")}-${policyDigest(current).slice(0, 12)}.cedar`), current);
        try {
          atomicWrite(policyFile, text);
        } catch (e) {
          throw new HttpError(500, `the policy file cannot be written (${e instanceof Error ? e.message : String(e)}); mount the config directory read-write for the console`);
        }
        audit("policy.save", { file: policyFile, from: policyDigest(current), to: policyDigest(text), bytes: text.length, confirmed: issues }, by);
        return { digest: policyDigest(text), note: "saved; a running gateway applies it from its next call" };
      });
    },

    "POST /api/grants/inspect": async (req) => {
      const body = object(await readBody(req));
      const cfg = loadConfig(options.configFile);
      const keys = keysOf(cfg);
      const env = (typeof body.grant === "string" ? safeJson(body.grant) : body.grant) as Envelope | undefined;
      if (!env || typeof env !== "object") throw new HttpError(400, "send the grant as a JSON object or a JSON string");
      const decoded = decodeDelegation(env);
      if (!decoded) throw new HttpError(400, "this is not a delegation grant");
      const digest = grantDigest(env);
      const verified = verifyDelegation(env, keys.principalKeys);
      const revoked = revokedList(cfg).includes(digest);
      const now = new Date().toISOString();
      let status: string;
      if (!verified.ok) status = "invalid";
      else if (revoked) status = "revoked";
      else if (!delegationValidAt(verified.delegation, now)) status = Date.parse(verified.delegation.expiresAt) < Date.now() ? "expired" : "not yet valid";
      else status = "valid";
      return {
        status,
        error: verified.ok ? null : verified.error,
        digest,
        agent: decoded.agent,
        principal: decoded.principal,
        scopes: decoded.scopes,
        issuedAt: decoded.issuedAt,
        expiresAt: decoded.expiresAt,
        delegated: !!decoded.parent,
        canDelegate: !!decoded.agentKey,
        revoked,
      };
    },

    "POST /api/grants/revoke": async (req, _url, by) => {
      const body = object(await readBody(req));
      const cfg = loadConfig(options.configFile);
      if (!cfg.revokedGrants) throw new HttpError(409, "the config has no revokedGrants file, which is where the gateway looks for revoked grants");
      const env = (typeof body.grant === "string" ? safeJson(body.grant) : body.grant) as Envelope | undefined;
      if (!env || typeof env !== "object") throw new HttpError(400, "send the grant as a JSON object or a JSON string");
      const decoded = decodeDelegation(env);
      if (!decoded) throw new HttpError(400, "this is not a delegation grant");
      const digest = grantDigest(env);
      const list = revokedList(cfg);
      if (!list.includes(digest)) writeRevokedGrants(cfg.revokedGrants, [...list, digest]);
      audit("grant.revoke", { agent: decoded.agent, principal: decoded.principal, digest, already: list.includes(digest) }, by);
      return { digest, agent: decoded.agent, note: "the gateway refuses this grant, and every grant delegated from it, on its next call" };
    },

    "GET /api/revocations": async () => ({ digests: revokedList(loadConfig(options.configFile)) }),

    "GET /api/receipts": async (_req, url) => {
      const cfg = loadConfig(options.configFile);
      const keys = keysOf(cfg);
      const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
      const files = receiptFiles(cfg);
      return { total: files.length, receipts: files.slice(0, limit).map((f) => summarize(f.id, f.file, cfg, keys)), problems: keys.problems };
    },

    "GET /api/audit": async () => ({
      entries: existsSync(auditFile) ? readFileSync(auditFile, "utf8").trim().split("\n").filter(Boolean).slice(-200).reverse().map((l) => JSON.parse(l) as unknown) : [],
    }),
  };

  const safeJson = (s: string): unknown => {
    try {
      return JSON.parse(s);
    } catch {
      throw new HttpError(400, "the grant is not valid JSON");
    }
  };

  const json = (res: ServerResponse, status: number, body: unknown) => {
    // a body that was refused unread leaves the connection with data on it: close it, so the next request does not reuse it
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options": "nosniff", ...(status === 413 ? { connection: "close" } : {}) });
    res.end(JSON.stringify(body));
  };

  // a wrong token is slow to retry: five misses from one address lock it out for a minute
  const misses = new Map<string, { n: number; until: number }>();
  const authorized = (req: IncomingMessage): { ok: true; by: string } | { ok: false; status: number; message: string } => {
    const ip = req.socket.remoteAddress ?? "unknown";
    const m = misses.get(ip);
    if (m && m.until > Date.now()) return { ok: false, status: 429, message: "too many wrong tokens; try again in a minute" };
    const header = req.headers.authorization ?? "";
    const presented = header.startsWith("Bearer ") ? header.slice(7) : "";
    if (presented && timingSafeEqual(sha(presented), tokenHash)) {
      misses.delete(ip);
      return { ok: true, by: `console@${ip}` };
    }
    // a request with no token at all is not a guess at one, so it does not count towards the lockout
    if (presented) {
      const n = (m?.n ?? 0) + 1;
      misses.set(ip, n >= 5 ? { n: 0, until: Date.now() + 60_000 } : { n, until: 0 });
    }
    return { ok: false, status: 401, message: "a valid bearer token is required" };
  };

  const server: Server = createServer(async (req, res) => {
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      if (req.method === "GET" && url.pathname === "/healthz") return json(res, 200, { ok: true });
      if (req.method === "GET" && url.pathname === "/") {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "content-security-policy": CONSOLE_CSP,
          "x-content-type-options": "nosniff",
          "x-frame-options": "DENY",
          "referrer-policy": "no-referrer",
          "cache-control": "no-store",
        });
        return void res.end(CONSOLE_HTML);
      }
      if (!url.pathname.startsWith("/api/")) return json(res, 404, { error: "not found" });
      const auth = authorized(req);
      if (!auth.ok) return json(res, auth.status, { error: auth.message });
      const receiptId = url.pathname.match(/^\/api\/receipts\/([^/]+)$/);
      if (req.method === "GET" && receiptId) {
        const id = receiptId[1]!;
        if (!UUID.test(id)) return json(res, 400, { error: "a receipt id is a UUID" });
        const cfg = loadConfig(options.configFile);
        const file = join(cfg.receiptsDir, `${id}.json`);
        if (!existsSync(file) || basename(file) !== `${id}.json`) return json(res, 404, { error: "no such receipt" });
        const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
        return json(res, 200, { summary: summarize(id, file, cfg, keysOf(cfg)), statement: decodePredicate(bundle) });
      }
      const handler = routes[`${req.method} ${url.pathname}`];
      if (!handler) return json(res, 404, { error: "not found" });
      json(res, 200, await handler(req, url, auth.by));
    } catch (e) {
      if (e instanceof HttpError) return json(res, e.status, { error: e.message });
      log(`agent-custody console: ${e instanceof Error ? e.stack ?? e.message : String(e)}`);
      json(res, 500, { error: e instanceof Error ? e.message : "internal error" });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 8795, options.host ?? "127.0.0.1", resolve);
  });
  const addr = server.address() as { port: number };
  const host = options.host ?? "127.0.0.1";
  return {
    url: `http://${host === "0.0.0.0" ? "127.0.0.1" : host}:${addr.port}/`,
    close: () => new Promise<void>((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
    }),
  };
}
