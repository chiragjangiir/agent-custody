// The door in front of a stand-in shop: an unknown arrival reads the catalogue and is refused a refund; a verified agent
// refunds within the policy and is refused above it, below zero, and at zero; a grant signed by a stranger, an expired
// grant, and a grant for other routes leave the arrival claimed; a declared name alone is claimed and never reaches the
// Cedar principal; a request that can change something is committed to the log before it is relayed, and not relayed
// when the log refuses; a redirect to the origin's own address comes back through the door; the policy decides before
// the body limit; observe mode relays and records; the origin down is an error receipt. A path cannot move the relay to
// another host or dodge a route by its encoding; every cookie the origin sets arrives; the proxy chain is the proxy's;
// a response too large to relay is still recorded as the origin's act. Every receipt the door writes verifies with
// public keys, the right principal and agent provenance, and the arrival fact the policy decided on.
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, request, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { checkDoorConfig, isDoorConfig } from "../src/check.ts";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey, sha256Hex } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { isCommitment } from "../src/capture.ts";
import { AGENT_HEADER, ARRIVAL_FACT, CLASS_HEADER, RECEIPT_HEADER, cedarArgs, createDoorHost, createRateTracker, matchRoute, RATE_BURST_MS, RATE_MINUTE_MS, normalizePath, queryOf, remoteOf, serveDoor, verifyChallengeToken, MAX_CHALLENGE_TOKEN, type Arrival, type ChallengeCheck, type DoorHost, type RunningDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { LogSink } from "../src/log-sink.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin, type DoorFixture, type Origin } from "../scripts/door-fixture.ts";

let origin: Origin;
let fx: DoorFixture;
let host: DoorHost;
let door: RunningDoor;

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const receipt = (id: string | null) => JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle;
const verified = (bundle: ReceiptBundle) => verifyBundle(bundle, { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile });
const grantFor = (agent: string, scopes: string[], key = fx.principalKey, ttlMs = 3600_000) => createDelegation(key, { version: "0.1", principal: "shop-owner", agent, scopes, issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + ttlMs).toISOString() });
const call = async (method: string, path: string, init: { headers?: Record<string, string>; body?: unknown } = {}) => {
  const res = await fetch(`${door.url}${path}`, { method, headers: { ...(init.body !== undefined ? { "content-type": "application/json" } : {}), ...(init.headers ?? {}) }, ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}) });
  const text = await res.text();
  const id = res.headers.get(RECEIPT_HEADER);
  const bundle = receipt(id);
  const st = decode(bundle);
  return { res, text, id, bundle, st, p: st.predicate, arrival: st.predicate.facts[ARRIVAL_FACT]!.value as Arrival };
};

/** A local origin that answers each request the way `respond` says, for the failures the stand-in shop cannot produce. */
const rawOrigin = async (respond: (res: import("node:http").ServerResponse) => void): Promise<{ url: string; hits: () => number; close: () => Promise<void> }> => {
  let hits = 0;
  const server: Server = createServer((req, res) => {
    hits += 1;
    req.resume();
    respond(res);
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, hits: () => hits, close: () => { server.closeAllConnections(); return new Promise<void>((r) => server.close(() => r())); } };
};
/** A port nothing listens on: bound once and released. */
const closedPort = async (): Promise<number> => {
  const s = createServer();
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const { port } = s.address() as AddressInfo;
  await new Promise<void>((r) => s.close(() => r()));
  return port;
};
const bundleAt = (dir: string, res: Response) => JSON.parse(readFileSync(join(dir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;

beforeAll(async () => {
  origin = await startOrigin();
  fx = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-")), origin.url);
  host = await createDoorHost(loadDoorConfig(fx.configFile));
  door = await serveDoor(host, { port: 0, log: () => {} });
}, 60_000);

afterAll(async () => {
  await door?.close();
  await host?.close();
  await origin?.close();
});

describe("routes", () => {
  const routes = [{ name: "catalogue", methods: ["GET" as const], path: "/catalogue/*" }, { name: "refund", methods: ["POST" as const], path: "/refunds" }, { name: "api", path: "/api/*" }];
  it("the first matching route wins: exact, prefix, method, and the unmatched name otherwise", () => {
    expect(matchRoute(routes, "other", "GET", "/catalogue/shoes")).toBe("catalogue");
    expect(matchRoute(routes, "other", "GET", "/catalogue")).toBe("catalogue");
    expect(matchRoute(routes, "other", "POST", "/catalogue/shoes")).toBe("other");
    expect(matchRoute(routes, "other", "POST", "/refunds")).toBe("refund");
    expect(matchRoute(routes, "other", "POST", "/refunds/1")).toBe("other");
    expect(matchRoute(routes, "other", "DELETE", "/api/orders/1")).toBe("api");
    expect(matchRoute(routes, "other", "GET", "/")).toBe("other");
  });

  // An origin that merges slashes or ignores a trailing slash reads these as the paths beside them. If the door matched
  // them as something else, `//admin/users` would reach the admin page under the route for the rest of the site.
  it("empty segments are merged and a trailing slash matches as none, so the door and the origin read one path", () => {
    expect(normalizePath("//admin/users")).toEqual({ path: "/admin/users", relay: "/admin/users" });
    expect(normalizePath("/admin//users")).toEqual({ path: "/admin/users", relay: "/admin/users" });
    expect(normalizePath("/refunds/")).toEqual({ path: "/refunds/", relay: "/refunds/" });
    expect(normalizePath("//")).toEqual({ path: "/", relay: "/" });
    const site = [{ name: "admin", path: "/admin/*" }, { name: "site", path: "*" }];
    expect(matchRoute(site, "other", "GET", (normalizePath("//admin/users") as { path: string }).path)).toBe("admin");
    expect(matchRoute(site, "other", "GET", (normalizePath("/admin//x") as { path: string }).path)).toBe("admin");
    expect(matchRoute(site, "other", "GET", "/admin/")).toBe("admin");
    expect(matchRoute(routes, "other", "POST", "/refunds/")).toBe("refund");
    expect(matchRoute(routes, "other", "GET", "/catalogue/")).toBe("catalogue");
    expect(matchRoute(routes, "other", "GET", "/cataloguex")).toBe("other");
    expect(matchRoute([{ name: "root", path: "/*" }], "other", "GET", "/x")).toBe("root");
  });

  it("a query parameter named after an Object member is a parameter: no inherited value, no prototype change", () => {
    const q = queryOf(new URL("http://door/x?constructor=acme&toString=1&__proto__=x&hasOwnProperty=2&a=1&a=2"));
    expect(Object.getPrototypeOf(q)).toBe(Object.prototype);
    expect(Object.keys(q).sort()).toEqual(["__proto__", "a", "constructor", "hasOwnProperty", "toString"]);
    expect(q.constructor).toBe("acme");
    expect(Object.getOwnPropertyDescriptor(q, "__proto__")?.value).toBe("x");
    expect(q.a).toEqual(["1", "2"]);
  });

  it("the policy reads a copy of the arguments Cedar accepts: nulls dropped, numbers that are not safe integers as strings", () => {
    expect(cedarArgs({ a: null, b: 1.5, c: 7, d: [1, null, 2.5], e: { f: null, g: 12345678901234567890 } })).toEqual({ b: "1.5", c: 7, d: [1, "2.5"], e: { g: "12345678901234567000" } });
    const own = cedarArgs(JSON.parse('{"__proto__":{"x":1}}')) as Record<string, unknown>;
    expect(Object.getPrototypeOf(own)).toBe(Object.prototype);
    expect(Object.hasOwn(own, "__proto__")).toBe(true);
  });
});

describe("rate", () => {
  it("counts one source's arrivals in the last 10 and 60 seconds, this one included, and forgets what is older", () => {
    let t = 1_000_000;
    const tracker = createRateTracker(() => t);
    expect(tracker.hit("remote:1.2.3.4")).toEqual({ burst: 1, minute: 1 });
    t += 5_000;
    expect(tracker.hit("remote:1.2.3.4")).toEqual({ burst: 2, minute: 2 });
    expect(tracker.hit("remote:9.9.9.9")).toEqual({ burst: 1, minute: 1 });
    t += 6_000;
    expect(tracker.hit("remote:1.2.3.4")).toEqual({ burst: 2, minute: 3 });
    t += 55_000;
    expect(tracker.hit("remote:1.2.3.4")).toEqual({ burst: 1, minute: 2 });
    tracker.close();
  });

  it("bounds itself: a client choosing a new key on every request cannot grow the map, nor make a key of any length", () => {
    const t = 1_000_000;
    const tracker = createRateTracker(() => t, { maxSources: 3, maxKeyLength: 16 });
    try {
      for (let i = 0; i < 100; i++) tracker.hit(`remote:10.0.0.${i}`);
      expect(tracker.size()).toBe(3);
      // the least recently seen go first: a source still arriving keeps its count
      tracker.hit("remote:keep");
      tracker.hit("remote:a");
      tracker.hit("remote:b");
      expect(tracker.hit("remote:keep")).toEqual({ burst: 2, minute: 2 });
      tracker.hit("remote:c");
      expect(tracker.hit("remote:keep")).toEqual({ burst: 3, minute: 3 });
      // a key past the length limit is kept as its digest, and still counts as one source
      const long = `remote:${"x".repeat(10_000)}`;
      tracker.hit(long);
      expect(tracker.hit(long)).toEqual({ burst: 2, minute: 2 });
    } finally {
      tracker.close();
    }
  });

  it("an arrival exactly 10 s old is outside the burst window, and one exactly 60 s old outside the minute", () => {
    let t = 1_000_000;
    const tracker = createRateTracker(() => t);
    tracker.hit("remote:a");
    t += RATE_BURST_MS;
    expect(tracker.hit("remote:a")).toEqual({ burst: 1, minute: 2 });
    t += RATE_MINUTE_MS - RATE_BURST_MS;
    expect(tracker.hit("remote:a")).toEqual({ burst: 1, minute: 2 });
    t += 1;
    expect(tracker.hit("remote:a")).toEqual({ burst: 2, minute: 3 });
    tracker.close();
  });

  // One flooding address must not make each of its arrivals cost more than the last: the door counts before it reads
  // the body or asks the policy, on the event loop every other arrival shares.
  it("one arrival costs the same however many came before it in the window, and the counts stay exact", () => {
    let t = 1_000_000;
    const tracker = createRateTracker(() => t);
    const timed = (n: number) => {
      const start = performance.now();
      for (let i = 0; i < n; i++) {
        t += 0.5;
        tracker.hit("remote:flood");
      }
      return (performance.now() - start) / n;
    };
    const early = timed(20_000);
    const late = timed(200_000);
    // 2000 arrivals a second for 110 s: the minute holds 120 000 of them, the burst 20 000, and this one at the same instant
    expect(tracker.hit("remote:flood")).toEqual({ burst: 20_001, minute: 120_001 });
    expect(late).toBeLessThan(Math.max(early * 5, 0.01));
    tracker.close();
  });

  // A step of the wall clock (NTP, a VM resume) must not keep an hour-old burst inside the windows: a source that paused
  // would be refused for the length of the step.
  it("the default clock is monotonic: after the wall clock steps back an hour, a source that paused a minute counts from 1", () => {
    // the sweep's timer stays real, so the count below is the windows' and not the sweep's
    vi.useFakeTimers({ toFake: ["Date", "performance"] });
    const tracker = createRateTracker();
    try {
      for (let i = 0; i < 31; i++) tracker.hit("remote:paused");
      vi.advanceTimersByTime(RATE_MINUTE_MS + 1_000);
      vi.setSystemTime(Date.now() - 3600_000);
      expect(tracker.hit("remote:paused")).toEqual({ burst: 1, minute: 1 });
    } finally {
      tracker.close();
      vi.useRealTimers();
    }
    // an injected clock that goes back is held at the last time seen, so the windows never run backwards
    let t = 1_000_000;
    const held = createRateTracker(() => t);
    held.hit("remote:b");
    t -= 3600_000;
    expect(held.hit("remote:b")).toEqual({ burst: 2, minute: 2 });
    t = 1_000_000 + RATE_MINUTE_MS;
    expect(held.hit("remote:b")).toEqual({ burst: 1, minute: 1 });
    held.close();
  });

  it("the minute sweep keeps a source still arriving and drops the quiet ones, which then count from 1", () => {
    vi.useFakeTimers();
    try {
      const tracker = createRateTracker(() => Date.now());
      for (let i = 0; i < 1500; i++) tracker.hit(`remote:10.0.2.${i}`);
      tracker.hit("remote:active");
      // 40 s on, only the active source arrives; the sweep runs at 60 s, when its first arrival and the quiet ones are 60 s old
      vi.advanceTimersByTime(40_000);
      for (let i = 0; i < 3; i++) tracker.hit("remote:active");
      vi.advanceTimersByTime(30_000);
      expect(tracker.size()).toBe(1);
      expect(tracker.hit("remote:active")).toEqual({ burst: 1, minute: 4 });
      expect(tracker.hit("remote:10.0.2.7")).toEqual({ burst: 1, minute: 1 });
      tracker.close();
    } finally {
      vi.useRealTimers();
    }
  });

  it("drops a source with no arrival in the last minute even when no more traffic comes", () => {
    vi.useFakeTimers();
    try {
      const tracker = createRateTracker(() => Date.now());
      for (let i = 0; i < 50; i++) tracker.hit(`remote:10.0.1.${i}`);
      expect(tracker.size()).toBe(50);
      vi.advanceTimersByTime(2 * RATE_MINUTE_MS);
      expect(tracker.size()).toBe(0);
      tracker.close();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("the door", () => {
  it("a challenge token is verified with the provider and the outcome is a signal: absent refused with the way in, failed refused with the reason, passed relayed without the token, provider down recorded as unavailable", async () => {
    process.env.DOOR_TEST_TURNSTILE = "secret-1";
    const gated = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-challenge-")), origin.url, { challenge: { provider: "turnstile", siteKey: "site-1", secretEnv: "DOOR_TEST_TURNSTILE", hostnames: ["Shop.example"] } });
    writeFileSync(join(gated.dir, "policy.cedar"), 'permit(principal, action == Action::"refund", resource) when { context.facts.arrival.challenge.outcome == "passed" };\n');
    const asked: Array<Record<string, string>> = [];
    const stub: typeof fetch = async (input, init) => {
      const u = String(input instanceof Request ? input.url : input);
      if (!u.startsWith("https://challenges.cloudflare.com/")) return fetch(input, init);
      const form = Object.fromEntries(new URLSearchParams(String(init?.body)));
      asked.push(form);
      if (form.response === "down") throw new Error("ECONNREFUSED");
      return new Response(JSON.stringify(form.response === "good" ? { success: true, hostname: "shop.example" } : { success: false, "error-codes": ["invalid-input-response"] }), { headers: { "content-type": "application/json" } });
    };
    const h = await createDoorHost(loadDoorConfig(gated.configFile), { fetch: stub });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const post = (token?: string) => fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json", ...(token ? { "x-agent-custody-challenge": token } : {}) }, body: JSON.stringify({ order: "o-1", amount: 500 }) });
    const arrivalOf = (res: Response) => (decode(JSON.parse(readFileSync(join(gated.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle).predicate.facts[ARRIVAL_FACT]!.value as Arrival);
    try {
      const none = await post();
      expect(none.status).toBe(403);
      expect(await none.json()).toMatchObject({ challenge: { provider: "turnstile", siteKey: "site-1", header: "x-agent-custody-challenge" } });
      expect(arrivalOf(none)).toMatchObject({ class: "unknown", challenge: { provider: "turnstile", outcome: "absent" } });
      const bad = await post("bad");
      expect(bad.status).toBe(403);
      expect(arrivalOf(bad).challenge).toEqual({ provider: "turnstile", outcome: "failed", error: "invalid-input-response" });
      const seenBefore = origin.seen.length;
      const good = await post("good");
      expect(good.status).toBe(200);
      expect((await good.json()).ok).toBe(true);
      expect(arrivalOf(good)).toMatchObject({ class: "unknown", challenge: { provider: "turnstile", outcome: "passed" } });
      const relayed = origin.seen[seenBefore]!;
      expect(relayed.headers["x-agent-custody-challenge"]).toBeUndefined();
      const down = await post("down");
      expect(down.status).toBe(403);
      expect(arrivalOf(down).challenge).toMatchObject({ outcome: "unavailable", error: "ECONNREFUSED" });
      expect(asked.map((q) => q.response)).toEqual(["bad", "good", "down"]);
      expect(asked[0]).toMatchObject({ secret: "secret-1" });
      // without trustProxy the socket's address may be a proxy's: it is not sent as the client's
      expect(asked[0]!.remoteip).toBeUndefined();
    } finally {
      await d.close();
      await h.close();
    }
    try {
      expect(checkDoorConfig(gated.configFile).filter((f) => f.level === "error")).toEqual([]);
    } finally {
      delete process.env.DOOR_TEST_TURNSTILE;
    }
    expect(checkDoorConfig(gated.configFile).filter((f) => f.level === "error").map((f) => f.message)).toEqual([expect.stringContaining("DOOR_TEST_TURNSTILE")]);
    await expect(createDoorHost(loadDoorConfig(gated.configFile), { fetch: stub })).rejects.toThrow("DOOR_TEST_TURNSTILE");
  });

  // A policy treats `failed` as the arrival's fault and `unavailable` as the provider's. A rotated secret must not make
  // every person look like an attacker, and a flood of junk tokens must not reach the provider at all.
  it("each provider answer maps to the outcome it means: token faults fail, provider and secret faults are unavailable, and no answer is unavailable", async () => {
    let calls = 0;
    const signals: (AbortSignal | null | undefined)[] = [];
    const urls: string[] = [];
    const forms: URLSearchParams[] = [];
    const answers: Record<string, (signal?: AbortSignal | null) => Response | Promise<Response>> = {
      "invalid-input-response": () => Response.json({ success: false, "error-codes": ["invalid-input-response"] }),
      "timeout-or-duplicate": () => Response.json({ success: false, "error-codes": ["timeout-or-duplicate"] }),
      "already-seen-response": () => Response.json({ success: false, "error-codes": ["already-seen-response"] }),
      "invalid-input-secret": () => Response.json({ success: false, "error-codes": ["invalid-input-secret"] }),
      "internal-error": () => Response.json({ success: false, "error-codes": ["internal-error"] }),
      "sitekey-secret-mismatch": () => Response.json({ success: false, "error-codes": ["sitekey-secret-mismatch"] }),
      "no-codes": () => Response.json({ success: false }),
      "status-500": () => new Response("busy", { status: 500 }),
      "status-429": () => new Response("slow down", { status: 429 }),
      "not-json": () => new Response("<html>maintenance</html>", { status: 200, headers: { "content-type": "text/html" } }),
      "never": (signal) => new Promise<Response>((_r, reject) => signal?.addEventListener("abort", () => reject(signal.reason))),
      "hcaptcha-good": () => Response.json({ success: true, hostname: "shop.example" }),
    };
    const stub: typeof fetch = async (input, init) => {
      calls += 1;
      urls.push(String(input));
      signals.push(init?.signal);
      const form = new URLSearchParams(String(init?.body));
      forms.push(form);
      return answers[form.get("response")!]!(init?.signal);
    };
    const check = (token: string, provider: ChallengeCheck["provider"] = "turnstile") => verifyChallengeToken({ provider, secret: "s", token, hostnames: ["shop.example"], siteKey: "site-9", timeoutMs: 200 }, stub);
    for (const token of ["invalid-input-response", "timeout-or-duplicate", "already-seen-response", "no-codes"]) expect(await check(token)).toMatchObject({ outcome: "failed" });
    expect(await check("timeout-or-duplicate")).toEqual({ provider: "turnstile", outcome: "failed", error: "timeout-or-duplicate" });
    for (const token of ["invalid-input-secret", "internal-error", "sitekey-secret-mismatch"]) expect(await check(token)).toEqual({ provider: "turnstile", outcome: "unavailable", error: `the provider could not check the token: ${token}` });
    expect(await check("status-500")).toMatchObject({ outcome: "unavailable", error: "the provider answered 500" });
    expect(await check("status-429")).toMatchObject({ outcome: "unavailable", error: "the provider answered 429" });
    expect(await check("not-json")).toMatchObject({ outcome: "unavailable" });
    expect(await check("never")).toMatchObject({ outcome: "unavailable", error: expect.stringMatching(/timeout|aborted/i) });
    // every call carries its own timeout signal
    expect(signals.every((sig) => sig instanceof AbortSignal)).toBe(true);
    // Turnstile's secret is tied to one widget: no sitekey. hCaptcha's belongs to the account: the sitekey goes with it
    expect(forms.every((f) => !f.has("sitekey"))).toBe(true);
    expect(urls.every((u) => u === "https://challenges.cloudflare.com/turnstile/v0/siteverify")).toBe(true);
    expect(await check("hcaptcha-good", "hcaptcha")).toEqual({ provider: "hcaptcha", outcome: "passed" });
    expect(urls.at(-1)).toBe("https://api.hcaptcha.com/siteverify");
    expect(forms.at(-1)!.get("sitekey")).toBe("site-9");
    // a value no provider would issue is refused without a call
    const before = calls;
    expect(await check("x".repeat(MAX_CHALLENGE_TOKEN + 1))).toMatchObject({ outcome: "failed", error: expect.stringContaining(`longer than ${MAX_CHALLENGE_TOKEN}`) });
    expect(calls).toBe(before);
  });

  it("a passed challenge must come from one of the site's hostnames and its action, over a call that never follows a redirect", async () => {
    const answers: Record<string, () => Response> = {
      good: () => Response.json({ success: true, hostname: "shop.example", action: "refund" }),
      elsewhere: () => Response.json({ success: true, hostname: "evil.example", action: "refund" }),
      nohost: () => Response.json({ success: true, action: "refund" }),
      login: () => Response.json({ success: true, hostname: "shop.example", action: "login" }),
      redirect: () => new Response(null, { status: 307, headers: { location: "https://evil.example/collect" } }),
    };
    const seen: RequestInit[] = [];
    const stub: typeof fetch = async (_input, init) => { seen.push(init!); return answers[String(new URLSearchParams(String(init?.body)).get("response"))]!(); };
    const check = (token: string, extra: Partial<ChallengeCheck> = {}) => verifyChallengeToken({ provider: "turnstile", secret: "s", token, hostnames: ["shop.example"], action: "refund", timeoutMs: 1000, ...extra }, stub);
    expect(await check("good")).toEqual({ provider: "turnstile", outcome: "passed" });
    expect(await check("elsewhere")).toMatchObject({ outcome: "failed", error: expect.stringContaining("evil.example") });
    expect(await check("nohost")).toMatchObject({ outcome: "failed", error: expect.stringContaining("no hostname") });
    expect(await check("login")).toMatchObject({ outcome: "failed", error: expect.stringContaining("action login, not refund") });
    expect(await check("login", { action: undefined })).toMatchObject({ outcome: "passed" });
    // a 307 would resend the secret and the token to its Location: the call does not follow it, and the outcome is unavailable
    expect(await check("redirect")).toMatchObject({ outcome: "unavailable", error: expect.stringContaining("redirect (307)") });
    expect(seen.every((init) => init.redirect === "manual")).toBe(true);
    expect(new URLSearchParams(String(seen[0]!.body)).has("remoteip")).toBe(false);
    await check("good", { remoteIp: "203.0.113.9" });
    expect(new URLSearchParams(String(seen.at(-1)!.body)).get("remoteip")).toBe("203.0.113.9");
  });

  it("bounds the challenge checks waiting on the provider: past the limit an arrival is unavailable, never relayed", async () => {
    process.env.DOOR_TEST_TURNSTILE = "secret-1";
    const gated = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-inflight-")), origin.url, { trustProxy: true, challenge: { provider: "turnstile", siteKey: "site-1", secretEnv: "DOOR_TEST_TURNSTILE", hostnames: ["shop.example"], maxInFlight: 1 } });
    writeFileSync(join(gated.dir, "policy.cedar"), 'permit(principal, action == Action::"refund", resource) when { context.facts.arrival.challenge.outcome == "passed" };\n');
    let release!: () => void;
    const held = new Promise<void>((r) => { release = r; });
    let started!: () => void;
    const waiting = new Promise<void>((r) => { started = r; });
    const forms: URLSearchParams[] = [];
    const stub: typeof fetch = async (input, init) => {
      const u = String(input instanceof Request ? input.url : input);
      if (!u.startsWith("https://challenges.cloudflare.com/")) return fetch(input, init);
      forms.push(new URLSearchParams(String(init?.body)));
      started();
      await held;
      return Response.json({ success: true, hostname: "shop.example" });
    };
    const h = await createDoorHost(loadDoorConfig(gated.configFile), { fetch: stub });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const post = () => fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json", "x-agent-custody-challenge": "t", "x-forwarded-for": "198.51.100.7" }, body: JSON.stringify({ order: "o-1", amount: 500 }) });
    const arrivalOf = (res: Response) => (decode(JSON.parse(readFileSync(join(gated.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle).predicate.facts[ARRIVAL_FACT]!.value as Arrival);
    try {
      const first = post();
      await waiting;
      const second = await post();
      expect(second.status).toBe(403);
      expect(arrivalOf(second).challenge).toMatchObject({ outcome: "unavailable", error: expect.stringContaining("1 challenge checks") });
      release();
      expect((await first).status).toBe(200);
      expect(forms).toHaveLength(1);
      // with trustProxy the door knows the client's address, and the provider may check the token against it
      expect(forms[0]!.get("remoteip")).toBe("198.51.100.7");
    } finally {
      release();
      await d.close();
      await h.close();
      delete process.env.DOOR_TEST_TURNSTILE;
    }
  });

  it("every arrival carries its source's rate, by address for an unverified arrival and by agent for a verified one, and a policy can refuse on it", async () => {
    const paced = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-rate-")), origin.url);
    writeFileSync(join(paced.dir, "policy.cedar"), 'permit(principal, action, resource);\nforbid(principal, action, resource) when { context.facts.arrival.rate.burst > 2 };\n');
    const h = await createDoorHost(loadDoorConfig(paced.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const arrivalOf = (res: Response) => (decode(JSON.parse(readFileSync(join(paced.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle).predicate.facts[ARRIVAL_FACT]!.value as Arrival);
    try {
      const first = await fetch(`${d.url}/catalogue/shoes`);
      const second = await fetch(`${d.url}/catalogue/hats`);
      const third = await fetch(`${d.url}/admin`);
      expect([first.status, second.status, third.status]).toEqual([200, 200, 403]);
      expect(arrivalOf(first).rate).toEqual({ by: "remote", burst: 1, minute: 1 });
      expect(arrivalOf(second).rate).toEqual({ by: "remote", burst: 2, minute: 2 });
      expect(arrivalOf(third).rate).toEqual({ by: "remote", burst: 3, minute: 3 });
      expect(JSON.parse(await third.text()).reason).toBe("policy1");
      const agent = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["api"], paced.principalKey))}` } });
      expect(agent.status).toBe(200);
      expect(arrivalOf(agent)).toMatchObject({ class: "verified", rate: { by: "agent", burst: 1, minute: 1 } });
      // The count is keyed on the agent only when a grant verified. A declared name or a grant from an untrusted key
      // counts by address, so nobody can spend, or reset, a verified agent's count by naming it.
      const declared = await fetch(`${d.url}/catalogue/x`, { headers: { [AGENT_HEADER]: "crawler-9" } });
      const forged = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-9", ["api"], generateKeyPair()))}` } });
      expect(arrivalOf(declared).rate?.by).toBe("remote");
      expect(arrivalOf(forged).rate?.by).toBe("remote");
      const real = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-9", ["api"], paced.principalKey))}` } });
      expect(arrivalOf(real)).toMatchObject({ class: "verified", rate: { by: "agent", burst: 1, minute: 1 } });
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("an unknown arrival reads the catalogue: relayed, receipted as door/unknown with a claimed principal, and the receipt verifies", async () => {
    const r = await call("GET", "/catalogue/shoes?size=9&size=10&colour=red");
    expect(r.res.status).toBe(200);
    expect(r.res.headers.get(CLASS_HEADER)).toBe("unknown");
    expect(r.res.headers.get("x-origin")).toBe("shop");
    expect(JSON.parse(r.text)).toMatchObject({ ok: true, method: "GET", path: "/catalogue/shoes?size=9&size=10&colour=red" });
    expect(r.p.issuer).toMatchObject({ kind: "door", framework: "http" });
    expect(r.p.principal).toEqual({ id: null, provenance: "claimed" });
    expect(r.p.agent).toEqual({ id: "unknown", provenance: "claimed" });
    expect(r.p.delegation).toBeUndefined();
    expect(r.p.tool).toEqual({ name: "catalogue", provenance: "observed" });
    expect(r.p.request.args).toMatchObject({ method: "GET", path: "/catalogue/shoes", query: { size: ["9", "10"], colour: "red" }, bodyBytes: 0 });
    expect(r.arrival).toMatchObject({ class: "unknown", subject: "unknown", grant: "absent", signature: false, route: "catalogue" });
    expect(r.p.policy).toMatchObject({ decision: "allow", provenance: "observed" });
    expect(r.p.execution).toMatchObject({ status: "executed", provenance: "observed" });
    const v = verified(r.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toContain("door receipt carries a policy decision");
    expect(v.checks.map((c) => c.name)).toContain("principal is claimed, not attested");
    // what the origin saw: the arrival's address and the receipt id travel with the relayed request
    const seen = origin.seen.at(-1)!;
    expect(seen.headers[RECEIPT_HEADER]).toBe(r.id);
    expect(seen.headers[CLASS_HEADER]).toBe("unknown");
    expect(seen.headers["x-forwarded-for"]).toBe("127.0.0.1");
  });

  it("an unknown arrival asking for a refund is refused with 403 and a denied receipt that verifies; nothing reached the origin", async () => {
    const before = origin.seen.length;
    const r = await call("POST", "/refunds", { body: { order: "o_1", amount: 1000 } });
    expect(r.res.status).toBe(403);
    expect(JSON.parse(r.text)).toMatchObject({ error: "refused by the door's policy", receipt: r.id });
    expect(r.p.execution).toMatchObject({ status: "denied" });
    expect(r.p.request.args).toMatchObject({ body: { order: "o_1", amount: 1000 }, bodyDigest: sha256Hex(JSON.stringify({ order: "o_1", amount: 1000 })) });
    expect(verified(r.bundle).ok).toBe(true);
    expect(origin.seen.length).toBe(before);
  });

  it("a verified agent refunds within the policy: the grant is the passport, the principal and agent are attested, and the grant does not reach the origin", async () => {
    const grant = grantFor("shopping-agent", ["refund", "api"]);
    const r = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grant)}` }, body: { order: "o_2", amount: 4500 } });
    expect(r.res.status).toBe(200);
    expect(r.res.headers.get(CLASS_HEADER)).toBe("verified");
    expect(r.p.principal).toMatchObject({ id: "shop-owner", provenance: "attested" });
    expect(r.p.agent).toEqual({ id: "shopping-agent", provenance: "attested" });
    expect(r.p.delegation).toMatchObject({ provenance: "attested" });
    expect(r.arrival).toMatchObject({ class: "verified", subject: "shopping-agent", grant: "verified" });
    const v = verified(r.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toContain("delegation binds principal and agent");
    expect(v.checks.map((c) => c.name)).toContain("executed tool within delegated scope");
    expect(origin.seen.at(-1)!.headers.authorization).toBeUndefined();
    expect(JSON.parse(origin.seen.at(-1)!.body)).toEqual({ order: "o_2", amount: 4500 });
  });

  it("the same verified agent is refused above the limit, at zero, and below zero: a bound has two ends", async () => {
    const grant = grantFor("shopping-agent", ["refund"]);
    for (const amount of [9000, 0, -1, -5000]) {
      const r = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grant)}` }, body: { order: "o_3", amount } });
      expect(r.res.status, `amount ${amount}`).toBe(403);
      expect(r.arrival.class).toBe("verified");
      expect(r.p.execution).toMatchObject({ status: "denied" });
      expect(r.p.authorization).toBeUndefined();
      expect(verified(r.bundle).ok).toBe(true);
    }
  });

  it("a request that can change something is committed to the log before it is relayed; a read is not", async () => {
    const refund = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"]))}` }, body: { order: "o_7", amount: 100 } });
    expect(refund.res.status).toBe(200);
    expect(refund.p.authorization).toBeDefined();
    const v = verified(refund.bundle);
    expect(v.checks.filter((c) => !c.ok)).toEqual([]);
    expect(v.checks.map((c) => c.name)).toEqual(expect.arrayContaining(["authorization names this call", "authorization log inclusion proof", "authorization logged before execution"]));
    expect(refund.p.authorization!.inclusion.leafIndex).toBeLessThan(refund.bundle.inclusion.leafIndex);
    // the committed statement is on disk in its own right, as evidence should the receipt never be written
    const committed = JSON.parse(readFileSync(join(fx.receiptsDir, `${refund.id}.authorization.json`), "utf8")) as ReceiptBundle;
    expect(decode(committed).predicate.receiptId).toBe(refund.id);
    const read = await call("GET", "/catalogue/socks");
    expect(read.p.authorization).toBeUndefined();
  });

  it("a route named in precommit is committed whatever the method", async () => {
    const pre = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-precommit-")), origin.url, { precommit: ["catalogue"] });
    const h = await createDoorHost(loadDoorConfig(pre.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/socks`);
      expect(res.status).toBe(200);
      const bundle = JSON.parse(readFileSync(join(pre.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(bundle).predicate.authorization).toBeDefined();
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(pre.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("when the log will not commit the request, it is not relayed: 503 and a withheld receipt in the outbox; observe mode relays and says so", async () => {
    const refusing: LogSink = { kind: "file", where: "refusing", append: async () => { throw new Error("the log is full"); } };
    const dir = mkdtempSync(join(tmpdir(), "agent-custody-door-refused-"));
    const fxr = buildDoorFixture(dir, origin.url);
    const h = await createDoorHost(loadDoorConfig(fxr.configFile), { log: refusing });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const before = origin.seen.length;
    try {
      const res = await fetch(`${d.url}/refunds`, { method: "POST", headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], fxr.principalKey))}`, "content-type": "application/json" }, body: JSON.stringify({ order: "o_8", amount: 100 }) });
      expect(res.status).toBe(503);
      expect(res.headers.get("x-agent-custody-log-pending")).toBe("true");
      expect(origin.seen.length).toBe(before);
      const outbox = JSON.parse(readFileSync(join(fxr.receiptsDir, "outbox", `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as { envelope: ReceiptBundle["envelope"] };
      expect(decode({ envelope: outbox.envelope } as ReceiptBundle).predicate.execution).toMatchObject({ status: "withheld", reason: expect.stringContaining("the log did not commit") });
    } finally {
      await d.close();
      await h.close();
    }
    const errors: string[] = [];
    const quiet = console.error;
    console.error = (m: string) => { errors.push(String(m)); };
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-refused-observe-")), origin.url, { mode: "observe" });
    const ho = await createDoorHost(loadDoorConfig(obs.configFile), { log: refusing });
    const dobs = await serveDoor(ho, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${dobs.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_8b", amount: 100 }) });
      expect(res.status).toBe(200);
      expect(origin.seen.length).toBe(before + 1);
      expect(errors.some((e) => e.includes("observe mode") && e.includes("relayed without it"))).toBe(true);
    } finally {
      console.error = quiet;
      await dobs.close();
      await ho.close();
    }
  });

  it("a redirect to the origin's own address is rewritten to a path, so the client's next request passes the door too", async () => {
    const res = await fetch(`${door.url}/catalogue/redirect`, { redirect: "manual" });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe("/catalogue/after?from=redirect");
    expect(decode(receipt(res.headers.get(RECEIPT_HEADER))).predicate.execution).toMatchObject({ status: "executed", result: { status: 302 } });
  });

  it("a grant from a stranger, an expired grant, and a grant for other routes leave the arrival claimed and refused, with the reason in the arrival fact", async () => {
    const stranger = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], generateKeyPair()))}` }, body: { order: "o_4", amount: 100 } });
    expect(stranger.res.status).toBe(403);
    expect(stranger.arrival).toMatchObject({ class: "claimed", subject: "shopping-agent", grant: "invalid" });
    expect(stranger.p.principal).toEqual({ id: null, provenance: "claimed" });
    expect(stranger.p.agent).toEqual({ id: "shopping-agent", provenance: "claimed" });
    expect(verified(stranger.bundle).ok).toBe(true);

    const expired = await call("POST", "/refunds", { headers: { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["refund"], fx.principalKey, -1))}` }, body: { order: "o_5", amount: 100 } });
    expect(expired.arrival).toMatchObject({ class: "claimed", grant: "invalid" });
    expect(expired.arrival.grantError).toMatch(/window/);

    const elsewhere = await call("POST", "/refunds", { headers: { [`x-agent-custody-grant`]: grantHeader(grantFor("read-agent", ["api"])) }, body: { order: "o_6", amount: 100 } });
    expect(elsewhere.res.status).toBe(403);
    expect(elsewhere.arrival).toMatchObject({ class: "claimed", subject: "read-agent", grant: "out-of-scope" });
    expect(elsewhere.p.delegation).toBeUndefined();
    expect(verified(elsewhere.bundle).ok).toBe(true);
  });

  it("a declared name without a grant is claimed: it may read the catalogue and is refused the API", async () => {
    const read = await call("GET", "/catalogue/hats", { headers: { [AGENT_HEADER]: "crawler-7" } });
    expect(read.res.status).toBe(200);
    expect(read.arrival).toMatchObject({ class: "claimed", subject: "crawler-7", declared: "crawler-7", grant: "absent" });
    expect(read.p.agent).toEqual({ id: "crawler-7", provenance: "claimed" });
    const api = await call("GET", "/api/orders", { headers: { [AGENT_HEADER]: "crawler-7" } });
    expect(api.res.status).toBe(403);
    expect(verified(api.bundle).ok).toBe(true);
  });

  it("a permit that names an agent is satisfied by that agent's verified grant alone, never by a declared name or a rejected grant; `check` warns about the permit", async () => {
    const named = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-named-")), origin.url);
    writeFileSync(join(named.dir, "policy.cedar"), 'permit(principal == Agent::"crawler-7", action == Action::"api", resource);\n');
    const h = await createDoorHost(loadDoorConfig(named.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const declared = await fetch(`${d.url}/api/orders`, { headers: { [AGENT_HEADER]: "crawler-7" } });
      expect(declared.status).toBe(403);
      const forged = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["api"], generateKeyPair()))}` } });
      expect(forged.status).toBe(403);
      const elsewhere = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["refund"], named.principalKey))}` } });
      expect(elsewhere.status).toBe(403);
      const real = await fetch(`${d.url}/api/orders`, { headers: { authorization: `Bearer ${grantHeader(grantFor("crawler-7", ["api"], named.principalKey))}` } });
      expect(real.status).toBe(200);
    } finally {
      await d.close();
      await h.close();
    }
    const warnings = checkDoorConfig(named.configFile).filter((f) => f.level === "warn" && f.check === "policy").map((f) => f.message);
    expect(warnings.some((m) => m.includes('Agent::"crawler-7"') && m.includes('arrival.class == "verified"'))).toBe(true);
    expect(checkDoorConfig(fx.configFile).filter((f) => f.level === "warn" && f.check === "policy")).toEqual([]);
  });

  it("an arrival at no configured route is the unmatched action and the policy refuses it", async () => {
    const r = await call("GET", "/admin");
    expect(r.res.status).toBe(403);
    expect(r.p.tool.name).toBe("other");
  });

  it("the origin answering 500 is a failed receipt; the status is relayed", async () => {
    const r = await call("GET", "/api/broken", { headers: { authorization: `Bearer ${grantHeader(grantFor("ops-agent", ["api"]))}` } });
    expect(r.res.status).toBe(500);
    expect(r.p.execution).toMatchObject({ status: "failed", result: { status: 500 } });
    expect(verified(r.bundle).ok).toBe(true);
  });

  it("the policy decides before the body limit: an oversized body on a refused route is denied, on an allowed route it is withheld with 413, and both receipts verify", async () => {
    const small = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-small-")), origin.url, { maxBodyBytes: 64 });
    const h = await createDoorHost(loadDoorConfig(small.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const check = (bundle: ReceiptBundle) => verifyBundle(bundle, { issuerKeys: [loadPublicKey(small.doorPub)], principalKeys: [loadPublicKey(small.principalPub)], logFile: small.logFile });
    const before = origin.seen.length;
    try {
      const big = JSON.stringify({ pad: "x".repeat(200) });
      const refused = await fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: big });
      expect(refused.status).toBe(403);
      const denied = JSON.parse(readFileSync(join(small.receiptsDir, `${refused.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(denied).predicate.execution).toMatchObject({ status: "denied" });
      expect(decode(denied).predicate.request.args).toMatchObject({ bodyOversized: true });
      expect(decode(denied).predicate.request.args).not.toHaveProperty("bodyDigest");
      expect(check(denied).checks.filter((c) => !c.ok)).toEqual([]);

      const grant = grantHeader(grantFor("ops-agent", ["api"], small.principalKey));
      const allowed = await fetch(`${d.url}/api/orders`, { method: "POST", headers: { "content-type": "application/json", authorization: `Bearer ${grant}` }, body: big });
      expect(allowed.status).toBe(413);
      const withheld = JSON.parse(readFileSync(join(small.receiptsDir, `${allowed.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(withheld).predicate.policy).toMatchObject({ decision: "allow" });
      expect(decode(withheld).predicate.execution).toMatchObject({ status: "withheld" });
      expect(decode(withheld).predicate.authorization).toBeUndefined();
      expect(check(withheld).checks.filter((c) => !c.ok)).toEqual([]);
      expect(origin.seen.length).toBe(before);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("the origin down is an error receipt and a 502 that says it could not be reached", async () => {
    const url = `http://127.0.0.1:${await closedPort()}`;
    const dead = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-dead-")), url, { origin: { url, timeoutMs: 2000 } });
    const h = await createDoorHost(loadDoorConfig(dead.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/x`);
      expect(res.status).toBe(502);
      expect(await res.json()).toMatchObject({ error: "the origin could not be reached" });
      const bundle = JSON.parse(readFileSync(join(dead.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(bundle).predicate.execution).toMatchObject({ status: "error", error: expect.stringContaining("could not be reached") });
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(dead.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("observe mode relays what the policy would refuse and marks the decision unenforced", async () => {
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-observe-")), origin.url, { mode: "observe" });
    const h = await createDoorHost(loadDoorConfig(obs.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_9", amount: 100 }) });
      expect(res.status).toBe(200);
      const bundle = JSON.parse(readFileSync(join(obs.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      const p = decode(bundle).predicate;
      expect(p.policy).toMatchObject({ decision: "deny", enforced: false });
      expect(p.execution.status).toBe("executed");
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(obs.doorPub)], principalKeys: [] }).ok).toBe(true);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("a policy change on disk applies to the next arrival; one that does not parse is refused and the policy in force stays", async () => {
    const before = host.policyDigest();
    const policyFile = join(fx.dir, "policy.cedar");
    const original = readFileSync(policyFile, "utf8");
    writeFileSync(policyFile, "permit(principal, action == Action::\"other\", resource);\n");
    const opened = await call("GET", "/admin");
    expect(opened.res.status).toBe(200);
    expect(host.policyDigest()).not.toBe(before);
    writeFileSync(policyFile, "permit(principal, action == Action::\"other\" resource;\n");
    const still = await call("GET", "/admin");
    expect(still.res.status).toBe(200);
    writeFileSync(policyFile, original);
    const closed = await call("GET", "/admin");
    expect(closed.res.status).toBe(403);
    expect(host.policyDigest()).toBe(before);
  });

  it("`check` recognises a door config and reports what the door would fail on", () => {
    expect(isDoorConfig(fx.configFile)).toBe(true);
    const good = checkDoorConfig(fx.configFile);
    expect(good.filter((f) => f.level === "error")).toEqual([]);
    expect(good.map((f) => f.check)).toEqual(expect.arrayContaining(["config", "key", "principal keys", "policy", "routes", "origin", "paths"]));
    const broken = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-check-")), origin.url, { routs: [], trustedPrincipalKeys: [], origin: { url: "http://shop.example", headerEnv: { "x-secret": "DOOR_TEST_UNSET_VARIABLE" } }, splunk: { url: "https://splunk.example:8088", tokenEnv: "DOOR_TEST_UNSET_SPLUNK" }, otel: { url: "https://otel.example", headersEnv: { authorization: "DOOR_TEST_UNSET_OTEL" } } });
    writeFileSync(join(broken.dir, "policy.cedar"), "permit(principal, action, resource");
    const findings = checkDoorConfig(broken.configFile);
    const messages = findings.filter((f) => f.level === "error").map((f) => `${f.check}: ${f.message}`);
    expect(messages.some((m) => m.startsWith("config: unknown key \"routs\"") && m.includes("routes"))).toBe(true);
    expect(messages.some((m) => m.startsWith("policy:"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_VARIABLE"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_SPLUNK"))).toBe(true);
    expect(messages.some((m) => m.startsWith("credentials:") && m.includes("DOOR_TEST_UNSET_OTEL"))).toBe(true);
    expect(good.map((f) => f.check)).toContain("precommit");
    expect(findings.filter((f) => f.level === "warn").map((f) => f.check)).toEqual(expect.arrayContaining(["principal keys", "origin"]));
  });

  // The request may have left: a client told "could not be reached" retries, and a refund the origin booked runs twice.
  it("a timeout or a body that stops after the headers is an unknown outcome: 504, do not retry, and the receipt says the origin may have acted", async () => {
    const stalls = await rawOrigin((res) => { res.writeHead(200, { "content-type": "text/plain" }); res.write("partial"); });
    const silent = await rawOrigin(() => {});
    try {
      for (const o of [stalls, silent]) {
        const f = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-stall-")), o.url, { origin: { url: o.url, timeoutMs: 300 } });
        const h = await createDoorHost(loadDoorConfig(f.configFile));
        const d = await serveDoor(h, { port: 0, log: () => {} });
        try {
          const res = await fetch(`${d.url}/catalogue/x`);
          expect(res.status).toBe(504);
          expect(await res.json()).toMatchObject({ error: expect.stringContaining("may have acted on the request") });
          const p = decode(bundleAt(f.receiptsDir, res)).predicate;
          expect(p.execution).toMatchObject({ status: "error", error: expect.stringContaining("the origin may have acted on the request") });
          expect(p.execution).not.toMatchObject({ error: expect.stringContaining("could not be reached") });
          expect(o.hits()).toBe(1);
        } finally {
          await d.close();
          await h.close();
        }
      }
    } finally {
      await stalls.close();
      await silent.close();
    }
  });

  it("past maxInFlight the next arrival is answered 503 before its body is read, with no receipt; the slot frees when the first is answered", async () => {
    let release: () => void = () => {};
    const held = new Promise<void>((r) => { release = r; });
    const slow = await rawOrigin((res) => { void held.then(() => res.end("ok")); });
    const f = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-busy-")), slow.url, { origin: { url: slow.url }, maxInFlight: 1 });
    const h = await createDoorHost(loadDoorConfig(f.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const first = fetch(`${d.url}/catalogue/a`);
      while (slow.hits() === 0) await new Promise((r) => setTimeout(r, 10));
      const busy = await fetch(`${d.url}/catalogue/b`);
      expect(busy.status).toBe(503);
      expect(busy.headers.get("retry-after")).toBe("1");
      expect(busy.headers.get(RECEIPT_HEADER)).toBeNull();
      expect(slow.hits()).toBe(1);
      release();
      expect((await first).status).toBe(200);
      expect((await fetch(`${d.url}/catalogue/c`)).status).toBe(200);
    } finally {
      release();
      await d.close();
      await h.close();
      await slow.close();
    }
  });

  it("the defaults bound what an arrival holds: a 1 MiB body, a 32 MiB response, 256 at once", () => {
    const cfg = loadDoorConfig(fx.configFile);
    expect([cfg.maxBodyBytes, cfg.maxResponseBytes, cfg.maxInFlight]).toEqual([1024 * 1024, 32 * 1024 * 1024, 256]);
  });

  it("an arrival at `//api/orders` falls under the API route and the origin is sent `/api/orders`; `/catalogue//shoes/` under the catalogue", async () => {
    const api = await call("GET", "//api/orders");
    expect(api.p.tool.name).toBe("api");
    expect(api.res.status).toBe(403);
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-merge-")), origin.url, { mode: "observe" });
    const h = await createDoorHost(loadDoorConfig(obs.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}//api//orders`);
      expect(decode(bundleAt(obs.receiptsDir, res)).predicate.tool.name).toBe("api");
      expect(origin.seen.at(-1)?.path).toBe("/api/orders");
      const shoes = await fetch(`${d.url}/catalogue//shoes/`);
      expect(decode(bundleAt(obs.receiptsDir, shoes)).predicate.tool.name).toBe("catalogue");
      expect(origin.seen.at(-1)?.path).toBe("/catalogue/shoes/");
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("a parameter named `constructor` or `__proto__` is recorded and decided as a parameter: a permitted read stays permitted", async () => {
    const r = await call("GET", "/catalogue/shoes?constructor=acme&__proto__=x&toString=1");
    expect(r.res.status).toBe(200);
    expect(r.p.policy).toMatchObject({ decision: "allow", errors: [] });
    expect(r.p.request.args).toMatchObject({ query: { constructor: "acme", toString: "1" } });
    expect(Object.getOwnPropertyDescriptor((r.p.request.args as { query: object }).query, "__proto__")?.value).toBe("x");
    expect(origin.seen.at(-1)?.path).toBe("/catalogue/shoes?constructor=acme&__proto__=x&toString=1");
  });

  it("a body with a null or a non-integer number is decided by the policy, not refused by Cedar; the receipt keeps the body as sent", async () => {
    const passport = { authorization: `Bearer ${grantHeader(grantFor("shopping-agent", ["api", "refund"]))}` };
    const order = { order: "o_9", coupon: null, price: 9.99, big: 1.5e300 };
    const r = await call("POST", "/api/orders", { headers: passport, body: order });
    expect(r.res.status).toBe(200);
    expect(r.p.policy).toMatchObject({ decision: "allow", errors: [] });
    expect(r.p.request.args).toMatchObject({ body: order });
    // a rule that compares a non-integer as a number errors, and that rule's deny is the answer
    const half = await call("POST", "/refunds", { headers: passport, body: { order: "o_10", amount: 45.5 } });
    expect(half.res.status).toBe(403);
    const errors = JSON.stringify(half.p.policy?.errors);
    expect(errors).not.toContain("null");
    expect(errors).not.toContain("RawCedarValueJson");
  });

  it("the path cannot move the relay: `/.//host/x` reaches the origin as a path and the other host hears nothing", async () => {
    const other = await startOrigin();
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-escape-")), origin.url, { mode: "observe", origin: { url: origin.url, headers: { "x-door-secret": "s3cret" } } });
    const h = await createDoorHost(loadDoorConfig(obs.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const before = origin.seen.length;
    try {
      const evil = other.url.replace("http://", "");
      const res = await fetch(`${d.url}/.//${evil}/steal`, { headers: { cookie: "session=1" } });
      expect(res.status).toBe(200);
      expect(other.seen).toEqual([]);
      expect(origin.seen.length).toBe(before + 1);
      expect(origin.seen.at(-1)).toMatchObject({ path: `/${evil}/steal`, headers: { "x-door-secret": "s3cret", cookie: "session=1" } });
      expect(decode(JSON.parse(readFileSync(join(obs.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle).predicate.request.args).toMatchObject({ path: `/${evil}/steal` });
    } finally {
      await d.close();
      await h.close();
      await other.close();
    }
  });

  it("an origin with a path keeps it: the arrival's path goes under it, and a redirect under it comes back as a door path", async () => {
    const based = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-based-")), `${origin.url}/api/v1/`);
    const targets: string[] = [];
    const stub: typeof fetch = async (input) => {
      targets.push(String(input));
      return new Response("{}", { status: 302, headers: { location: `${origin.url}/api/v1/catalogue/after?x=1`, "content-type": "application/json" } });
    };
    const h = await createDoorHost(loadDoorConfig(based.configFile), { fetch: stub });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/shoes?size=9`, { redirect: "manual" });
      expect(res.status).toBe(302);
      expect(targets).toEqual([`${origin.url}/api/v1/catalogue/shoes?size=9`]);
      expect(res.headers.get("location")).toBe("/catalogue/after?x=1");
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("every redirect to the origin's host becomes a door path, so the client never follows it around the door", async () => {
    const based = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-escape-")), `${origin.url}/api/v1/`);
    const host = new URL(origin.url);
    let location = "";
    const stub: typeof fetch = async () => new Response("{}", { status: 302, headers: { location, "content-type": "application/json" } });
    const h = await createDoorHost(loadDoorConfig(based.configFile), { fetch: stub });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const cases: [string, string][] = [
        // outside the origin's path: before, left absolute, and the browser went straight to the origin
        [`${origin.url}/admin`, "/admin"],
        // normalised out of the prefix by the URL parser
        [`${origin.url}/api/v1/../../admin?x=1`, "/admin?x=1"],
        // the same host on another scheme or port
        [`https://${host.hostname}:1/api/v1/x`, "/x"],
        // relative forms resolve against the origin, then come back as door paths
        ["/admin", "/admin"],
        ["after", "/catalogue/after"],
        // another host is not the origin: relayed as sent
        ["https://elsewhere.example/x", "https://elsewhere.example/x"],
      ];
      for (const [sent, want] of cases) {
        location = sent;
        const res = await fetch(`${d.url}/catalogue/shoes`, { redirect: "manual" });
        expect(res.headers.get("location"), sent).toBe(want);
      }
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("a route is matched on the decoded path and the origin is sent that form; a path that decodes to a slash or a dot segment is refused with 400 and a withheld receipt", async () => {
    expect(normalizePath("/%61dmin/x")).toEqual({ path: "/admin/x", relay: "/admin/x" });
    expect(normalizePath("/a%20b/%25")).toEqual({ path: "/a b/%", relay: "/a%20b/%25" });
    expect(normalizePath("/host:8/a@b/c=d&e+f")).toEqual({ path: "/host:8/a@b/c=d&e+f", relay: "/host:8/a@b/c=d&e+f" });
    expect(normalizePath("/a%2fb")).toMatchObject({ problem: expect.stringContaining("slash") });
    expect(normalizePath("/a%5cb")).toMatchObject({ problem: expect.stringContaining("slash") });
    expect(normalizePath("/%2e%2e/x")).toMatchObject({ problem: expect.stringContaining("dot segment") });
    expect(normalizePath("/%zz")).toMatchObject({ problem: expect.stringContaining("does not percent-decode") });

    const before = origin.seen.length;
    const refund = await call("POST", "/%72efunds", { body: { amount: 100 } });
    expect(refund.res.status).toBe(403);
    expect(refund.p.tool.name).toBe("refund");
    expect(refund.arrival.path).toBe("/refunds");
    expect(origin.seen.length).toBe(before);

    const read = await call("GET", "/%63atalogue/sh%6fes");
    expect(read.res.status).toBe(200);
    expect(read.p.tool.name).toBe("catalogue");
    expect(read.p.request.args).toMatchObject({ path: "/catalogue/shoes" });
    expect(origin.seen.at(-1)?.path).toBe("/catalogue/shoes");

    // the URL parser resolves `%2e%2e` as a dot segment before the door sees it: the route is the one for /admin
    const dotted = await call("GET", "/catalogue/%2e%2e/admin");
    expect(dotted.res.status).toBe(403);
    expect(dotted.p.tool.name).toBe("other");
    expect(dotted.arrival.path).toBe("/admin");
    // a path that does not decode cleanly falls under the unmatched route, and the policy decides first: refused here
    const bad = await call("GET", "/catalogue/a%2fb");
    expect(bad.res.status).toBe(403);
    expect(bad.p.tool.name).toBe("other");
    expect(origin.seen.at(-1)?.path).toBe("/catalogue/shoes");

    // where the policy would relay it, it is withheld with 400
    const obs = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-malformed-")), origin.url, { mode: "observe" });
    const h = await createDoorHost(loadDoorConfig(obs.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      for (const path of ["/catalogue/a%2fb", "/catalogue/%zz", "/a%5cb"]) {
        const res = await fetch(`${d.url}${path}`);
        expect(res.status).toBe(400);
        const bundle = JSON.parse(readFileSync(join(obs.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
        expect(decode(bundle).predicate.execution).toMatchObject({ status: "withheld", reason: expect.stringContaining("the path was not relayed") });
        expect(decode(bundle).predicate.tool.name).toBe("other");
        expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(obs.doorPub)], principalKeys: [loadPublicKey(obs.principalPub)], logFile: obs.logFile }).checks.filter((c) => !c.ok)).toEqual([]);
      }
      expect(origin.seen.at(-1)?.path).toBe("/catalogue/shoes");
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("every cookie the origin sets reaches the client", async () => {
    const res = await fetch(`${door.url}/catalogue/cookies`);
    expect(res.status).toBe(200);
    expect(res.headers.getSetCookie()).toEqual(["session=1; HttpOnly", "csrf=2"]);
  });

  it("a request with `Expect: 100-continue` is relayed; the door answers the expectation itself", async () => {
    const grant = grantHeader(grantFor("ops-agent", ["api"]));
    const body = JSON.stringify({ order: 1 });
    const { port } = new URL(door.url);
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({ host: "127.0.0.1", port, method: "POST", path: "/api/orders", headers: { expect: "100-continue", "content-type": "application/json", "content-length": Buffer.byteLength(body), authorization: `Bearer ${grant}` } }, (res) => { res.resume(); res.on("end", () => resolve(res.statusCode ?? 0)); });
      req.on("continue", () => req.end(body));
      req.on("error", reject);
    });
    expect(status).toBe(200);
    expect(origin.seen.at(-1)).toMatchObject({ path: "/api/orders", body });
    expect(origin.seen.at(-1)?.headers).not.toHaveProperty("expect");
  });

  it("with trustProxy the arrival's address is the last one the proxy appended, and the proxy's chain and scheme are kept on the relay; without it the client's headers are replaced", async () => {
    const headers = { "x-forwarded-for": "6.6.6.6, 203.0.113.9", "x-forwarded-proto": "https", "x-forwarded-host": "shop.example" };
    // an origin that reads the client's address from any of these would otherwise trust what the client wrote
    const spoofed = { forwarded: "for=10.0.0.5", "x-real-ip": "10.0.0.5", "true-client-ip": "10.0.0.5", "cf-connecting-ip": "10.0.0.5", "x-forwarded-port": "443", "x-forwarded-prefix": "/admin" };
    const direct = await call("GET", "/catalogue/x", { headers: { ...headers, ...spoofed } });
    expect(direct.arrival.remote).toBe("127.0.0.1");
    const seenDirect = origin.seen.at(-1)!.headers;
    expect(seenDirect).toMatchObject({ "x-forwarded-for": "127.0.0.1", "x-forwarded-proto": "http", "x-forwarded-host": `127.0.0.1:${new URL(door.url).port}`, "x-real-ip": "127.0.0.1" });
    for (const name of ["forwarded", "true-client-ip", "cf-connecting-ip", "x-forwarded-port", "x-forwarded-prefix"]) expect(seenDirect[name]).toBeUndefined();

    const behind = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-proxied-")), origin.url, { trustProxy: true });
    const h = await createDoorHost(loadDoorConfig(behind.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/x`, { headers: { ...headers, ...spoofed } });
      const arrival = decode(JSON.parse(readFileSync(join(behind.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle).predicate.facts[ARRIVAL_FACT]!.value as Arrival;
      expect(arrival.remote).toBe("203.0.113.9");
      // behind the proxy you run, these are that proxy's to set, and they are relayed as it sent them
      expect(origin.seen.at(-1)?.headers).toMatchObject({ "x-forwarded-for": "6.6.6.6, 203.0.113.9, 127.0.0.1", "x-forwarded-proto": "https", "x-forwarded-host": "shop.example", ...spoofed });
    } finally {
      await d.close();
      await h.close();
    }
    expect(remoteOf({ headers: { "x-forwarded-for": ["1.1.1.1", "2.2.2.2 , 3.3.3.3"] }, socket: { remoteAddress: "127.0.0.1" } } as never, true)).toBe("3.3.3.3");
    expect(remoteOf({ headers: { "x-forwarded-for": "" }, socket: { remoteAddress: "127.0.0.1" } } as never, true)).toBe("127.0.0.1");
  });

  it("a response larger than the limit is not held or relayed: the client gets 502, the receipt records that the origin answered, by size", async () => {
    let pulled = 0;
    const chunk = new Uint8Array(1024 * 1024);
    const stub: typeof fetch = async () => new Response(new ReadableStream({ pull(c) { pulled += 1; c.enqueue(chunk); } }), { status: 200, headers: { "content-type": "application/octet-stream" } });
    const big = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-big-")), origin.url);
    const h = await createDoorHost(loadDoorConfig(big.configFile), { fetch: stub });
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const res = await fetch(`${d.url}/catalogue/huge`);
      expect(res.status).toBe(502);
      expect(await res.json()).toMatchObject({ error: expect.stringContaining("Do not retry") });
      expect(pulled).toBeLessThan(40);
      const bundle = JSON.parse(readFileSync(join(big.receiptsDir, `${res.headers.get(RECEIPT_HEADER)}.json`), "utf8")) as ReceiptBundle;
      expect(decode(bundle).predicate.execution).toMatchObject({ status: "executed", result: { status: 200, bodyOversized: true, bodyBytes: 33 * 1024 * 1024 } });
      expect(decode(bundle).predicate.execution).not.toHaveProperty("result.bodyDigest");
      expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(big.doorPub)], principalKeys: [loadPublicKey(big.principalPub)], logFile: big.logFile }).checks.filter((c) => !c.ok)).toEqual([]);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("when the receipt cannot be written after the origin acted, the client is told that, with the receipt id, not that nothing was relayed", async () => {
    const stuck = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-stuck-")), origin.url);
    const h = await createDoorHost(loadDoorConfig(stuck.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    const errors: string[] = [];
    const stderr = console.error;
    console.error = (m: string) => { errors.push(m); };
    chmodSync(stuck.receiptsDir, 0o500);
    try {
      const res = await fetch(`${d.url}/catalogue/x`);
      expect(res.status).toBe(500);
      expect(await res.json()).toMatchObject({ error: "the door could not record this request", outcome: expect.stringContaining("the origin acted on the request"), receipt: res.headers.get(RECEIPT_HEADER) });
      expect(origin.seen.at(-1)?.path).toBe("/catalogue/x");
      expect(errors.some((m) => m.includes("was not written"))).toBe(true);
    } finally {
      chmodSync(stuck.receiptsDir, 0o700);
      console.error = stderr;
      await d.close();
      await h.close();
    }
  });

  // A query can carry an API key and a form body a password. A config that sets no rule still keeps them out of the
  // receipt file and the log, and the receipt still verifies.
  it("without a capture rule the receipt withholds the query and the body, keeps the method, path, headers, and size in clear, and verifies", async () => {
    const secret = `sk_live_${Date.now()}`;
    const plain = buildDoorFixture(mkdtempSync(join(tmpdir(), "agent-custody-door-default-capture-")), origin.url, { capture: undefined });
    const h = await createDoorHost(loadDoorConfig(plain.configFile));
    const d = await serveDoor(h, { port: 0, log: () => {} });
    try {
      const read = await fetch(`${d.url}/catalogue/shoes?api_key=${secret}`);
      expect(read.status).toBe(200);
      const login = await fetch(`${d.url}/api/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email: "a@b.c", password: secret }) });
      expect(login.status).toBe(403);
      for (const res of [read, login]) {
        const bundle = bundleAt(plain.receiptsDir, res);
        const args = decode(bundle).predicate.request.args as Record<string, unknown>;
        expect(args).toMatchObject({ method: expect.any(String), path: expect.any(String), headers: expect.any(Object), bodyBytes: expect.any(Number) });
        // the withheld fields leave one salted commitment, `$rest`, in their place
        expect(args.query).toBeUndefined();
        expect(args.body).toBeUndefined();
        expect(isCommitment(args.$rest)).toBe(true);
        expect(JSON.stringify(bundle)).not.toContain(secret);
        expect(Buffer.from(bundle.envelope.payload, "base64").toString()).not.toContain(secret);
        expect(verifyBundle(bundle, { issuerKeys: [loadPublicKey(plain.doorPub)], principalKeys: [loadPublicKey(plain.principalPub)], logFile: plain.logFile }).checks.filter((c) => !c.ok)).toEqual([]);
      }
      expect(readFileSync(plain.logFile, "utf8")).not.toContain(secret);
    } finally {
      await d.close();
      await h.close();
    }
  });

  it("the well-known endpoint names the key and the policy", async () => {
    const res = await fetch(`${door.url}/.well-known/agent-custody-door`);
    expect(await res.json()).toMatchObject({ keyid: host.keyid, policyDigest: host.policyDigest() });
  });
});
