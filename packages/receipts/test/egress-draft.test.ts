// `egress draft-policy` turns observe-mode receipts into a first allow list. What matters: it permits only what a
// verified agent was actually relayed to, for that agent alone; a receipt that does not verify adds nothing, since
// anyone could have written it; and the output says it must be reviewed, because it permits bad destinations too.
// The draft is run by a real witness in enforce mode, so the test fails if the text stops meaning what it claims.
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { createServer as createHttpServer, request as httpRequest, type Server } from "node:http";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { loadEgressConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import { DRAFT_WARNING, draftEgressPolicy, type EgressPolicyDraft } from "../src/egress-draft.ts";
import { createEgressHost, serveEgress } from "../src/egress.ts";
import { policyParseErrors } from "../src/policy.ts";
import type { ReceiptBundle } from "../src/receipt.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho, type EchoServer, type EgressFixture } from "../scripts/egress-fixture.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const BUILD = "build-agent";
const BUILD_SECRET_ENV = "EGRESS_DRAFT_TEST_BUILD_SECRET";
const BUILD_SECRET = "draft-test-secret-not-a-real-credential";
const research = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);
const build = proxyAuth(BUILD, BUILD_SECRET);

async function witness(dir: string, extra: Record<string, unknown>, policy: string) {
  process.env[BUILD_SECRET_ENV] = BUILD_SECRET;
  const fx = buildEgressFixture(dir, { agents: [{ id: EGRESS_AGENT, secretEnv: "EGRESS_FIXTURE_RESEARCH_SECRET" }, { id: BUILD, secretEnv: BUILD_SECRET_ENV }], ...extra }, policy);
  const host = await createEgressHost(loadEgressConfig(fx.configFile));
  const running = await serveEgress(host, { port: 0, log: () => {} });
  return { fx, port: Number(new URL(running.url).port), async stop() { await host.close(); await running.close(); } };
}

/** CONNECT, send a byte, close; resolves with the status and the receipt id once the receipt is on disk. */
async function visit(fx: EgressFixture, port: number, target: string, auth?: string) {
  const a = await connectThrough(port, target, auth);
  if (a.status === 200) await new Promise((r) => { a.socket.once("data", r); a.socket.write("x"); });
  a.socket.end();
  const id = a.headers[RECEIPT_HEADER]!;
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200; i++) {
    try { readFileSync(file); break; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  return { status: a.status, file };
}

/** A plain HTTP GET through the witness, in absolute form; resolves with the status once the receipt is on disk. */
async function get(fx: EgressFixture, port: number, target: string, auth: string) {
  const { status, id } = await new Promise<{ status: number; id: string }>((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: `http://${target}/`, headers: { host: target, "proxy-authorization": auth }, agent: false }, (res) => {
      res.resume();
      res.on("end", () => resolve({ status: res.statusCode!, id: String(res.headers[RECEIPT_HEADER]) }));
    });
    req.on("error", reject);
    req.end();
  });
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200; i++) {
    try { readFileSync(file); break; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  return status;
}

const closedPort = () => new Promise<number>((resolve) => {
  const s = createServer();
  s.listen(0, "127.0.0.1", () => { const p = (s.address() as AddressInfo).port; s.close(() => resolve(p)); });
});

describe("egress draft-policy", () => {
  let docs: EchoServer, registry: EchoServer, exfil: EchoServer;
  let web: Server;
  let webAt: string;
  let observed: Awaited<ReturnType<typeof witness>>;
  let draft: EgressPolicyDraft;
  let anonymous: string, forgedFile: string;
  const at = (e: EchoServer) => `127.0.0.1:${e.port}`;

  beforeAll(async () => {
    [docs, registry, exfil] = await Promise.all([startEcho(), startEcho(), startEcho()]);
    web = createHttpServer((_req, res) => res.end("ok"));
    await new Promise<void>((r) => web.listen(0, "127.0.0.1", () => r()));
    webAt = `127.0.0.1:${(web.address() as AddressInfo).port}`;
    // observe mode under a policy that permits nothing: every verified connection is relayed and recorded as a deny
    observed = await witness(mkdtempSync(join(tmpdir(), "egress-draft-")), { mode: "observe" }, "forbid(principal, action, resource);\n");
    const { fx, port } = observed;
    for (const [target, auth] of [[at(registry), research], [at(docs), research], [at(docs), research], [at(registry), build]] as const) {
      expect((await visit(fx, port, target, auth)).status).toBe(200);
    }
    const anon = await visit(fx, port, at(docs));
    expect(anon.status).toBe(407);
    anonymous = anon.file.split("/").at(-1)!;
    expect((await visit(fx, port, `127.0.0.1:${await closedPort()}`, research)).status).toBe(502);
    // a plain GET: the action is host:port as for a tunnel, so only the scheme tells them apart
    expect(await get(fx, port, webAt, build)).toBe(200);
    // a receipt someone rewrote: research-agent "reached" the exfiltration host
    const forged = await visit(fx, port, at(exfil), research);
    forgedFile = forged.file.split("/").at(-1)!;
    const bundle = JSON.parse(readFileSync(forged.file, "utf8")) as ReceiptBundle;
    const payload = Buffer.from(bundle.envelope.payload, "base64").toString().replaceAll(`:${exfil.port}`, ":9");
    writeFileSync(forged.file, JSON.stringify({ ...bundle, envelope: { ...bundle.envelope, payload: Buffer.from(payload).toString("base64") } }));
    await observed.stop();
    // a symlink to a copy of a real receipt outside the directory, and a fifo: neither is read, and the draft does not stall
    const outside = join(mkdtempSync(join(tmpdir(), "egress-draft-outside-")), "copy.json");
    copyFileSync(join(fx.receiptsDir, anonymous), outside);
    symlinkSync(outside, join(fx.receiptsDir, "linked.json"));
    expect(spawnSync("mkfifo", [join(fx.receiptsDir, "fifo.json")]).status).toBe(0);
    draft = draftEgressPolicy(fx.receiptsDir, { issuerKeys: [loadPublicKey(fx.witnessPub)], logFile: fx.logFile });
  });
  afterAll(async () => { await Promise.all([docs, registry, exfil].map((e) => e.close())); await new Promise((r) => web.close(r)); });

  it("starts with the review warning, because it permits whatever the agents did", () => {
    expect(draft.policy.startsWith(DRAFT_WARNING.join("\n") + "\n")).toBe(true);
    expect(draft.policy).toContain("including any they should not have reached");
  });

  it("drafts one permit per verified agent and scheme over the destinations it was relayed to, sorted, de-duplicated, and counted", () => {
    expect(policyParseErrors(draft.policy)).toEqual([]);
    expect(draft.agents.map((a) => a.id)).toEqual([BUILD, EGRESS_AGENT]);
    const r = draft.agents[1]!;
    expect(r.destinations.map((d) => d.name)).toEqual([at(docs), at(registry)].sort());
    expect(r.destinations.find((d) => d.name === at(docs))!.count).toBe(2);
    expect(r.count).toBe(3);
    for (const d of r.destinations) expect(d.first <= d.last).toBe(true);
    // research-agent: tunnels; build-agent: tunnels and plain HTTP, each in its own permit
    expect(draft.policy.match(/^permit\(/gm)).toHaveLength(3);
    expect(draft.agents[0]!.destinations.map((d) => [d.scheme, d.name])).toEqual([["connect", at(registry)], ["http", webAt]]);
    expect(draft.policy).toMatch(new RegExp(`Action::"${at(docs)}"[,]? // 2 connections, first \\S+, last \\S+`));
    // 127.0.0.1 is internal: the comment says only the platform refuses a literal a rule names
    expect(draft.policy).toContain("INTERNAL ADDRESS");
  });

  it("skips a receipt that does not verify, a connection with no verified agent, and one that was not relayed, and says so", () => {
    expect(draft.read).toBe(10);
    expect(draft.used).toBe(5);
    expect(draft.skipped.filter((s) => s.kind === "not-a-file").map((s) => s.file).sort()).toEqual(["fifo.json", "linked.json"]);
    expect(draft.skipped.find((s) => s.file === forgedFile)?.kind).toBe("unverified");
    expect(draft.skipped.filter((s) => s.kind === "not-relayed").map((s) => s.reason)).toEqual(["error"]);
    // An observe-mode 407 keeps the policy's unenforced deny beside a denied status, which the verifier refuses today,
    // so it is skipped as unverified rather than as no verified agent. Either way no anonymous connection is permitted.
    expect(["no-agent", "unverified"]).toContain(draft.skipped.find((s) => s.file === anonymous)?.kind);
    expect(draft.skipped).toHaveLength(5);
    expect(draft.policy).not.toContain('"unknown"');
    expect(draft.policy).not.toContain(`"${at(exfil)}"`);
    expect(draft.policy).not.toContain(`"127.0.0.1:9"`);
    expect(draft.policy).toMatch(/^\/\/   skipped, did not verify: \d$/m);
  });

  it("enforced, the draft allows what each agent did and refuses what it did not; a draft from those receipts permits only what was relayed", async () => {
    const w = await witness(mkdtempSync(join(tmpdir(), "egress-draft-enforce-")), {}, draft.policy);
    try {
      expect((await visit(w.fx, w.port, at(docs), research)).status).toBe(200);
      expect((await visit(w.fx, w.port, at(registry), build)).status).toBe(200);
      expect((await visit(w.fx, w.port, at(docs), build)).status).toBe(403);
      expect((await visit(w.fx, w.port, at(exfil), research)).status).toBe(403);
      expect((await visit(w.fx, w.port, at(docs))).status).toBe(407);
      // the observed plain GET is permitted as a plain GET, never as a tunnel to the same host and port
      expect(await get(w.fx, w.port, webAt, build)).toBe(200);
      expect((await visit(w.fx, w.port, webAt, build)).status).toBe(403);
    } finally { await w.stop(); }
    const again = draftEgressPolicy(w.fx.receiptsDir, { issuerKeys: [loadPublicKey(w.fx.witnessPub)], logFile: w.fx.logFile });
    expect(again.skipped.map((s) => s.kind).sort()).toEqual(["no-agent", "not-relayed", "not-relayed", "not-relayed"]);
    expect(again.agents.map((a) => [a.id, a.destinations.map((d) => `${d.scheme} ${d.name}`)])).toEqual([[BUILD, [`connect ${at(registry)}`, `http ${webAt}`]], [EGRESS_AGENT, [`connect ${at(docs)}`]]]);
  });

  it("the command prints the draft, names the receipt it skipped, and exits 1 when there is nothing to permit", () => {
    const { fx } = observed;
    const ok = spawnSync(process.execPath, ["--import", "tsx", cli, "egress", "draft-policy", "--receipts", fx.receiptsDir, "--issuer-key", fx.witnessPub, "--log", fx.logFile], { encoding: "utf8", timeout: 30_000 });
    expect(ok.status, ok.stderr).toBe(0);
    expect(ok.stdout).toBe(draft.policy);
    expect(ok.stderr).toMatch(/skipped \S+\.json: does not verify/);
    const empty = mkdtempSync(join(tmpdir(), "egress-draft-empty-"));
    const none = spawnSync(process.execPath, ["--import", "tsx", cli, "egress", "draft-policy", "--receipts", empty, "--issuer-key", fx.witnessPub], { encoding: "utf8", timeout: 30_000 });
    expect(none.status).toBe(1);
    expect(none.stdout.startsWith(DRAFT_WARNING[0]!)).toBe(true);
  });
});
