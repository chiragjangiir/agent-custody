// `agent-custody export`: what leaves a receipts directory for a pull request. The receipts come from the SDK issuer with real capture rules,
// so the test needs no gateway and no network.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { loadSdkConfig } from "../src/config.ts";
import { clearSides } from "../src/export.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { buildSdkFixture } from "../scripts/fixture.ts";

const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString("utf8")) as ReceiptStatement;
const idOf = (b: ReceiptBundle) => decode(b).predicate.receiptId;
const pause = (ms: number) => new Promise((r) => setTimeout(r, ms));

let dir: string;
let receipts: string;
let pub: string;
let digest: ReceiptBundle;
let early: ReceiptBundle;
let late: ReceiptBundle;
let bash: ReceiptBundle;
let bashLoneCommand: ReceiptBundle;
let plain: ReceiptBundle;
let clearError: ReceiptBundle;
let clearDenied: ReceiptBundle;

beforeAll(async () => {
  const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "export-")));
  dir = fx.dir;
  receipts = fx.receiptsDir;
  pub = fx.appPub;
  const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
  cfg.capture = {
    "*": { args: { mode: "digest" }, result: { mode: "digest" }, facts: { mode: "digest" } },
    Bash: { args: { mode: "digest", clear: ["command"] }, result: { mode: "digest" } },
    "plain.tool": { args: { mode: "clear" }, result: { mode: "clear" } },
  };
  writeFileSync(fx.configFile, JSON.stringify(cfg));
  const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
  digest = await sdk.record({ tool: "stripe.refund", args: { customer_id: "cust_EXPORT_SECRET", amount: 900 } }, { status: "executed", result: { note: "card ending 4242" } });
  bash = await sdk.record({ tool: "Bash", args: { command: "ls -la", description: "list files with TOKEN_IN_DESCRIPTION" } }, { status: "executed", result: { stdout: "secret output" } });
  bashLoneCommand = await sdk.record({ tool: "Bash", args: { command: "ls" } }, { status: "executed", result: { stdout: "secret output" } });
  plain = await sdk.record({ tool: "plain.tool", args: { q: "plain question" } }, { status: "executed", result: { a: "plain answer" } });
  // no arguments, so only the error message and the denial reason carry data; a rule that withholds nothing leaves them in clear
  clearError = await sdk.record({ tool: "plain.tool", args: {} }, { status: "error", error: "failed with TOKEN_IN_ERROR" });
  clearDenied = await sdk.record({ tool: "plain.tool", args: {} }, { status: "denied", reason: "denied for TOKEN_IN_REASON" });
  early = await sdk.record({ tool: "stripe.refund", args: { amount: 1 } }, { status: "executed", result: { ok: true } });
  await pause(10);
  late = await sdk.record({ tool: "stripe.refund", args: { amount: 2 } }, { status: "executed", result: { ok: true } });
});

const out = () => join(mkdtempSync(join(tmpdir(), "export-out-")), "pr");
const run = (outDir: string, ...extra: string[]) =>
  spawnSync(process.execPath, [cli, "export", "--receipts", receipts, "--out", outDir, "--issuer-key", pub, ...extra], { encoding: "utf8", timeout: 30_000 });
const copiedNames = (outDir: string) => (existsSync(outDir) ? readdirSync(outDir).sort() : []);
const name = (b: ReceiptBundle) => `${idOf(b)}.json`;
const bytes = (path: string) => readFileSync(path);

describe("agent-custody export", () => {
  it("copies receipts that keep their values private, byte for byte, and leaves everything else in the directory", () => {
    // the directory also holds what must never leave: salts, an outbox, an authorization, a stray file, and a subdirectory
    expect(existsSync(join(receipts, "salts"))).toBe(true);
    mkdirSync(join(receipts, "outbox"), { recursive: true });
    copyFileSync(join(receipts, name(digest)), join(receipts, "outbox", name(digest)));
    copyFileSync(join(receipts, name(digest)), join(receipts, `${idOf(digest)}.authorization.json`));
    writeFileSync(join(receipts, "notes.txt"), "cust_EXPORT_SECRET");
    mkdirSync(join(receipts, "nested"), { recursive: true });
    copyFileSync(join(receipts, name(digest)), join(receipts, "nested", name(digest)));

    const outDir = out();
    const r = run(outDir);
    // the plain receipt is refused, so the run fails; the rest are copied
    expect(r.status, r.stderr).toBe(1);
    expect(copiedNames(outDir)).toEqual([name(digest), name(bash), name(early), name(late)].sort());
    for (const b of [digest, bash, early, late]) expect(bytes(join(outDir, name(b))).equals(bytes(join(receipts, name(b))))).toBe(true);
    expect(r.stdout).toContain(`copied  ${name(digest)}`);
    expect(r.stdout).toMatch(/4 copied, 4 refused, 0 skipped/);
    // no value of the digest receipt reaches the output directory
    for (const f of copiedNames(outDir)) expect(readFileSync(join(outDir, f), "utf8")).not.toMatch(/cust_EXPORT_SECRET|ending 4242|TOKEN_IN_DESCRIPTION|secret output/);
  });

  it("refuses a receipt with plain values and writes nothing for it; --allow-clear copies it and warns", () => {
    const outDir = out();
    const r = run(outDir);
    expect(r.status).toBe(1);
    expect(r.stdout).toContain(`refused ${name(plain)}: args and result in clear`);
    expect(copiedNames(outDir)).not.toContain(name(plain));

    const allowed = out();
    const a = run(allowed, "--allow-clear");
    expect(copiedNames(allowed)).toContain(name(plain));
    expect(bytes(join(allowed, name(plain))).equals(bytes(join(receipts, name(plain))))).toBe(true);
    expect(a.stdout).toContain(`copied  ${name(plain)} (plain values: args, result)`);
    expect(a.stderr).toContain("publishes its arguments or its result");
    // the digest receipts do not carry the mark
    expect(a.stdout).toContain(`copied  ${name(digest)}\n`);
  });

  it("keeps a clear-listed field in clear and refuses a call whose every field is listed", () => {
    const outDir = out();
    const r = run(outDir);
    // the command stays beside one commitment for the description; the result is withheld
    expect(copiedNames(outDir)).toContain(name(bash));
    expect(decode(bash).predicate.request.args).toMatchObject({ command: "ls -la", $rest: { $custody: "withheld" } });
    // nothing is left to withhold in { command }, and the check cannot tell it from mode clear
    expect(r.stdout).toContain(`refused ${name(bashLoneCommand)}: args in clear`);
  });

  it("refuses a receipt whose error message or denial reason is in clear", () => {
    expect(decode(clearError).predicate.execution).toMatchObject({ error: "failed with TOKEN_IN_ERROR" });
    expect(decode(clearDenied).predicate.execution).toMatchObject({ reason: "denied for TOKEN_IN_REASON" });
    const outDir = out();
    const r = run(outDir);
    expect(r.stdout).toContain(`refused ${name(clearError)}: result in clear`);
    expect(r.stdout).toContain(`refused ${name(clearDenied)}: result in clear`);
    expect(copiedNames(outDir)).not.toContain(name(clearError));
    expect(copiedNames(outDir)).not.toContain(name(clearDenied));
  });

  it("counts the value of a fact as in clear unless the capture note withholds it", () => {
    const p = decode(early).predicate;
    expect(clearSides(p)).toEqual([]);
    const facts = { customer: { tool: "customer.lookup", args: {}, value: { verified: true }, resultDigest: "d", provenance: "observed" as const } };
    expect(clearSides({ ...p, facts })).toEqual(["facts"]);
    const note = { ...p.capture!, withheld: [...p.capture!.withheld, ["facts", "customer", "value", "$rest"]] };
    expect(clearSides({ ...p, facts, capture: note })).toEqual([]);
  });

  it("exits 0 and copies everything when every receipt keeps its values private", () => {
    const only = mkdtempSync(join(tmpdir(), "export-private-"));
    for (const b of [digest, bash]) copyFileSync(join(receipts, name(b)), join(only, name(b)));
    const outDir = out();
    const r = spawnSync(process.execPath, [cli, "export", "--receipts", only, "--out", outDir, "--issuer-key", pub], { encoding: "utf8", timeout: 30_000 });
    expect(r.status, r.stderr).toBe(0);
    expect(copiedNames(outDir)).toEqual([name(digest), name(bash)].sort());
    expect(r.stdout).toContain("2 copied, 0 refused, 0 skipped");
  });

  it("refuses a receipt that does not verify, and a valid receipt under the name of another", () => {
    const only = mkdtempSync(join(tmpdir(), "export-bad-"));
    const tampered = structuredClone(digest);
    const payload = tampered.envelope.payload;
    tampered.envelope.payload = payload.slice(0, 40) + (payload[40] === "A" ? "B" : "A") + payload.slice(41);
    writeFileSync(join(only, name(digest)), JSON.stringify(tampered));
    const otherName = `${idOf(bash).replace(/^./, (c) => (c === "0" ? "1" : "0"))}.json`;
    copyFileSync(join(receipts, name(bash)), join(only, otherName));
    copyFileSync(join(receipts, name(early)), join(only, name(early)));
    const outDir = out();
    const r = spawnSync(process.execPath, [cli, "export", "--receipts", only, "--out", outDir, "--issuer-key", pub], { encoding: "utf8", timeout: 30_000 });
    expect(r.status).toBe(1);
    expect(r.stdout).toContain(`refused ${name(digest)}: receipt signature (issuer key)`);
    expect(r.stdout).toContain(`refused ${otherName}: file name matches receipt id`);
    expect(copiedNames(outDir)).toEqual([name(early)]);
    expect(r.stdout).toContain("1 copied, 2 refused, 0 skipped");
  });

  it("--since keeps the receipts issued at or after that time", () => {
    const outDir = out();
    const r = run(outDir, "--since", decode(late).predicate.timestamp);
    expect(copiedNames(outDir)).toEqual([name(late)]);
    expect(r.stdout).toContain(`skipped ${name(early)}: issued ${decode(early).predicate.timestamp}, before --since`);
    // a receipt older than --since is skipped before the privacy check, so a plain receipt from before the rule does not fail the run
    expect(r.stdout).toContain(`skipped ${name(plain)}`);
    expect(r.status).toBe(0);
  });

  it("exits 1 with a message when it copies no receipt, and creates no output directory", () => {
    const outDir = out();
    const empty = mkdtempSync(join(tmpdir(), "export-empty-"));
    writeFileSync(join(empty, "notes.txt"), "x");
    const none = spawnSync(process.execPath, [cli, "export", "--receipts", empty, "--out", outDir, "--issuer-key", pub], { encoding: "utf8", timeout: 30_000 });
    expect(none.status).toBe(1);
    expect(none.stderr).toContain("The receipts directory holds no receipt bundle.");
    const future = run(outDir, "--since", "2999-01-01T00:00:00Z");
    expect(future.status).toBe(1);
    expect(future.stderr).toContain("No receipt was copied.");
    expect(existsSync(outDir)).toBe(false);
  });

  it("needs --issuer-key, and a valid --since", () => {
    const noKey = spawnSync(process.execPath, [cli, "export", "--receipts", receipts, "--out", out()], { encoding: "utf8", timeout: 30_000 });
    expect(noKey.status).toBe(1);
    expect(noKey.stderr).toContain("--issuer-key");
    // Date.parse reads a bare number as a year
    for (const since of ["last week", "1", "2001"]) expect(run(out(), "--since", since).stderr).toContain("--since must be an ISO time");
    expect(run(out(), "--since", "2999-01-01").stderr).toContain("No receipt was copied.");
  });
});
