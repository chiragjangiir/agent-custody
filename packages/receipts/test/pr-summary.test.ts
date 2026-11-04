// The table that the GitHub Action posts. The input is the signed vectors, so the test needs no gateway and no network.
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { describe, expect, it } from "vitest";
import { loadSdkConfig } from "../src/config.ts";
import { publicKeyFromPem } from "../src/crypto.ts";
import { formatSummaryMarkdown, receiptFiles, summarizeReceipts, SUMMARY_MARKER } from "../src/pr-summary.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { buildSdkFixture } from "../scripts/fixture.ts";

const vectors = JSON.parse(readFileSync(join(import.meta.dirname, "..", "vectors", "receipts.json"), "utf8"));
const cli = join(import.meta.dirname, "..", "src", "cli.ts");
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString("utf8")) as ReceiptStatement;
const vector = (name: string): ReceiptBundle => vectors.cases.find((c: { name: string }) => c.name === name).bundle;

/** A directory of bundles named by receipt id, as the gateway writes them, and the issuer and principal key files. */
function setup(bundles: ReceiptBundle[]) {
  const dir = mkdtempSync(join(tmpdir(), "pr-summary-"));
  const receipts = join(dir, "receipts");
  mkdirSync(receipts);
  for (const b of bundles) writeFileSync(join(receipts, `${decode(b).predicate.receiptId}.json`), JSON.stringify(b));
  writeFileSync(join(dir, "issuer.pub"), vectors.keys.gateway.publicKeyPem);
  writeFileSync(join(dir, "principal.pub"), vectors.keys.principal.publicKeyPem);
  return { dir, receipts };
}
const keys = { issuerKeys: [publicKeyFromPem(vectors.keys.gateway.publicKeyPem)], principalKeys: [publicKeyFromPem(vectors.keys.principal.publicKeyPem)] };
const good = () => [vector("gateway-executed-no-log-copy"), vector("gateway-denied")];

/** One character of the signed payload changes, so the signature no longer matches. */
function oneByteChanged(b: ReceiptBundle): ReceiptBundle {
  const copy = structuredClone(b);
  const payload = copy.envelope.payload;
  copy.envelope.payload = payload.slice(0, 40) + (payload[40] === "A" ? "B" : "A") + payload.slice(41);
  return copy;
}

describe("the pull request table", () => {
  it("lists a good bundle as verified with its tool and status", () => {
    const { receipts } = setup(good());
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(true);
    expect(summary.rows.map((r) => [r.tool, r.status, r.result]).sort()).toEqual(
      good().map((b) => [decode(b).predicate.tool.name, decode(b).predicate.execution.status, "verified"]).sort(),
    );
    const md = formatSummaryMarkdown(summary);
    expect(md.startsWith(`${SUMMARY_MARKER}\n`)).toBe(true);
    expect(md).toContain("**Verified.** All 2 receipts verify.");
    expect(md).toContain("| Receipt | Tool | Status | Result |");
    expect(md).toContain("| denied | verified |");
  });

  it("names the failed check when one byte of a receipt changes, and lists that receipt first", () => {
    const [executed, denied] = good() as [ReceiptBundle, ReceiptBundle];
    const { receipts } = setup([executed]);
    // the changed bundle keeps the file name of the original receipt
    writeFileSync(join(receipts, `${decode(denied).predicate.receiptId}.json`), JSON.stringify(oneByteChanged(denied)));
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(false);
    const bad = summary.rows.filter((r) => !r.ok);
    expect(bad).toHaveLength(1);
    expect(bad[0]!.receiptId).toBe(decode(denied).predicate.receiptId);
    expect(bad[0]!.result).toContain("receipt signature (issuer key)");
    const md = formatSummaryMarkdown(summary);
    expect(md).toContain("**Not verified.** 1 of 2 receipts do not verify.");
    expect(md).toContain("`receipt signature (issuer key)`");
    expect(md.indexOf(decode(denied).predicate.receiptId)).toBeLessThan(md.indexOf(decode(executed).predicate.receiptId));
  });

  it("fails a valid receipt under the file name of another receipt", () => {
    const [executed, denied] = good() as [ReceiptBundle, ReceiptBundle];
    const { receipts } = setup([executed]);
    writeFileSync(join(receipts, `${decode(denied).predicate.receiptId}.json`), JSON.stringify(executed));
    const summary = summarizeReceipts(receiptFiles(receipts), keys);
    expect(summary.ok).toBe(false);
    expect(summary.rows.filter((r) => !r.ok).map((r) => r.result)).toEqual(["file name matches receipt id"]);
  });

  it("fails when the directory holds no receipt, or does not exist", () => {
    const { dir, receipts } = setup([]);
    writeFileSync(join(receipts, `${"0".repeat(8)}-0000-0000-0000-000000000000.authorization.json`), "{}");
    for (const path of [receipts, join(dir, "missing")]) {
      const summary = summarizeReceipts(receiptFiles(path), keys);
      expect(summary.ok).toBe(false);
      expect(formatSummaryMarkdown(summary)).toContain("**Not verified.** No receipt bundles found.");
    }
  });

  it("keeps text from a receipt out of the table markup", () => {
    const { receipts } = setup([]);
    writeFileSync(join(receipts, "evil|<img>.json"), "not json at all `x` |");
    const md = formatSummaryMarkdown(summarizeReceipts(receiptFiles(receipts), keys));
    expect(md).not.toMatch(/<img>/);
    const row = md.split("\n").find((l) => l.includes("evil"))!;
    expect(row.split("|").length).toBe(6);
  });
});

describe("what a pull request can put into the comment", () => {
  it("shows a signed tool name that holds Markdown, a newline, and the marker as one escaped cell", async () => {
    const fx = buildSdkFixture(mkdtempSync(join(tmpdir(), "pr-summary-sdk-")));
    const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
    await sdk.record({ tool: `x\`|\n${SUMMARY_MARKER}<img src=x>\\y`, args: {} }, { status: "executed", result: {} });
    const summary = summarizeReceipts(receiptFiles(fx.receiptsDir), { issuerKeys: [publicKeyFromPem(readFileSync(fx.appPub, "utf8"))], principalKeys: [] });
    expect(summary.ok).toBe(true);
    const md = formatSummaryMarkdown(summary);
    expect(md.split(SUMMARY_MARKER)).toHaveLength(2);
    expect(md).not.toContain("<img");
    const rows = md.split("\n").filter((l) => l.startsWith("| `"));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatch(/^\| `[0-9a-f-]+` \| `[^`|]+` \| executed \| verified \|$/);
  });

  it("does not follow a symbolic link, and does not print what a file holds", () => {
    const { dir, receipts } = setup(good());
    writeFileSync(join(dir, "runner-file"), "RUNNER_SECRET_LINE 127.0.0.1");
    symlinkSync(join(dir, "runner-file"), join(receipts, "linked.json"));
    writeFileSync(join(receipts, "plain.json"), "RUNNER_SECRET_LINE in a file that is not JSON");
    const files = receiptFiles(receipts);
    expect(files.map((f) => basename(f))).not.toContain("linked.json");
    const summary = summarizeReceipts(files, keys);
    expect(summary.rows.find((r) => r.receiptId === "plain")!.result).toBe("not a JSON file");
    expect(formatSummaryMarkdown(summary)).not.toContain("RUNNER_SECRET_LINE");
  });
});

describe("verify --markdown", () => {
  const run = (...args: string[]) => spawnSync(process.execPath, [cli, "verify", "--markdown", ...args], { encoding: "utf8", timeout: 30_000 });

  it("prints the table and exits 0 for a good directory", () => {
    const { dir, receipts } = setup(good());
    const r = run(receipts, "--issuer-key", join(dir, "issuer.pub"), "--principal-key", join(dir, "principal.pub"));
    expect(r.status, r.stderr).toBe(0);
    expect(r.stdout).toContain("**Verified.** All 2 receipts verify.");
  });

  it("exits 1 when one receipt changed", () => {
    const { dir, receipts } = setup(good());
    const [executed] = good() as [ReceiptBundle];
    writeFileSync(join(receipts, `${decode(executed).predicate.receiptId}.json`), JSON.stringify(oneByteChanged(executed)));
    const r = run(receipts, "--issuer-key", join(dir, "issuer.pub"), "--principal-key", join(dir, "principal.pub"));
    expect(r.status).toBe(1);
    expect(r.stdout).toContain("**Not verified.** 1 of 2 receipts do not verify.");
  });

  it("exits 1 for an empty directory, and refuses --json", () => {
    const { dir, receipts } = setup([]);
    const base = ["--issuer-key", join(dir, "issuer.pub")];
    expect(run(receipts, ...base).status).toBe(1);
    expect(run(receipts, ...base, "--json").stderr).toContain("does not combine");
  });
});
