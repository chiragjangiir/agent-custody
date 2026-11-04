// Aspect: putting receipts into a pull request without publishing the call. Source: src/export.ts
// Run:    node examples/39-export.ts
//
// An agent works under a capture rule that withholds every value, except one tool that records plain values. The export
// command copies the receipts that keep their values private and refuses the one that does not. A changed byte is
// refused too. The copies are byte for byte the same as the originals, because the signature covers them.
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadSdkConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { exportReceipts, formatReceiptExport } from "../src/export.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { createSdkIssuer } from "../src/sdk/index.ts";
import { buildSdkFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const idOf = (b: ReceiptBundle) => (JSON.parse(Buffer.from(b.envelope.payload, "base64").toString("utf8")) as ReceiptStatement).predicate.receiptId;
const show = (lines: string[]) => console.log(lines.map((l) => `   ${l}`).join("\n"));

step(1, "an agent works under a capture rule: every value digest, except the command of Bash, which stays in clear");
const fx = buildSdkFixture(out("39-export"));
const cfg = JSON.parse(readFileSync(fx.configFile, "utf8"));
cfg.capture = {
  "*": { args: { mode: "digest" }, result: { mode: "digest" }, facts: { mode: "digest" } },
  Bash: { args: { mode: "digest", clear: ["command"] }, result: { mode: "digest" } },
  "notes.read": { args: { mode: "clear" }, result: { mode: "clear" } },
};
writeFileSync(fx.configFile, JSON.stringify(cfg, null, 2));
show(JSON.stringify(cfg.capture, null, 2).split("\n"));
const sdk = createSdkIssuer(loadSdkConfig(fx.configFile));
const refund = await sdk.record({ tool: "stripe.refund", args: { customer_id: "cust_123", amount: 5000 } }, { status: "executed", result: { note: "card ending 4242" } });
const bash = await sdk.record({ tool: "Bash", args: { command: "bun test", description: "run the tests" } }, { status: "executed", result: { stdout: "12 passed" } });
const notes = await sdk.record({ tool: "notes.read", args: { path: "diary.md" } }, { status: "executed", result: { text: "a plain diary" } });

step(2, "export copies the two receipts that withhold their values and refuses the third");
const keys = { issuerKeys: [loadPublicKey(fx.appPub)], principalKeys: [] };
const dest = join(fx.dir, "pr-receipts");
const first = exportReceipts({ receiptsDir: fx.receiptsDir, outDir: dest, verify: keys });
show(formatReceiptExport(first));

step(3, "the copies are the same bytes as the originals; the salts stay behind, and the output directory holds nothing else");
const same = [refund, bash].every((b) => readFileSync(join(dest, `${idOf(b)}.json`)).equals(readFileSync(join(fx.receiptsDir, `${idOf(b)}.json`))));
const only = readdirSync(dest).length === 2;
console.log(`   same bytes: ${same}, files in the output directory: ${readdirSync(dest).length}`);

step(4, "one changed byte makes export refuse the receipt");
const file = join(fx.receiptsDir, `${idOf(refund)}.json`);
const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
const payload = bundle.envelope.payload;
bundle.envelope.payload = payload.slice(0, 40) + (payload[40] === "A" ? "B" : "A") + payload.slice(41);
writeFileSync(file, JSON.stringify(bundle));
const second = exportReceipts({ receiptsDir: fx.receiptsDir, outDir: join(fx.dir, "pr-receipts-2"), verify: keys });
show(formatReceiptExport(second));

const ok = first.copied === 2 && first.refused === 1 && first.lines.find((l) => l.file === `${idOf(notes)}.json`)?.outcome === "refused" && same && only && second.copied === 1 && second.refused === 2;
if (!ok) throw new Error("unexpected result");
console.log("\nOK");
