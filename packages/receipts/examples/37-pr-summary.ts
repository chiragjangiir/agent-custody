// Aspect: the table that the GitHub Action posts on a pull request. Source: src/pr-summary.ts
// Run:    node examples/37-pr-summary.ts
//
// A gateway makes two receipts. The reviewer's side verifies the directory and gets one table. Then one byte of one
// receipt changes, as in a tampered branch, and the same command names the failed check. The action in action.yml runs
// the same code as `agent-custody verify --markdown`.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { createGateway } from "../src/gateway.ts";
import { formatSummaryMarkdown, receiptFiles, summarizeReceipts } from "../src/pr-summary.ts";
import { buildFixture } from "../scripts/fixture.ts";
import { out, step } from "./_out.ts";

const fx = buildFixture(out("37-pr-summary"));
const keys = { issuerKeys: [loadPublicKey(fx.gatewayPub)], principalKeys: [loadPublicKey(fx.principalPub)] };

step(1, "an agent works through the gateway; each call gets a signed receipt in the receipts directory");
const gw = await createGateway(loadConfig(fx.configFile));
await gw.handleCall({ name: "customer.lookup", arguments: { customer_id: "cust_123" } });
await gw.handleCall({ name: "stripe.refund", arguments: { customer_id: "cust_123", amount: 5000, currency: "GBP" } });
await gw.close();

step(2, "the reviewer's side verifies the directory and gets one table");
const before = summarizeReceipts(receiptFiles(fx.receiptsDir), keys);
console.log(formatSummaryMarkdown(before).replace(/^/gm, "   "));

step(3, "one byte of one receipt changes; the table names the failed check and the run fails");
const victim = before.rows[0]!.file;
const bundle = JSON.parse(readFileSync(victim, "utf8")) as { envelope: { payload: string } };
const payload = bundle.envelope.payload;
bundle.envelope.payload = payload.slice(0, 40) + (payload[40] === "A" ? "B" : "A") + payload.slice(41);
writeFileSync(victim, JSON.stringify(bundle));
const after = summarizeReceipts(receiptFiles(fx.receiptsDir), keys);
console.log(formatSummaryMarkdown(after).replace(/^/gm, "   "));

step(4, "a directory with no receipt fails too");
const empty = summarizeReceipts(receiptFiles(join(fx.receiptsDir, "missing")), keys);
console.log(formatSummaryMarkdown(empty).replace(/^/gm, "   "));

const ok = before.ok && before.rows.length === 2 && !after.ok && after.rows.filter((r) => !r.ok).length === 1 && after.rows.some((r) => r.result.includes("receipt signature (issuer key)")) && !empty.ok;
if (!ok) throw new Error("unexpected result");
console.log("\nOK");
