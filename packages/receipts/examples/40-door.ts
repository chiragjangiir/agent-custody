// Aspect: the door, a receipted reverse proxy in front of your own site or API. Source: src/door.ts, src/config.ts
// Run:    node examples/40-door.ts
//
// The gateway stands in front of an agent's tools. The door stands in front of a business: a shop's API here. Every
// arrival is classified by what it presented, decided by the Cedar policy for its route, relayed or refused, and
// receipted either way. An unknown arrival may read the catalogue and may not refund; an agent carrying a grant signed
// by the shop's principal key is verified and may refund a positive amount up to £50, and that refund is committed to
// the log before it is relayed; a grant signed by a stranger leaves it claimed.
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { loadDoorConfig } from "../src/config.ts";
import { generateKeyPair, loadPublicKey } from "../src/crypto.ts";
import { createDelegation } from "../src/delegation.ts";
import { ARRIVAL_FACT, CLASS_HEADER, RECEIPT_HEADER, createDoorHost, serveDoor } from "../src/door.ts";
import { grantHeader } from "../src/gateway-http.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { buildDoorFixture, startOrigin } from "../scripts/door-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "a stand-in shop API, and the door in front of it from door.json");
const origin = await startOrigin();
const fx = buildDoorFixture(out("40-door"), origin.url);
console.log("   policy:\n" + readFileSync(join(fx.dir, "policy.cedar"), "utf8").split("\n").map((l) => "     " + l).join("\n"));
const host = await createDoorHost(loadDoorConfig(fx.configFile));
const door = await serveDoor(host, { port: 0, log: () => {} });
console.log("   door:", door.url, "in front of", origin.url);

const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const show = async (label: string, res: Response) => {
  const id = res.headers.get(RECEIPT_HEADER)!;
  const p = decode(JSON.parse(readFileSync(join(fx.receiptsDir, `${id}.json`), "utf8")) as ReceiptBundle).predicate;
  const arrival = p.facts[ARRIVAL_FACT]!.value as { class: string; subject: string; grant: string };
  console.log(`   ${label}: HTTP ${res.status}, class ${res.headers.get(CLASS_HEADER)}, route ${p.tool.name}, ${p.execution.status}; agent ${p.agent.id} (${p.agent.provenance}), grant ${arrival.grant}; receipt ${id.slice(0, 8)}`);
  return id;
};

step(2, "an unknown arrival, a browser or a bot, reads the catalogue and is refused a refund");
await show("GET /catalogue/shoes ", await fetch(`${door.url}/catalogue/shoes`));
const refused = await show("POST /refunds        ", await fetch(`${door.url}/refunds`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ order: "o_1", amount: 1000 }) }));

step(3, "the shop's principal signs a grant for its shopping agent: the passport the door accepts");
const grant = createDelegation(fx.principalKey, { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund", "api"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
const passport = { authorization: `Bearer ${grantHeader(grant)}`, "content-type": "application/json" };
const allowed = await show("POST /refunds £45    ", await fetch(`${door.url}/refunds`, { method: "POST", headers: passport, body: JSON.stringify({ order: "o_2", amount: 4500 }) }));
await show("POST /refunds £90    ", await fetch(`${door.url}/refunds`, { method: "POST", headers: passport, body: JSON.stringify({ order: "o_3", amount: 9000 }) }));
await show("POST /refunds -£10   ", await fetch(`${door.url}/refunds`, { method: "POST", headers: passport, body: JSON.stringify({ order: "o_3b", amount: -1000 }) }));
console.log("   the £45 refund was committed to the log before it was relayed:", existsSync(join(fx.receiptsDir, `${allowed}.authorization.json`)) ? "receipts/<id>.authorization.json is on disk" : "MISSING");

step(4, "a grant signed by a stranger is claimed, not verified, and the policy refuses it");
const forged = createDelegation(generateKeyPair(), { version: "0.1", principal: "shop-owner", agent: "shopping-agent", scopes: ["refund"], issuedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 3600_000).toISOString() });
await show("POST /refunds forged ", await fetch(`${door.url}/refunds`, { method: "POST", headers: { authorization: `Bearer ${grantHeader(forged)}`, "content-type": "application/json" }, body: JSON.stringify({ order: "o_4", amount: 100 }) }));

step(5, "the origin saw only what was allowed, with the arrival's address and the receipt id on each request");
console.log("   requests at the origin:", origin.seen.map((s) => `${s.method} ${s.path} (receipt ${String(s.headers[RECEIPT_HEADER]).slice(0, 8)}, ${s.headers[CLASS_HEADER]})`).join("; "));

step(6, "anyone with the door's and the principal's public keys verifies the receipts; the refusal verifies without a principal key at all");
const keys = { issuerKeys: [loadPublicKey(fx.doorPub)], principalKeys: [loadPublicKey(fx.principalPub)], logFile: fx.logFile };
const okReport = verifyBundle(JSON.parse(readFileSync(join(fx.receiptsDir, `${allowed}.json`), "utf8")), keys);
console.log(formatReport(okReport).split("\n").slice(0, 12).map((l) => "   " + l).join("\n"));
const refusedReport = verifyBundle(JSON.parse(readFileSync(join(fx.receiptsDir, `${refused}.json`), "utf8")), { issuerKeys: keys.issuerKeys, principalKeys: [] });
console.log(`   refusal: ${refusedReport.ok ? "verified" : "FAILED"}, ${refusedReport.checks.length} checks, principal ${refusedReport.statement?.predicate.principal.provenance}`);

await door.close();
await host.close();
await origin.close();
if (!okReport.ok || !refusedReport.ok) throw new Error("a receipt did not verify");
console.log("\nOK");
