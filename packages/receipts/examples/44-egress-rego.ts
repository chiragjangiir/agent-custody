// Aspect: the egress witness deciding by a Rego policy in place of Cedar. Source: src/egress.ts, src/policy-rego.ts
// Run:    node examples/44-egress-rego.ts   (needs the opa binary on PATH)
//
// A team that already writes its policies in Rego points `policyFile` at a .rego file. The witness compiles it with
// `opa build`, as the gateway does, and evaluates it in-process on every connection. The input is the same request as
// Cedar's: the principal is the agent the proxy credential proved, the action is host:port, and
// context.facts.destination is the witness's own observation. A file that does not compile is never loaded.
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadEgressConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import { createEgressHost, serveEgress } from "../src/egress.ts";
import { policyDigest } from "../src/policy.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { verifyBundle } from "../src/verify.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho } from "../scripts/egress-fixture.ts";
import { out, step } from "./_out.ts";

const REGO = `package agentcustody

# The research agent may reach the documentation mirror on this machine.
allow if {
	input.principal == "${EGRESS_AGENT}"
	input.context.facts.destination.host == "127.0.0.1"
}

# Payments go through the gateway, which holds the Stripe key.
deny contains "payments go through the gateway" if endswith(input.action, ".stripe.com:443")
`;

step(1, "egress.json names policy.rego; the witness compiles it with opa build when it loads");
const fx = buildEgressFixture(out("44-egress-rego"), { policyFile: "policy.rego" }, REGO);
const policyFile = join(fx.dir, "policy.rego");
console.log("   policy:\n" + readFileSync(policyFile, "utf8").split("\n").map((l) => "     " + l).join("\n"));
const host = await createEgressHost(loadEgressConfig(fx.configFile));
const witness = await serveEgress(host, { port: 0, log: () => {} });
const port = Number(new URL(witness.url).port);
console.log(`   witness: ${witness.url}; policy digest ${host.policyDigest().slice(0, 12)}…`);

const receiptOf = async (id: string) => {
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200; i++) {
    try { return JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  throw new Error(`no receipt ${id}`);
};
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const auth = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);

step(2, "the agent tries the payment provider directly; the Rego deny rule refuses it, and its string is the reason");
const refused = await connectThrough(port, "api.stripe.com:443", auth);
refused.socket.destroy();
const refusedBundle = await receiptOf(refused.headers[RECEIPT_HEADER]!);
const rp = decode(refusedBundle).predicate;
console.log(`   HTTP ${refused.status}: ${JSON.parse(refused.body).reason}`);
console.log(`   receipt ${rp.receiptId.slice(0, 8)}: ${rp.tool.name}, ${rp.policy!.decision}, policy ${rp.policy!.policyDigest.slice(0, 12)}… (the sha256 of policy.rego)`);

step(3, "the documentation mirror is allowed for the agent the credential proved");
const docs = await startEcho();
const allowed = await connectThrough(port, `127.0.0.1:${docs.port}`, auth);
allowed.socket.end();
const ap = decode(await receiptOf(allowed.headers[RECEIPT_HEADER]!)).predicate;
console.log(`   HTTP ${allowed.status}; receipt ${ap.receiptId.slice(0, 8)}: ${ap.policy!.decision} by ${ap.policy!.reasons.join(", ")}`);

step(4, "a guessed secret naming the same agent: the Rego principal is \"unknown\", so the allow does not hold");
const guessed = await connectThrough(port, `127.0.0.1:${docs.port}`, proxyAuth(EGRESS_AGENT, "guess"));
guessed.socket.destroy();
const gp = decode(await receiptOf(guessed.headers[RECEIPT_HEADER]!)).predicate;
console.log(`   HTTP ${guessed.status}; receipt ${gp.receiptId.slice(0, 8)}: agent ${gp.agent.id} (${gp.agent.provenance}), policy ${gp.policy!.decision}`);

step(5, "an edit that does not compile is not loaded; the policy in force stays");
writeFileSync(`${policyFile}.new`, "package agentcustody\nallow if {\n");
renameSync(`${policyFile}.new`, policyFile);
const after = await connectThrough(port, `127.0.0.1:${docs.port}`, auth);
after.socket.end();
const afterp = decode(await receiptOf(after.headers[RECEIPT_HEADER]!)).predicate;
console.log(`   HTTP ${after.status}; still decided by policy ${afterp.policy!.policyDigest.slice(0, 12)}…`);

const report = verifyBundle(refusedBundle, { issuerKeys: [loadPublicKey(fx.witnessPub)], principalKeys: [], logFile: fx.logFile });
console.log(`\n   the refusal verifies with the witness's public key: ${report.ok ? "PASS" : "FAIL"}`);

await host.close();
await witness.close();
await docs.close();
if (!report.ok || refused.status !== 403 || allowed.status !== 200 || guessed.status !== 407 || gp.policy!.decision !== "deny" || after.status !== 200 || afterp.policy!.policyDigest !== policyDigest(REGO)) {
  throw new Error("the Rego policy did not decide as shown");
}
console.log("\nOK");
