// Aspect: the egress witness, a receipted forward proxy for calls that go around the gateway. Source: src/egress.ts, src/config.ts
// Run:    node examples/41-egress.ts
//
// The gateway holds the agent's tool credentials, so an agent's calls should go through it. An agent with a credential
// of its own could call the provider directly. Under lockdown (deploy/gateway/lockdown) the agent's network reaches only
// the gateway and this witness, so a direct call has to come through here: the witness identifies the agent by the proxy
// credential it checked, lets the Cedar policy decide per destination, and receipts the connection either way. It sees
// where traffic went and how much, never what was sent: no TLS interception.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { loadEgressConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import { DESTINATION_FACT, createEgressHost, serveEgress, type EgressResult } from "../src/egress.ts";
import type { ReceiptBundle, ReceiptStatement } from "../src/receipt.ts";
import { formatReport, verifyBundle } from "../src/verify.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho } from "../scripts/egress-fixture.ts";
import { out, step } from "./_out.ts";

step(1, "the witness from egress.json: one agent, its proxy secret in the environment, a policy per destination");
const fx = buildEgressFixture(out("41-egress"));
console.log("   policy:\n" + readFileSync(join(fx.dir, "policy.cedar"), "utf8").split("\n").map((l) => "     " + l).join("\n"));
const host = await createEgressHost(loadEgressConfig(fx.configFile));
const witness = await serveEgress(host, { port: 0, log: () => {} });
const port = Number(new URL(witness.url).port);
console.log(`   witness: ${witness.url}; the agent's HTTPS_PROXY is http://${EGRESS_AGENT}:<secret>@<witness>`);

const receiptOf = async (id: string) => {
  const file = join(fx.receiptsDir, `${id}.json`);
  for (let i = 0; i < 200; i++) {
    try { return JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  throw new Error(`no receipt ${id}`);
};
const decode = (b: ReceiptBundle) => JSON.parse(Buffer.from(b.envelope.payload, "base64").toString()) as ReceiptStatement;
const auth = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);

step(2, "the agent tries a direct call to the payment provider, around the gateway: CONNECT api.stripe.com:443");
const refused = await connectThrough(port, "api.stripe.com:443", auth);
refused.socket.destroy();
const refusedBundle = await receiptOf(refused.headers[RECEIPT_HEADER]!);
const rp = decode(refusedBundle).predicate;
console.log(`   HTTP ${refused.status}: ${JSON.parse(refused.body).error}; nothing left this machine`);
console.log(`   receipt ${rp.receiptId.slice(0, 8)}: issuer ${rp.issuer.kind}, agent ${rp.agent.id} (${rp.agent.provenance}: the credential the witness checked), destination ${rp.tool.name} (${rp.tool.provenance}), ${rp.execution.status}`);

step(3, "the same agent reaches the documentation mirror the policy allows; the tunnel is opaque to the witness");
const docs = await startEcho();
const allowed = await connectThrough(port, `127.0.0.1:${docs.port}`, auth);
await new Promise((r) => { allowed.socket.once("data", r); allowed.socket.write("GET /guide"); });
allowed.socket.end();
const ap = decode(await receiptOf(allowed.headers[RECEIPT_HEADER]!)).predicate;
const result = (ap.execution as { result: EgressResult }).result;
console.log(`   HTTP ${allowed.status}; receipt ${ap.receiptId.slice(0, 8)}: ${ap.tool.name}, ${result.bytesUp} bytes up, ${result.bytesDown} down, ${result.end}; the bytes themselves are not in it`);

step(4, "a connection with no proxy credential names nobody, so it is refused whatever the destination");
const anonymous = await connectThrough(port, `127.0.0.1:${docs.port}`);
anonymous.socket.destroy();
const np = decode(await receiptOf(anonymous.headers[RECEIPT_HEADER]!)).predicate;
console.log(`   HTTP ${anonymous.status} (${anonymous.headers["proxy-authenticate"]}); receipt ${np.receiptId.slice(0, 8)}: agent ${np.agent.id} (${np.agent.provenance}), credential ${(np.facts[DESTINATION_FACT]!.value as { credential: string }).credential}`);

step(5, "anyone with the witness's public key verifies the refusal");
const report = verifyBundle(refusedBundle, { issuerKeys: [loadPublicKey(fx.witnessPub)], principalKeys: [], logFile: fx.logFile });
console.log(formatReport(report).split("\n").map((l) => "   " + l).join("\n"));
console.log("   what this receipt cannot tell you: what the agent meant to send. A receipt is an observed bypass, not a record of what was done.");

await host.close();
await witness.close();
await docs.close();
if (!report.ok || refused.status !== 403 || rp.execution.status !== "denied") throw new Error("the refusal was not receipted and verified");
console.log("\nOK");
