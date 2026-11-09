// Aspect: a first egress policy, drafted from what the agents did while the witness only observed. Source: src/egress-draft.ts
// Run:    node examples/42-egress-draft.ts
//
// Writing an allow list from nothing means guessing. Run the witness with "mode": "observe" for a while instead: it
// relays every connection from a verified agent and receipts it. `agent-custody egress draft-policy` then turns those
// receipts into one permit per agent and scheme. The draft permits whatever happened in the window, a bad destination included,
// so a person reviews it before it is enforced. This tutorial shows the review catching one.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { loadEgressConfig } from "../src/config.ts";
import { loadPublicKey } from "../src/crypto.ts";
import { RECEIPT_HEADER } from "../src/door.ts";
import { draftEgressPolicy } from "../src/egress-draft.ts";
import { createEgressHost, serveEgress } from "../src/egress.ts";
import { EGRESS_AGENT, EGRESS_SECRET, buildEgressFixture, connectThrough, proxyAuth, startEcho, type EgressFixture } from "../scripts/egress-fixture.ts";
import { out, step } from "./_out.ts";

const auth = proxyAuth(EGRESS_AGENT, EGRESS_SECRET);
async function visit(fx: EgressFixture, port: number, target: string) {
  const a = await connectThrough(port, target, auth);
  if (a.status === 200) await new Promise((r) => { a.socket.once("data", r); a.socket.write("x"); });
  a.socket.end();
  const file = join(fx.receiptsDir, `${a.headers[RECEIPT_HEADER]}.json`);
  for (let i = 0; i < 200; i++) {
    try { readFileSync(file); break; } catch { await new Promise((r) => setTimeout(r, 25)); }
  }
  return a.status;
}
async function witness(fx: EgressFixture) {
  const host = await createEgressHost(loadEgressConfig(fx.configFile));
  const running = await serveEgress(host, { port: 0, log: () => {} });
  return { port: Number(new URL(running.url).port), async stop() { await host.close(); await running.close(); } };
}

// Stand-ins on this machine: a documentation mirror the agent needs, and a paste site it should never have reached.
const docs = await startEcho();
const paste = await startEcho();
const DOCS = `127.0.0.1:${docs.port}`;
const PASTE = `127.0.0.1:${paste.port}`;

step(1, `the witness in observe mode, under a policy that permits nothing: it relays every verified connection and receipts it`);
const fx = buildEgressFixture(out("42-egress-draft"), { mode: "observe" }, "forbid(principal, action, resource);\n");
const observing = await witness(fx);
for (const target of [DOCS, DOCS, DOCS, PASTE]) console.log(`   ${EGRESS_AGENT} -> ${target === DOCS ? "docs mirror" : "paste site "} ${target}: HTTP ${await visit(fx, observing.port, target)}`);
await observing.stop();

step(2, "agent-custody egress draft-policy --receipts receipts --issuer-key keys/egress.pub: every receipt is verified first");
const draft = draftEgressPolicy(fx.receiptsDir, { issuerKeys: [loadPublicKey(fx.witnessPub)], logFile: fx.logFile });
console.log(draft.policy.trimEnd().split("\n").map((l) => "   " + l).join("\n"));

step(3, "the review: the paste site is in the draft, because the agent went there. The reviewer deletes that line");
const reviewed = draft.policy.split("\n").filter((l) => !l.includes(`"${PASTE}"`)).join("\n").replace(`"${DOCS}",`, `"${DOCS}"`);
writeFileSync(join(fx.dir, "policy.cedar"), reviewed);
console.log(`   removed Action::"${PASTE}"; policy.cedar now permits ${EGRESS_AGENT} the docs mirror only`);

step(4, `"mode": "enforce" with the reviewed policy`);
writeFileSync(fx.configFile, JSON.stringify({ ...JSON.parse(readFileSync(fx.configFile, "utf8")), mode: "enforce" }, null, 2));
const enforcing = await witness(fx);
const toDocs = await visit(fx, enforcing.port, DOCS);
const toPaste = await visit(fx, enforcing.port, PASTE);
console.log(`   docs mirror: HTTP ${toDocs}; paste site: HTTP ${toPaste}, refused and receipted`);
await enforcing.stop();
await docs.close();
await paste.close();

if (!draft.policy.includes(`"${PASTE}"`) || draft.agents.length !== 1 || draft.agents[0]!.destinations.find((d) => d.name === DOCS)?.count !== 3) throw new Error("the draft did not record what the agent did");
if (toDocs !== 200 || toPaste !== 403) throw new Error("the reviewed policy did not allow the docs mirror and refuse the paste site");
console.log("\nOK");
