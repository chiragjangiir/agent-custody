// The witness exists so a verifier does not have to trust the log's operator either. It countersigns a checkpoint
// only after proving it extends the last head it signed; a log that rewrites history, or shows a second history at
// the same size, gets an alarm instead of a signature. Everything here runs in-process: a log with published
// checkpoints, a static server for them, and a witness pointed at both.
import { createServer, type Server } from "node:http";
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { dirCheckpoints } from "../src/checkpoints.ts";
import { dsseSign, dsseVerifiers, generateKeyPair, loadPublicKey, writeKeyPair, type Envelope } from "../src/crypto.ts";
import { CheckpointPublisher, fileResolver, serveLog, type RunningLog } from "../src/log-sink.ts";
import { TREEHEAD_TYPE } from "../src/receipt.ts";
import { localSigner } from "../src/signer.ts";
import { auditExtends } from "../src/verify.ts";
import { fetchWitnessKeys, Witness } from "../src/witness.ts";

/** The witness's fetch: refuses a call that carries no abort signal, because every outbound fetch needs a timeout. */
const timedFetch: typeof fetch = async (input, init) => {
  if (!(init?.signal instanceof AbortSignal)) throw new Error(`fetch without a timeout signal: ${String(input)}`);
  return fetch(input, init);
};

/** Serves a directory the way the checkpoints host does. */
function staticHost(dir: string): Promise<{ server: Server; url: string }> {
  const server = createServer((req, res) => {
    const file = join(dir, decodeURIComponent(new URL(req.url ?? "/", "http://x").pathname));
    if (!existsSync(file)) {
      res.writeHead(404);
      return res.end();
    }
    try {
      const body = readFileSync(file);
      res.writeHead(200, { "content-type": extname(file) === ".json" ? "application/json" : "text/plain" });
      res.end(body);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${(server.address() as { port: number }).port}/` })));
}

describe("the witness", () => {
  let dir: string;
  let log: RunningLog;
  let host: { server: Server; url: string };
  let publisher: CheckpointPublisher;
  let logKp: { keyFile: string; pubFile: string };
  let witnessKp: { keyFile: string; pubFile: string };
  let witness: Witness;
  const cpDir = () => join(dir, "checkpoints");
  const post = (leaf: string) => fetch(new URL("append", log.url), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ leaf }) });
  const witnessed = (name = "latest.json") => JSON.parse(readFileSync(join(dir, "witness", "default", name), "utf8")) as { treeSize: number; envelope: Envelope; witness: { keyid: string } };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "witness-"));
    logKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "log");
    witnessKp = writeKeyPair(generateKeyPair(), join(dir, "keys"), "witness");
    const { loadPrivateKey } = await import("../src/crypto.ts");
    const signer = localSigner(loadPrivateKey(logKp.keyFile));
    const store = dirCheckpoints(cpDir());
    const resolver = fileResolver(join(dir, "log.jsonl"), { logId: "watched-log" });
    log = await serveLog(resolver, signer, { port: 0, checkpoints: store });
    publisher = new CheckpointPublisher(resolver, signer, store, 60_000);
    host = await staticHost(cpDir());
    witness = new Witness({ logUrl: log.url, checkpointsUrl: host.url, tenants: ["default"], key: loadPrivateKey(witnessKp.keyFile), outDir: join(dir, "witness"), fetch: timedFetch, warn: () => {} });
  });
  afterAll(async () => {
    await log.close();
    host.server.close();
  });

  it("publishes its own key document, waits while there is nothing to sign, then countersigns the first checkpoint", async () => {
    const keys = (JSON.parse(readFileSync(join(dir, "witness", ".well-known", "agent-custody-witness.json"), "utf8")) as { keys: { keyid: string }[] }).keys;
    expect(keys[0]?.keyid).toBe(loadPublicKey(witnessKp.pubFile).keyid);
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "unavailable", reason: "no checkpoint published yet" }]);
    await post("a");
    await post("b");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 2 }]);
    const w = witnessed();
    expect(w.treeSize).toBe(2);
    expect(w.envelope.signatures.map((s) => s.keyid).sort()).toEqual([loadPublicKey(logKp.pubFile).keyid, loadPublicKey(witnessKp.pubFile).keyid].sort());
    expect(dsseVerifiers(w.envelope, [loadPublicKey(logKp.pubFile), loadPublicKey(witnessKp.pubFile)])).toHaveLength(2);
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "unchanged", treeSize: 2 }]);
  });

  it("countersigns a later checkpoint only after the log proves it extends the earlier one, and an audit can require the witness", async () => {
    await post("c");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 3 }]);
    const older = witnessed("2.json").envelope;
    const newer = witnessed("3.json").envelope;
    const proof = (await (await fetch(new URL("consistency?old=2&new=3", log.url))).json()) as { hashes: string[] };
    const keys = [loadPublicKey(logKp.pubFile)];
    const both = auditExtends(older, newer, proof.hashes, keys, "watched-log", { witnessKeys: [loadPublicKey(witnessKp.pubFile)] });
    expect(both.checks.filter((c) => !c.ok)).toEqual([]);
    expect(both.checks.map((c) => c.name)).toContain("newer tree head countersigned by a witness");
    // the log's own checkpoint, without the witness's signature, fails a verifier who requires one
    const unwitnessed = (JSON.parse(readFileSync(join(cpDir(), "default", "3.json"), "utf8")) as { envelope: Envelope }).envelope;
    const alone = auditExtends(older, unwitnessed, proof.hashes, keys, "watched-log", { witnessKeys: [loadPublicKey(witnessKp.pubFile)] });
    expect(alone.checks.filter((c) => !c.ok).map((c) => c.name)).toEqual(["newer tree head countersigned by a witness"]);
    // a verifier fetches the witness's keys from its host, the way it fetches the log's
    const wHost = await staticHost(join(dir, "witness"));
    try {
      expect((await fetchWitnessKeys(wHost.url, timedFetch)).map((k) => k.keyid)).toEqual([loadPublicKey(witnessKp.pubFile).keyid]);
    } finally {
      wHost.server.close();
    }
  });

  it("a second history at the same size, a rewritten history, and a stranger's key each get an alarm and no signature; the last good head is kept", async () => {
    const { loadPrivateKey } = await import("../src/crypto.ts");
    const logKey = loadPrivateKey(logKp.keyFile);
    const publish = (treeSize: number, rootHash: string, key = logKey) =>
      writeFileSync(join(cpDir(), "default", "latest.json"), JSON.stringify({ tenant: "default", logId: "watched-log", treeSize, rootHash, signedAt: "t", envelope: dsseSign(TREEHEAD_TYPE, { treeSize, rootHash, timestamp: "t", log: "watched-log" }, key) }));
    // same size, different root: the log is showing two histories
    publish(3, "ee".repeat(32));
    const [split] = await witness.runOnce();
    expect(split).toMatchObject({ tenant: "default", outcome: "refused" });
    expect((split as { reason: string }).reason).toMatch(/two histories/);
    expect(existsSync(join(dir, "witness", "default", "ALARM.json"))).toBe(true);
    // the log grows to 4 honestly, but the published checkpoint at 4 carries a root that is not the log's: the proof from the log refutes it
    await post("d");
    publish(4, "ff".repeat(32));
    const [rewritten] = await witness.runOnce();
    expect(rewritten).toMatchObject({ outcome: "refused" });
    expect((rewritten as { reason: string }).reason).toMatch(/does not extend|history was rewritten/);
    expect(existsSync(join(dir, "witness", "default", "4.json"))).toBe(false);
    expect(witnessed().treeSize).toBe(3);
    // a checkpoint signed by a key the log does not publish is refused too
    publish(4, "aa".repeat(32), generateKeyPair());
    const [stranger] = await witness.runOnce();
    expect(stranger).toMatchObject({ outcome: "refused" });
    expect((stranger as { reason: string }).reason).toMatch(/published keys/);
    // the honest log carries on: the next real checkpoint extends the last good head and is countersigned
    await post("e");
    await publisher.publishOnce();
    expect(await witness.runOnce()).toEqual([{ tenant: "default", outcome: "countersigned", treeSize: 5 }]);
    expect(readdirSync(join(dir, "witness", "default")).filter((n) => n.startsWith("ALARM-")).length).toBe(3);
  });
});
