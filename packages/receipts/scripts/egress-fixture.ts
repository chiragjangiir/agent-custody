// A complete working directory for the egress witness: its key, a policy, a config with one agent whose proxy secret is
// in the environment, and a stand-in destination on this machine. Shared by the test, the tutorial, and the vectors.
import { connect, createServer, type Server, type Socket } from "node:net";
import type { AddressInfo } from "node:net";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair, writeKeyPair } from "../src/crypto.ts";

/** The test values of the fixture's agent: published on purpose, never a real credential. */
export const EGRESS_AGENT = "research-agent";
export const EGRESS_SECRET_ENV = "EGRESS_FIXTURE_RESEARCH_SECRET";
export const EGRESS_SECRET = "fixture-secret-not-a-real-credential";

/**
 * The research agent may reach the documentation mirror, a stand-in on this machine. Nothing permits a payment provider:
 * payments go through the gateway, which holds the provider's key, so a direct call to one is refused here.
 */
export const EGRESS_POLICY = `// The research agent may reach the documentation mirror on this machine.
permit(principal == Agent::"${EGRESS_AGENT}", action, resource)
when { context.facts.destination.host == "127.0.0.1" };

// No rule permits api.stripe.com: payments go through the gateway, which holds the Stripe key.
`;

export interface EgressFixture {
  dir: string;
  configFile: string;
  witnessPub: string;
  receiptsDir: string;
  logFile: string;
}

export function buildEgressFixture(dir: string, extra: Record<string, unknown> = {}, policy = EGRESS_POLICY): EgressFixture {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const witness = writeKeyPair(generateKeyPair(), join(dir, "keys"), "egress");
  // a policyFile in extra names the file the policy is written to, so a .rego name holds a Rego policy
  writeFileSync(join(dir, typeof extra.policyFile === "string" ? extra.policyFile : "policy.cedar"), policy);
  process.env[EGRESS_SECRET_ENV] = EGRESS_SECRET;
  const config = {
    identity: { keyFile: "keys/egress.key" },
    agents: [{ id: EGRESS_AGENT, secretEnv: EGRESS_SECRET_ENV }],
    policyFile: "policy.cedar",
    receiptsDir: "receipts",
    logFile: "log.jsonl",
    ...extra,
  };
  const configFile = join(dir, "egress.json");
  writeFileSync(configFile, JSON.stringify(config, null, 2));
  return { dir, configFile, witnessPub: witness.pubFile, receiptsDir: join(dir, "receipts"), logFile: join(dir, "log.jsonl") };
}

/** `Proxy-Authorization` for an agent id and secret. */
export const proxyAuth = (id: string, secret: string) => `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`;

export interface EchoServer {
  port: number;
  close(): Promise<void>;
}

/** A TCP destination that answers every chunk with `echo:` and the chunk: what a tunnel carries is the agent's business. */
export function startEcho(): Promise<EchoServer> {
  const sockets = new Set<Socket>();
  const server: Server = createServer((s) => {
    sockets.add(s);
    s.on("close", () => sockets.delete(s));
    s.on("error", () => undefined);
    s.on("data", (c) => s.write(`echo:${c.toString()}`));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve({
    port: (server.address() as AddressInfo).port,
    close: () => new Promise<void>((done) => { for (const s of sockets) s.destroy(); server.close(() => done()); }),
  })));
}

export interface ConnectAnswer {
  status: number;
  headers: Record<string, string>;
  body: string;
  /** the tunnel, open when status is 200 */
  socket: Socket;
}

/** Sends `CONNECT target` to the witness, as an HTTP client configured with HTTPS_PROXY would, and reads its answer. */
export function connectThrough(proxyPort: number, target: string, auth?: string): Promise<ConnectAnswer> {
  return new Promise((resolve, reject) => {
    const socket = connect(proxyPort, "127.0.0.1");
    let buf = Buffer.alloc(0);
    const onData = (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0) return;
      const lines = buf.subarray(0, end).toString().split("\r\n");
      const status = Number(lines[0]!.split(" ")[1]);
      const headers: Record<string, string> = {};
      for (const l of lines.slice(1)) { const i = l.indexOf(":"); headers[l.slice(0, i).trim().toLowerCase()] = l.slice(i + 1).trim(); }
      if (status === 200) {
        socket.off("data", onData);
        return resolve({ status, headers, body: buf.subarray(end + 4).toString(), socket });
      }
      const length = Number(headers["content-length"] ?? 0);
      if (buf.length - end - 4 < length) return;
      socket.off("data", onData);
      resolve({ status, headers, body: buf.subarray(end + 4, end + 4 + length).toString(), socket });
    };
    socket.on("data", onData);
    socket.on("error", reject);
    socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n${auth ? `Proxy-Authorization: ${auth}\r\n` : ""}\r\n`);
  });
}
