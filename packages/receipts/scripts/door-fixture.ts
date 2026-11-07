// A complete working directory for the door: keys, a principal whose grants are passports, a policy for a small shop's
// API, a config pointed at an origin, and a stand-in origin that echoes what reached it. Shared by the test, the
// tutorial, and the conformance vectors.
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { generateKeyPair, writeKeyPair, type KeyPair } from "../src/crypto.ts";

/**
 * Anyone may read the catalogue. A refund is for a verified agent, a positive amount up to £50 (5000 pence); an unknown or claimed
 * arrival gets no refund. Anything else at the API is for verified agents only. The arrival fact is the door's own.
 */
export const DOOR_POLICY = `// The catalogue is public: humans, agents, anyone.
permit(principal, action == Action::"catalogue", resource);

// Refunds: a verified agent, in its grant's scope, for a positive amount of at most £50.
permit(principal, action == Action::"refund", resource)
when {
  context.facts.arrival.class == "verified" &&
  context.args.body.amount > 0 &&
  context.args.body.amount <= 5000
};

// Everything else on the API is for verified agents.
permit(principal, action == Action::"api", resource)
when { context.facts.arrival.class == "verified" };
`;

export interface DoorFixture {
  dir: string;
  configFile: string;
  doorPub: string;
  principalPub: string;
  principalKey: KeyPair;
  receiptsDir: string;
  logFile: string;
}

export function buildDoorFixture(dir: string, originUrl: string, extra: Record<string, unknown> = {}): DoorFixture {
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  const door = writeKeyPair(generateKeyPair(), join(dir, "keys"), "door");
  const principalKey = generateKeyPair();
  const principal = writeKeyPair(principalKey, join(dir, "keys"), "principal");
  writeFileSync(join(dir, "policy.cedar"), DOOR_POLICY);
  const config = {
    identity: { keyFile: "keys/door.key" },
    origin: { url: originUrl },
    routes: [
      { name: "catalogue", methods: ["GET"], path: "/catalogue/*" },
      { name: "refund", methods: ["POST"], path: "/refunds" },
      { name: "api", path: "/api/*" },
    ],
    trustedPrincipalKeys: ["keys/principal.pub"],
    policyFile: "policy.cedar",
    receiptsDir: "receipts",
    logFile: "log.jsonl",
    // the tests, the example, and the vectors read the arguments; a door config without a rule withholds the query and the body
    capture: { "*": { args: { mode: "clear" } } },
    ...extra,
  };
  const configFile = join(dir, "door.json");
  writeFileSync(configFile, JSON.stringify(config, null, 2));
  return { dir, configFile, doorPub: door.pubFile, principalPub: principal.pubFile, principalKey, receiptsDir: join(dir, "receipts"), logFile: join(dir, "log.jsonl") };
}

export interface Origin {
  url: string;
  /** every request that reached the origin: method, path, the headers it saw, the body */
  seen: { method: string; path: string; headers: Record<string, string | string[] | undefined>; body: string }[];
  close(): Promise<void>;
}

/** The site behind the door: answers 200 with a JSON echo, 404 when the path contains /missing, 500 when it contains /broken, a 302 to its own /catalogue/after when it contains /redirect, and two cookies when it contains /cookies. */
export function startOrigin(): Promise<Origin> {
  const seen: Origin["seen"] = [];
  const server: Server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const body = Buffer.concat(chunks).toString("utf8");
      seen.push({ method: req.method ?? "", path: req.url ?? "", headers: req.headers, body });
      if (req.url?.includes("/redirect")) {
        res.writeHead(302, { location: `http://127.0.0.1:${(server.address() as AddressInfo).port}/catalogue/after?from=redirect`, "x-origin": "shop" });
        res.end();
        return;
      }
      const status = req.url?.includes("/missing") ? 404 : req.url?.includes("/broken") ? 500 : 200;
      res.writeHead(status, { "content-type": "application/json", "x-origin": "shop", ...(req.url?.includes("/cookies") ? { "set-cookie": ["session=1; HttpOnly", "csrf=2"] } : {}) });
      res.end(JSON.stringify({ ok: status === 200, method: req.method, path: req.url, body: body ? JSON.parse(body) : null }));
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve({ url: `http://127.0.0.1:${port}`, seen, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) });
    });
  });
}
