#!/usr/bin/env node
import { hostname, userInfo } from "node:os";
import { captureKeyFrom, getAt, pathText, restorePaths, setAt } from "./capture.ts";
import { saltsFileFor } from "./retention.ts";
import { isProviderAttestation } from "./upstream.ts";
import { parseArgs } from "node:util";
import { closeSync, constants as fsConstants, existsSync, fchmodSync, openSync, readFileSync, readdirSync, writeFileSync, writeSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { loadConfig, loadSdkConfig, type A2aUpstreamConfig } from "./config.ts";
import { dsseVerify, generateKeyPair, loadPrivateKey, loadPublicKey, writeKeyPair } from "./crypto.ts";
import type { Envelope } from "./crypto.ts";
import { createDelegation, decodeDelegation, delegateFrom, grantDigest } from "./delegation.ts";
import { createGateway, createGatewayHost, serveStdio, writeRevokedGrants } from "./gateway.ts";
import { postgresResolver, serveLog } from "./log-sink.ts";
import { importLogFile, PostgresTenancy, type PostgresLike, type Plan } from "./log-store.ts";
import { bothCheckpoints, dirCheckpoints, postgresCheckpoints, type CheckpointStore } from "./checkpoints.ts";
import { connectSigner, fetchLogKeys, localSigner, serveSigner, type RetiredKey, type Signer } from "./signer.ts";
import { fetchWitnessKeys, Witness } from "./witness.ts";
import { checkLog, formatLogCheck } from "./log-check.ts";
import { Anchor, ANCHOR_CHAINS, resolveAnchorChain } from "./anchor.ts";
import { checkCompleteness, formatCompleteness, stripeSource, type StripeObject } from "./completeness.ts";
import { evmChain } from "./anchor-evm.ts";
import { serveHttp } from "./gateway-http.ts";
import { serveA2a } from "./a2a.ts";
import { PortalStore, sendFollowUps, servePortal, type MailOptions, type OAuthOptions, type Role, type StripeOptions } from "./portal.ts";
import type { OidcConfig, SamlConfig } from "./sso.ts";
import { exportLog, formatExport } from "./log-export.ts";
import { CheckpointPublisher, fileResolver, type LogResolver } from "./log-sink.ts";
import type { AdminOptions } from "./log-admin.ts";
import { createRequire } from "node:module";
import { pruneLog } from "./retention.ts";
import { serveSidecar } from "./sidecar.ts";
import { checkConfig, formatFindings } from "./check.ts";
import { serveConsole } from "./console.ts";
import { TREEHEAD_TYPE, type AuthorizationBundle, type ReceiptBundle, type TreeHead, type ReceiptStatement } from "./receipt.ts";
import { MerkleLog } from "./log.ts";
import { createSdkIssuer } from "./sdk/index.ts";
import { initClaudeCode } from "./claude-init.ts";
import { denyReport, formatDenyReport } from "./deny-report.ts";
import { fileURLToPath } from "node:url";
import { handleHookEvent, type HookInput } from "./sdk/claude.ts";
import { auditExtends, formatReport, verifyBundle, type VerifyOptions } from "./verify.ts";
import { CLEAR_WARNING, exportReceipts, formatReceiptExport as formatExportLines } from "./export.ts";
import { formatSummaryMarkdown, receiptFiles, summarizeReceipts } from "./pr-summary.ts";
import { formatSimulation, simulatePolicy, verifyOrphanAuthorization, type SimulationSkip } from "./simulate.ts";

/**
 * Resolves on SIGINT or SIGTERM: a container runtime and systemd stop a service with SIGTERM, which PID 1 ignores unless
 * it is handled. The handlers are installed once, before a service starts, so a signal that arrives while it starts up
 * is kept and the service closes as soon as it is running.
 */
let stopped: Promise<void> | undefined;
function untilStopped(): Promise<void> {
  stopped ??= new Promise<void>((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
  return stopped;
}
const SERVICES = new Set(["serve", "witness", "signer", "portal", "log", "console"]);
/** a command that waits for untilStopped(); a stdio gateway runs until its input closes and keeps the default signal behaviour */
const runsUntilStopped = (cmd: string | undefined, args: string[]) => !!cmd && (SERVICES.has(cmd) || (cmd === "gateway" && (args.includes("--http") || args.includes("--a2a"))));

/** A secret kept in a file that only this process can read, such as a container secret mounted at /run/secrets. The file's path is not a secret; its contents are. */
function tokenFromFile(path: string): string {
  const v = readFileSync(path, "utf8").trim();
  if (!v) throw new Error(`${path} is empty`);
  return v;
}

/** A shared secret from an environment variable; never from the command line, where it would land in shell history. */
function secretFrom(envName: string): string {
  const v = process.env[envName];
  if (!v) throw new Error(`environment variable ${envName} is not set`);
  return v;
}

const USAGE = `agent-custody <command>

  keygen  --dir <dir> --name <name>
  grant   --key <principal.key> --principal <id> --agent <id> --scopes <a,b> [--ttl-hours 24] [--agent-key <agent.pub>] --out <file>
                                                   --agent-key names the agent's own key in the grant, so the agent may delegate
  delegate --key <agent.key> --parent <grant.json> --agent <sub-agent> --scopes <a,b> [--ttl-hours N] [--agent-key <sub.pub>] --out <file>
                                                   a narrower grant for a sub-agent, signed by the agent the parent names; the parent travels inside
  reveal <bundle> --capture-key-env NAME --issuer-key <pub> [--out <file>] [--include-salts]   the values a receipt withheld (capture mode encrypted), as a disclosure file
                                                   for verify --disclose; needs the customer's capture key
  revoke --config <gateway.json> --grant <grant.json>     revokes a grant: its digest goes into the config's revokedGrants file, every
                                                   session under it or under a grant delegated from it refuses its next call, and no new session opens for them
  reconcile --config <gateway.json> --operation <uuid>   operator-only provider lookup; commits a receipt before closing an unknown/pending financial operation
  console --config <gateway.json> [--port 8795] [--host 127.0.0.1] [--token-env CONSOLE_TOKEN | --token-file <path>] [--gateway-url <url>] [--state-dir <dir>]
                                                   the admin console for a gateway: its config and tools, a config check, receipts with a verdict each, a policy editor that
                                                   validates and replays recorded calls before it saves, grant inspection and revocation, and an audit trail of its own changes.
                                                   A separate service from the gateway, behind a token read from the environment; it holds no principal key and never signs
  check   --config <gateway.json> [--connect] [--json]
                                                   what the gateway would fail on at startup, found before it starts: the config and its unknown keys, the keys,
                                                   the Cedar policy, the grant, credential variables, stdio commands, and writable paths. --connect also starts the
                                                   upstreams (tool-name collisions, unreachable servers) and checks every tool name the config and grant mention. Exits 1 on an error
  gateway --config <gateway.json> [--http [--port 8790] [--host 127.0.0.1] [--idle-minutes 30]]
                                                   stdio: one gateway for the grant the config names. --http: one shared gateway, MCP over
                                                   Streamable HTTP at /mcp, each connection presenting its own grant as Authorization: Bearer
  init claude-code [--dir <dir>] [--user] [--enforce] [--log-url <url> [--log-id <id>] [--log-token-env NAME] [--log-key <pub>]]
                                                   one command for your own Claude Code sessions: an agent key, sdk.json in observe mode, a starter deny
                                                   policy, and the three hooks in .claude/settings.local.json (--user: ~/.claude/settings.json). Safe to run twice
  report  --config <sdk.json>                      the calls that the policy would have denied, from the receipts: tool, command or path, rule, receipt id;
                                                   a receipt that does not verify is counted apart. Exits 1 when any receipt does not verify
  hook    [--config <sdk.json>]        Claude Code hook command; reads the event on stdin (or AGENT_CUSTODY_CONFIG)
  serve   --config <sdk.json> [--port 8788] [--host 127.0.0.1]   the SDK as a local HTTP API for agents in other languages
  prune   --log <log.jsonl> --before <ISO instant> [--receipts <dir>]
          retention on the receipt log: replaces older leaves with their hashes, so proofs still verify and the content is gone
  log     --file <log.jsonl> --key <log.key> [--port 8787] [--host 127.0.0.1] [--token-env <NAME>]   reference log server
  verify  <bundle.json> --issuer-key <pub> [--principal-key <pub>] [--approval-key <pub>] [--log-key <pub> | --log-url <url>] [--log-id <id>] [--require-strict] [--upstream-key <pub>] [--stripe-secret-env NAME] [--github-secret-env NAME] [--log <log.jsonl>] [--disclose <file>] [--capture-key-env NAME] [--json]
          verify --markdown <dir|bundle.json>... --issuer-key <pub>   one Markdown table for a directory of bundles; exit 1 when one does not verify or none exists
  export  --receipts <dir> --out <dir> --issuer-key <pub>... [--principal-key <pub>]... [--approval-key <pub>]... [--since <ISO time>] [--allow-clear]
                                                   copies the verified receipt bundles that keep their values private into a directory for a pull request, byte for byte.
                                                   Reads only <id>.json at the top level; never salts/, outbox/, or *.authorization.json. Exits 1 when it refuses a receipt, and when it copies none
  policy simulate --policy <proposed.cedar> --receipts <dir> --issuer-key <pub>... [--principal-key <pub>]... [--approval-key <pub>]... [--log-key <pub>]... [--json] [--out <file>]
  completeness --receipts <dir> --issuer-key <pub>... [--principal-key <pub>]... [--log-key <pub>]... [--log <log.jsonl>] [--log-id <id>]
               --provider stripe --object refunds|payouts|transfers --key-env NAME --tool <name>... --since <ISO> --until <ISO>
               [--id-path id] [--amount-field amount] [--currency-field currency] [--beneficiary <arg>=<field>]... [--json]
                                                 for an auditor: lists the provider's objects in the window with a read-only key, and
                                                 matches each to a verified receipt by the provider's object id; reports actions with no
                                                 receipt, receipts the provider does not have, and mismatched amounts; exits 1 unless complete
                                                   replay verified local receipts against a proposed policy using their recorded inputs;
                                                   --out saves the full JSON report. Exits 1 when any call could not be evaluated.
  log     ... --db-env NAME                     the same server over Postgres: tenants and tokens from the database, one writer per tenant,
                                                 root paths serve the tenant "default" (created with --log-id). Needs the pg package.
  log     ... (--key <log.key> [--retired-key <pub>]... | --signer-url <url> [--signer-token-env NAME]) [--checkpoint-dir <dir>] [--checkpoint-every <seconds>] [--checkpoint-heartbeat <seconds>]
                                                 sign with a key in this process, or through a signer process that holds it; publish a signed
                                                 checkpoint per log that has grown, every 300 s by default, to the directory (and, with a
                                                 database, to its heads table); serve the key document at /.well-known/agent-custody-log.json
  log     ... [--trust-proxy]                    behind a reverse proxy you run: key per-address limits by the address the proxy appended
  log     ... [--hash-only]                      accept only leaf hashes on append; a log run for other people must never receive a receipt
  log     ... --db-env NAME --admin-token-env NAME [--public-url <https://log.example.com/>] [--checkpoints-url <https://checkpoints.example.com/>]
                                                 the operator's admin page at /admin and its API, behind the admin token: tenants, tokens shown once,
                                                 the welcome sheet; the public URLs fill the sheet in
  log-check --log-url <url> [--checkpoints-url <url>] [--witness-url <url>] [--tenant <name>]... [--max-lag <seconds>]
            [--anchor-url <url> --anchor-address <0x...> --anchor-rpc-env NAME... --anchor-log-id <tenant>=<log id>...
             [--anchor-chain ethereum] [--max-anchor-lag <seconds>]] [--json]
  log-export --log-url <url> [--tenant <name>] --token-env NAME --out <dir> [--month YYYY-MM]... [--json]
                                                   a tenant's own log, with their token: every leaf hash as a log file the verifier
                                                   reads, the signed head, the published keys, the checkpoints, and their usage
                                                 the outside monitor: verifies the head against the published keys, that checkpoints keep up
                                                 with the head and the head extends them, and that the witness countersigns and raises no
                                                 alarm; exits 1 on any failure. Run it from cron or a scheduled workflow elsewhere.
  witness --key <witness.key> --log-url <url> --checkpoints-url <url> --out <dir> [--tenant <name>]... [--every <seconds>] [--once]
                                                 a second signer, run by someone who is not the log's operator: fetches the log's latest
                                                 checkpoint per watched log, proves it extends the last one it signed, and countersigns it
                                                 into <dir>; refuses and writes an alarm otherwise. Serve <dir> from a host of your own.
  anchor  --log-url <url> --checkpoints-url <url> --out <dir> --rpc-url-env NAME --key-env NAME [--tenant <name>]...
          [--chain ethereum|base|arbitrum|optimism|polygon|<chain id>] [--max-fee-gwei <gwei>] [--every <seconds>] [--once]
                                                 anchors the log's checkpoints on an EVM chain, Ethereum by default: proves each new one extends the last one
                                                 anchored, sends one transaction with a Merkle root over them from the key's address,
                                                 and writes each log's record and inclusion proof into <dir>; refuses and writes an alarm
                                                 otherwise. Needs the optional package viem. Serve <dir> read-only.
  signer  --key <log.key> --port 8790 [--host 127.0.0.1] [--token-env NAME] [--retired-key <pub>]...
                                                 the one process that holds the log's key: POST /sign, GET /keys
  log-admin --db-env NAME tenant add <id> [--log-id <id>] | tenant list | tenant disable <id> | tenant plan <id> <free|team|enterprise>
  log-admin --db-env NAME token add <tenant> --label <text> | token list <tenant> | token revoke <tenant> <hash-prefix>
  log-admin --db-env NAME audit [--tenant <id>]   who did what to tenants and tokens, newest first
  log-admin --db-env NAME sso set <tenant> --domains a.com,b.com [--default-role readonly] [--enforce]
            (--oidc-issuer <url> --oidc-client-id <id> --oidc-secret-env NAME | --saml-entry-point <url> --saml-cert <pem file> [--saml-idp-issuer <id>])
  log-admin --db-env NAME sso show <tenant> | sso remove <tenant>   enterprise sign-in through the tenant's own identity provider
  log-admin --db-env NAME user mfa-reset <email>   turns MFA off for a portal account that lost its authenticator
  portal  --db-env NAME --secret-env NAME --public-url <log url> [--checkpoints-url <url>] [--portal-url <url>] [--port 8792] [--host 127.0.0.1]
          [--stripe-key-env NAME --stripe-webhook-env NAME --stripe-price-team <price id>] [--trust-proxy]
                                                   the tenant portal: register, first key, usage against plan, keys, billing, export
  log-admin --db-env NAME import --file <log.jsonl> [--tenant default]      copies a file log into the database as hashes
  portal-followup --db-env NAME --mail-key-env NAME --mail-from <address> [--mail-notify <address>] [--portal-url <url>] [--dry-run]
                                                   the founder's note to registrations an hour to a week old that have not had it; hourly from cron
  audit   --older <bundle.json> --newer <bundle.json> (--log <log.jsonl> | --log-url <url>) [--issuer-key <pub>] [--log-key <pub>] [--log-id <id>] [--witness-key <pub> | --witness-url <url>] [--json]
                                                 with --log-url the log's published keys are fetched and pinned by keyid; with a witness key or
                                                 URL the newer head must also carry the witness's countersignature
          checks that the newer receipt's log extends the older one's: nothing between them was rewritten
`;

/** A retired public key for the key document, from a .pub file; still listed so heads it signed keep verifying. */
function retiredKey(pubFile: string): RetiredKey {
  return { key: loadPublicKey(pubFile), pem: readFileSync(pubFile, "utf8") };
}

/** A pg Pool from the URL in an environment variable. pg is an optional peer: it is loaded only here, and its absence says what to install. */
function openPostgres(envName: string): PostgresLike {
  const url = process.env[envName];
  if (!url) throw new Error(`environment variable ${envName} is not set`);
  let Pool: new (o: { connectionString: string }) => PostgresLike;
  try {
    ({ Pool } = createRequire(import.meta.url)("pg") as { Pool: typeof Pool });
  } catch {
    throw new Error("a Postgres log needs the pg package: npm install pg");
  }
  return new Pool({ connectionString: url });
}

/** The tenants file for `log --tenants`: paths relative to the file, tokens from the environment, ids default to the tenant name. */
function loadTenants(path: string): Record<string, { file: string; tokens?: string[]; logId?: string }> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as Record<string, { file: string; tokenEnv?: string; logId?: string }>;
  const out: Record<string, { file: string; tokens?: string[]; logId?: string }> = {};
  for (const [name, t] of Object.entries(raw)) {
    if (!/^[A-Za-z0-9_.-]+$/.test(name) || typeof t?.file !== "string") throw new Error(`tenants: "${name}" needs a file, and its name must be a plain identifier`);
    const token = t.tokenEnv ? process.env[t.tokenEnv] : undefined;
    if (t.tokenEnv && !token) throw new Error(`tenants: environment variable ${t.tokenEnv} for "${name}" is not set`);
    out[name] = { file: resolve(dirname(resolve(path)), t.file), ...(token ? { tokens: [token] } : {}), ...(t.logId ? { logId: t.logId } : {}) };
  }
  return out;
}

async function main(argv: string[]): Promise<number> {
  const [cmd, ...rest] = argv;
  if (runsUntilStopped(cmd, rest)) void untilStopped();
  switch (cmd) {
    case "reconcile": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, operation: { type: "string" } } });
      if (!values.config || !values.operation) throw new Error("reconcile needs --config and --operation");
      const cfg = loadConfig(values.config);
      const host = await createGatewayHost(cfg);
      try {
        const bundle = await host.reconcile(values.operation);
        const p = (JSON.parse(Buffer.from(bundle.envelope.payload, "base64").toString("utf8")) as ReceiptStatement).predicate;
        console.log(JSON.stringify({ operation: values.operation, status: p.operation!.status, receipt: join(cfg.receiptsDir, `${p.receiptId}.json`) }));
        return 0;
      } finally { await host.close(); }
    }
    case "keygen": {
      const { values } = parseArgs({ args: rest, options: { dir: { type: "string" }, name: { type: "string" } } });
      if (!values.dir || !values.name) throw new Error("keygen needs --dir and --name");
      const kp = generateKeyPair();
      const files = writeKeyPair(kp, values.dir, values.name);
      console.log(`keyid ${kp.keyid}\nprivate ${files.keyFile}\npublic  ${files.pubFile}`);
      return 0;
    }
    case "grant": {
      const { values } = parseArgs({
        args: rest,
        options: {
          key: { type: "string" },
          principal: { type: "string" },
          agent: { type: "string" },
          scopes: { type: "string" },
          "ttl-hours": { type: "string", default: "24" },
          "agent-key": { type: "string" },
          out: { type: "string" },
        },
      });
      if (!values.key || !values.principal || !values.agent || !values.scopes || !values.out) throw new Error("grant needs --key --principal --agent --scopes --out");
      const now = Date.now();
      const env = createDelegation(loadPrivateKey(values.key), {
        version: "0.1",
        principal: values.principal,
        agent: values.agent,
        scopes: values.scopes.split(",").map((s) => s.trim()).filter(Boolean),
        issuedAt: new Date(now).toISOString(),
        expiresAt: new Date(now + Number(values["ttl-hours"]) * 3600_000).toISOString(),
        ...(values["agent-key"] ? { agentKey: readFileSync(values["agent-key"], "utf8") } : {}),
      });
      writeFileSync(values.out, JSON.stringify(env, null, 2));
      console.log(`wrote ${values.out}`);
      return 0;
    }
    case "delegate": {
      const { values } = parseArgs({ args: rest, options: { key: { type: "string" }, parent: { type: "string" }, agent: { type: "string" }, scopes: { type: "string" }, "ttl-hours": { type: "string" }, "agent-key": { type: "string" }, out: { type: "string" } } });
      if (!values.key || !values.parent || !values.agent || !values.scopes || !values.out) throw new Error("delegate needs --key --parent --agent --scopes --out");
      const parent = JSON.parse(readFileSync(values.parent, "utf8")) as Envelope;
      const env = delegateFrom(parent, loadPrivateKey(values.key), {
        agent: values.agent,
        scopes: values.scopes.split(",").map((s) => s.trim()).filter(Boolean),
        ...(values["ttl-hours"] ? { expiresAt: new Date(Date.now() + Number(values["ttl-hours"]) * 3600_000).toISOString() } : {}),
        ...(values["agent-key"] ? { agentKey: readFileSync(values["agent-key"], "utf8") } : {}),
      });
      writeFileSync(values.out, JSON.stringify(env, null, 2));
      const chain = decodeDelegation(env)!;
      console.log(`delegated to ${chain.agent}: scopes [${chain.scopes.join(", ")}] until ${chain.expiresAt}, under ${decodeDelegation(parent)!.agent}'s grant from ${chain.principal}`);
      return 0;
    }
    case "console": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, port: { type: "string", default: "8795" }, host: { type: "string", default: "127.0.0.1" }, "token-env": { type: "string", default: "CONSOLE_TOKEN" }, "token-file": { type: "string" }, "gateway-url": { type: "string" }, "state-dir": { type: "string" } } });
      if (!values.config) throw new Error("console needs --config");
      const running = await serveConsole({ configFile: values.config, token: values["token-file"] ? tokenFromFile(values["token-file"]) : secretFrom(values["token-env"]), port: Number(values.port), host: values.host, ...(values["gateway-url"] ? { gatewayUrl: values["gateway-url"] } : {}), ...(values["state-dir"] ? { stateDir: values["state-dir"] } : {}) });
      console.error(`agent-custody console: ${running.url} config=${values.config}${values.host === "0.0.0.0" || (values.host !== "127.0.0.1" && values.host !== "localhost") ? " (reachable beyond this host: put TLS in front and limit who can reach it)" : ""}`);
      await untilStopped();
      await running.close();
      return 0;
    }
    case "check": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, connect: { type: "boolean", default: false }, json: { type: "boolean", default: false } } });
      if (!values.config) throw new Error("check needs --config");
      const findings = await checkConfig(values.config, { connect: values.connect });
      console.log(values.json ? JSON.stringify(findings, null, 2) : formatFindings(findings));
      return findings.some((f) => f.level === "error") ? 1 : 0;
    }
    case "revoke": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, grant: { type: "string" } } });
      if (!values.config || !values.grant) throw new Error("revoke needs --config and --grant");
      const cfg = loadConfig(values.config);
      if (!cfg.revokedGrants) throw new Error("revoke needs revokedGrants in the config: the file the gateway re-reads on every call");
      const envelope = JSON.parse(readFileSync(values.grant, "utf8")) as Envelope;
      const chain = decodeDelegation(envelope);
      if (!chain) throw new Error(`${values.grant} is not a delegation grant`);
      const digest = grantDigest(envelope);
      const list = existsSync(cfg.revokedGrants) ? (JSON.parse(readFileSync(cfg.revokedGrants, "utf8")) as string[]) : [];
      if (!list.includes(digest)) writeRevokedGrants(cfg.revokedGrants, [...list, digest]);
      console.log(`revoked ${chain.agent}'s grant from ${chain.principal} (${digest.slice(0, 12)}…): ${cfg.revokedGrants} now lists ${list.includes(digest) ? list.length : list.length + 1} grant(s); a running gateway refuses it on its next call`);
      return 0;
    }
    case "gateway": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, http: { type: "boolean", default: false }, a2a: { type: "boolean", default: false }, port: { type: "string", default: "8790" }, host: { type: "string", default: "127.0.0.1" }, "idle-minutes": { type: "string", default: "30" } } });
      if (!values.config) throw new Error("gateway needs --config");
      if (values.a2a) {
        // The gateway as an A2A agent: the config's one A2A upstream is what it fronts; the grant file is the default
        // session, and a request may present its own grant in the same header the HTTP gateway takes.
        const cfg = loadConfig(values.config);
        const candidates = (cfg.upstreams ?? (cfg.upstream ? [cfg.upstream] : [])).filter((u) => "a2a" in u);
        if (candidates.length !== 1) throw new Error("gateway --a2a needs exactly one { a2a: ... } upstream in the config");
        const a2a = (candidates[0] as { a2a: A2aUpstreamConfig }).a2a;
        const host = await createGatewayHost(cfg, { autoFlush: true });
        const grant = cfg.grantFile ? (JSON.parse(readFileSync(cfg.grantFile, "utf8")) as Envelope) : undefined;
        const running = await serveA2a(host, a2a, { port: Number(values.port), host: values.host, ...(grant ? { grant } : {}) });
        console.error(`agent-custody gateway (a2a): ${running.url} keyid=${host.keyid} fronting ${a2a.url} as ${a2a.prefix}.send; card at ${running.url}/.well-known/agent-card.json`);
        await untilStopped();
        await running.close();
        await host.close();
        return 0;
      }
      if (values.http) {
        const host = await createGatewayHost(loadConfig(values.config), { autoFlush: true });
        const running = await serveHttp(host, { port: Number(values.port), host: values.host, idleMs: Number(values["idle-minutes"]) * 60_000 });
        console.error(`agent-custody gateway: ${running.url} keyid=${host.keyid} one session per grant; GET /health`);
        await untilStopped();
        await running.close();
        await host.close();
        return 0;
      }
      const gw = await createGateway(loadConfig(values.config), { autoFlush: true });
      console.error(`agent-custody gateway: agent=${gw.agentId} principal=${gw.delegation.principal} scopes=[${gw.delegation.scopes.join(", ")}]`);
      await serveStdio(gw);
      await gw.close();
      return 0;
    }
    case "init": {
      const [target, ...args] = rest;
      if (target !== "claude-code") throw new Error("init needs a target: init claude-code");
      const { values } = parseArgs({
        args,
        options: {
          dir: { type: "string" },
          user: { type: "boolean", default: false },
          enforce: { type: "boolean", default: false },
          "log-url": { type: "string" },
          "log-id": { type: "string" },
          "log-token-env": { type: "string" },
          "log-key": { type: "string" },
        },
      });
      initClaudeCode({
        cliPath: fileURLToPath(import.meta.url),
        ...(values.dir ? { dir: values.dir } : {}),
        user: values.user,
        enforce: values.enforce,
        ...(values["log-url"] ? { logUrl: values["log-url"] } : {}),
        ...(values["log-id"] ? { logId: values["log-id"] } : {}),
        ...(values["log-token-env"] ? { logTokenEnv: values["log-token-env"] } : {}),
        ...(values["log-key"] ? { logKey: values["log-key"] } : {}),
      });
      return 0;
    }
    case "report": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" } } });
      if (!values.config) throw new Error("report needs --config <sdk.json>");
      const report = denyReport(resolve(values.config));
      console.log(formatDenyReport(report));
      return report.unverified.length ? 1 : 0;
    }
    case "hook": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" } } });
      const configPath = values.config ?? process.env.AGENT_CUSTODY_CONFIG;
      if (!configPath) throw new Error("hook needs --config or AGENT_CUSTODY_CONFIG");
      const input = JSON.parse(readFileSync(0, "utf8")) as HookInput;
      const out = await handleHookEvent(createSdkIssuer(loadSdkConfig(configPath)), input);
      console.log(JSON.stringify(out));
      return 0;
    }
    case "serve": {
      const { values } = parseArgs({ args: rest, options: { config: { type: "string" }, port: { type: "string", default: "8788" }, host: { type: "string", default: "127.0.0.1" } } });
      if (!values.config) throw new Error("serve needs --config");
      const issuer = createSdkIssuer(loadSdkConfig(values.config));
      const running = await serveSidecar(issuer, { port: Number(values.port), host: values.host });
      console.error(`agent-custody serve: ${running.url} agent=${issuer.agentId} keyid=${issuer.keyid} log=${issuer.log.kind}:${issuer.log.where}`);
      await untilStopped();
      await running.close();
      return 0;
    }
    case "log-check": {
      const { values } = parseArgs({ args: rest, options: { "log-url": { type: "string" }, "checkpoints-url": { type: "string" }, "witness-url": { type: "string" }, tenant: { type: "string", multiple: true }, "max-lag": { type: "string", default: "900" }, "anchor-url": { type: "string" }, "anchor-address": { type: "string" }, "anchor-rpc-env": { type: "string", multiple: true }, "anchor-log-id": { type: "string", multiple: true }, "anchor-chain": { type: "string", default: "ethereum" }, "max-anchor-lag": { type: "string", default: "46800" }, json: { type: "boolean", default: false } } });
      if (!values["log-url"]) throw new Error("log-check needs --log-url");
      let anchor = {};
      if (values["anchor-url"]) {
        if (!values["anchor-address"] || !values["anchor-rpc-env"]?.length) throw new Error("--anchor-url needs --anchor-address and at least one --anchor-rpc-env");
        const rpcUrls = values["anchor-rpc-env"].map((name) => {
          const url = process.env[name];
          if (!url) throw new Error(`environment variable ${name} is not set`);
          return url;
        });
        const anchorLogIds: Record<string, string> = {};
        for (const pin of values["anchor-log-id"] ?? []) {
          const at = pin.indexOf("=");
          if (at < 1 || at === pin.length - 1) throw new Error(`--anchor-log-id takes <tenant>=<log id>, got "${pin}"`);
          anchorLogIds[pin.slice(0, at)] = pin.slice(at + 1);
        }
        anchor = { anchorUrl: values["anchor-url"], anchorAddress: values["anchor-address"], anchorRpcUrls: rpcUrls, anchorLogIds, anchorChainId: resolveAnchorChain(values["anchor-chain"]).chainId, maxAnchorLagMs: Number(values["max-anchor-lag"]) * 1000 };
      }
      const r = await checkLog({ logUrl: values["log-url"], ...(values["checkpoints-url"] ? { checkpointsUrl: values["checkpoints-url"] } : {}), ...(values["witness-url"] ? { witnessUrl: values["witness-url"] } : {}), tenants: values.tenant?.length ? values.tenant : ["default"], maxLagMs: Number(values["max-lag"]) * 1000, ...anchor });
      console.log(values.json ? JSON.stringify(r, null, 2) : formatLogCheck(r));
      return r.ok ? 0 : 1;
    }
    case "log-export": {
      const { values } = parseArgs({ args: rest, options: { "log-url": { type: "string" }, tenant: { type: "string" }, "token-env": { type: "string" }, out: { type: "string" }, month: { type: "string", multiple: true }, json: { type: "boolean", default: false } } });
      if (!values["log-url"] || !values["token-env"] || !values.out) throw new Error("log-export needs --log-url, --token-env, and --out");
      const token = process.env[values["token-env"]];
      if (!token) throw new Error(`environment variable ${values["token-env"]} is not set`);
      const r = await exportLog({ logUrl: values["log-url"], ...(values.tenant ? { tenant: values.tenant } : {}), token, outDir: values.out, ...(values.month?.length ? { months: values.month } : {}) });
      console.log(values.json ? JSON.stringify(r, null, 2) : formatExport(r));
      return r.problems.length ? 1 : 0;
    }
    case "witness": {
      const { values } = parseArgs({ args: rest, options: { key: { type: "string" }, "log-url": { type: "string" }, "checkpoints-url": { type: "string" }, out: { type: "string" }, tenant: { type: "string", multiple: true }, every: { type: "string", default: "300" }, once: { type: "boolean", default: false } } });
      if (!values.key || !values["log-url"] || !values["checkpoints-url"] || !values.out) throw new Error("witness needs --key, --log-url, --checkpoints-url, and --out");
      const w = new Witness({ logUrl: values["log-url"], checkpointsUrl: values["checkpoints-url"], tenants: values.tenant?.length ? values.tenant : ["default"], key: loadPrivateKey(values.key), outDir: values.out });
      const everyMs = Number(values.every) * 1000;
      if (!(everyMs > 0)) throw new Error("--every must be a positive number of seconds");
      if (values.once) {
        const outcomes = await w.runOnce();
        for (const o of outcomes) console.log(`${o.tenant.padEnd(20)} ${o.outcome}${"treeSize" in o ? ` at ${o.treeSize}` : ""}${"reason" in o ? `: ${o.reason}` : ""}`);
        return outcomes.some((o) => o.outcome === "refused") ? 1 : 0;
      }
      console.error(`agent-custody witness: keyid=${w.keyid} watching ${values["log-url"]} via ${values["checkpoints-url"]} every ${values.every}s, writing to ${values.out}`);
      w.start(everyMs);
      await untilStopped();
      w.stop();
      return 0;
    }
    case "anchor": {
      const { values } = parseArgs({ args: rest, options: { "log-url": { type: "string" }, "checkpoints-url": { type: "string" }, out: { type: "string" }, tenant: { type: "string", multiple: true }, "rpc-url-env": { type: "string" }, "key-env": { type: "string" }, chain: { type: "string", default: "ethereum" }, "max-fee-gwei": { type: "string" }, every: { type: "string", default: "21600" }, once: { type: "boolean", default: false } } });
      if (!values["log-url"] || !values["checkpoints-url"] || !values.out || !values["rpc-url-env"] || !values["key-env"]) throw new Error("anchor needs --log-url, --checkpoints-url, --out, --rpc-url-env, and --key-env");
      const rpcUrl = process.env[values["rpc-url-env"]];
      if (!rpcUrl) throw new Error(`environment variable ${values["rpc-url-env"]} is not set`);
      const privateKey = process.env[values["key-env"]];
      if (!privateKey) throw new Error(`environment variable ${values["key-env"]} is not set`);
      const everyMs = Number(values.every) * 1000;
      if (!(everyMs > 0)) throw new Error("--every must be a positive number of seconds");
      const target = resolveAnchorChain(values.chain);
      const maxFeeGwei = values["max-fee-gwei"] === undefined ? target.maxFeeGwei : Number(values["max-fee-gwei"]);
      if (maxFeeGwei === undefined) throw new Error(`chain ${target.chainId} has no default fee cap; give --max-fee-gwei (the named chains are ${Object.keys(ANCHOR_CHAINS).join(", ")})`);
      const chain = await evmChain({ rpcUrl, privateKey, chainId: target.chainId, maxFeeGwei });
      const a = new Anchor({ logUrl: values["log-url"], checkpointsUrl: values["checkpoints-url"], tenants: values.tenant?.length ? values.tenant : ["default"], chain, outDir: values.out });
      if (values.once) {
        const run = await a.runOnce();
        for (const t of run.tenants) console.log(`${t.tenant.padEnd(20)} ${t.outcome}${"treeSize" in t ? ` at ${t.treeSize}` : ""}${"reason" in t ? `: ${t.reason}` : ""}`);
        const tx = run.tx;
        console.log(`transaction: ${tx.outcome}${"txHash" in tx ? ` ${tx.txHash}` : ""}${"blockNumber" in tx ? ` in block ${tx.blockNumber}` : ""}${"reason" in tx ? `: ${tx.reason}` : ""}`);
        return run.tenants.some((t) => t.outcome === "refused") ? 1 : 0;
      }
      console.error(`agent-custody anchor: ${a.address} on ${target.name ?? "chain"} ${chain.chainId}, fee cap ${maxFeeGwei} gwei, watching ${values["log-url"]} via ${values["checkpoints-url"]} every ${values.every}s, writing to ${values.out}`);
      a.start(everyMs);
      await untilStopped();
      await a.stop();
      return 0;
    }
    case "signer": {
      const { values } = parseArgs({ args: rest, options: { key: { type: "string" }, port: { type: "string", default: "8790" }, host: { type: "string", default: "127.0.0.1" }, "token-env": { type: "string" }, "retired-key": { type: "string", multiple: true } } });
      if (!values.key) throw new Error("signer needs --key");
      const token = values["token-env"] ? process.env[values["token-env"]] : undefined;
      if (values["token-env"] && !token) throw new Error(`signer: environment variable ${values["token-env"]} is not set`);
      const kp = loadPrivateKey(values.key);
      const running = await serveSigner(kp, { port: Number(values.port), host: values.host, ...(token ? { token } : {}), retired: (values["retired-key"] ?? []).map(retiredKey) });
      console.error(`agent-custody signer: ${running.url} keyid=${kp.keyid} ${token ? "token required" : "open: bind this to a private network"}${values["retired-key"]?.length ? ` retired=${values["retired-key"].length}` : ""}`);
      await untilStopped();
      await running.close();
      return 0;
    }
    case "portal-followup": {
      // The founder's note to every registration between an hour and a week old that has not had it; run hourly from cron.
      const { values } = parseArgs({ args: rest, options: { "db-env": { type: "string" }, "mail-key-env": { type: "string" }, "mail-from": { type: "string" }, "mail-notify": { type: "string" }, "portal-url": { type: "string", default: "https://app.agent-custody.dev/" }, "dry-run": { type: "boolean", default: false } } });
      if (!values["db-env"] || !values["mail-key-env"] || !values["mail-from"]) throw new Error("portal-followup needs --db-env, --mail-key-env, and --mail-from");
      const apiKey = process.env[values["mail-key-env"]];
      if (!apiKey) throw new Error(`portal-followup: environment variable ${values["mail-key-env"]} is not set`);
      const r = await sendFollowUps(new PortalStore(openPostgres(values["db-env"])), { apiKey, from: values["mail-from"], ...(values["mail-notify"] ? { notify: values["mail-notify"] } : {}) }, { portalUrl: values["portal-url"], dryRun: values["dry-run"] });
      console.log(`${values["dry-run"] ? "would send" : "sent"} ${r.sent.length}, skipped ${r.skipped.length} (operator's own), failed ${r.failed.length}${r.sent.length ? `: ${r.sent.join(", ")}` : ""}`);
      return r.failed.length ? 1 : 0;
    }
    case "portal": {
      const { values } = parseArgs({ args: rest, options: { "db-env": { type: "string" }, "secret-env": { type: "string" }, "public-url": { type: "string" }, "checkpoints-url": { type: "string" }, "portal-url": { type: "string" }, port: { type: "string", default: "8792" }, host: { type: "string", default: "127.0.0.1" }, "stripe-key-env": { type: "string" }, "stripe-webhook-env": { type: "string" }, "stripe-price-team": { type: "string" }, "mail-key-env": { type: "string" }, "mail-from": { type: "string" }, "mail-notify": { type: "string" }, "github-client-id": { type: "string" }, "github-secret-env": { type: "string" }, "google-client-id": { type: "string" }, "google-secret-env": { type: "string" }, "trust-proxy": { type: "boolean", default: false } } });
      if (!values["db-env"] || !values["secret-env"] || !values["public-url"]) throw new Error("portal needs --db-env, --secret-env, and --public-url");
      let oauth: OAuthOptions | undefined;
      for (const p of ["github", "google"] as const) {
        const id = values[`${p}-client-id`];
        const env = values[`${p}-secret-env`];
        if (!id && !env) continue;
        if (!id || !env) throw new Error(`${p} sign-in needs both --${p}-client-id and --${p}-secret-env`);
        const clientSecret = process.env[env];
        if (!clientSecret) throw new Error(`portal: environment variable ${env} is not set`);
        if (!values["portal-url"]) throw new Error("provider sign-in needs --portal-url, the callback is built from it");
        oauth = { ...(oauth ?? {}), [p]: { clientId: id, clientSecret } };
      }
      let mail: MailOptions | undefined;
      if (values["mail-key-env"] || values["mail-from"]) {
        if (!values["mail-key-env"] || !values["mail-from"]) throw new Error("mail needs both --mail-key-env and --mail-from");
        const apiKey = process.env[values["mail-key-env"]];
        if (!apiKey) throw new Error(`portal: environment variable ${values["mail-key-env"]} is not set`);
        mail = { apiKey, from: values["mail-from"], ...(values["mail-notify"] ? { notify: values["mail-notify"] } : {}) };
      }
      const secret = process.env[values["secret-env"]];
      if (!secret || secret.length < 32) throw new Error(`environment variable ${values["secret-env"]} must hold a secret of at least 32 characters`);
      let stripe: StripeOptions | undefined;
      if (values["stripe-key-env"] || values["stripe-webhook-env"] || values["stripe-price-team"]) {
        if (!values["stripe-key-env"] || !values["stripe-webhook-env"] || !values["stripe-price-team"]) throw new Error("billing needs all three of --stripe-key-env, --stripe-webhook-env, --stripe-price-team");
        const secretKey = process.env[values["stripe-key-env"]];
        const webhookSecret = process.env[values["stripe-webhook-env"]];
        if (!secretKey || !webhookSecret) throw new Error("the Stripe key and webhook secret variables must both be set");
        stripe = { secretKey, webhookSecret, priceTeam: values["stripe-price-team"] };
      }
      const client = openPostgres(values["db-env"]);
      const tenancy = new PostgresTenancy(client);
      let keyid: string | undefined;
      try {
        keyid = (await fetchLogKeys(values["public-url"])).keys[0]?.keyid;
      } catch {
        // the log may not be reachable from here at start; the sheet then omits the keyid
      }
      const running = await servePortal({ tenancy, client, secret, publicUrl: values["public-url"], ...(values["checkpoints-url"] ? { checkpointsUrl: values["checkpoints-url"] } : {}), ...(values["portal-url"] ? { portalUrl: values["portal-url"] } : {}), ...(keyid ? { keyid } : {}), ...(stripe ? { stripe } : {}), ...(mail ? { mail } : {}), ...(oauth ? { oauth } : {}), trustProxy: values["trust-proxy"] }, { port: Number(values.port), host: values.host });
      console.error(`agent-custody portal: ${running.url} log=${values["public-url"]} billing=${stripe ? "stripe" : "off"}${values["trust-proxy"] ? " trust-proxy" : ""}`);
      await untilStopped();
      await running.close();
      return 0;
    }
    case "log-admin": {
      const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { "db-env": { type: "string" }, "log-id": { type: "string" }, label: { type: "string" }, file: { type: "string" }, tenant: { type: "string", default: "default" }, domains: { type: "string" }, "default-role": { type: "string", default: "readonly" }, enforce: { type: "boolean", default: false }, "oidc-issuer": { type: "string" }, "oidc-client-id": { type: "string" }, "oidc-secret-env": { type: "string" }, "saml-entry-point": { type: "string" }, "saml-cert": { type: "string" }, "saml-idp-issuer": { type: "string" } } });
      if (!values["db-env"]) throw new Error("log-admin needs --db-env NAME");
      const tenancy = new PostgresTenancy(openPostgres(values["db-env"]));
      const [what, verb, ...args] = positionals;
      const actor = `cli:${userInfo().username}@${hostname()}`;
      if (what === "tenant" && verb === "add" && args[0]) {
        const t = await tenancy.addTenant(args[0], values["log-id"] ?? args[0], actor);
        console.log(`tenant ${t.id} log=${t.logId} reached at /t/${t.id}/`);
      } else if (what === "tenant" && verb === "list") {
        for (const t of await tenancy.listTenants()) console.log(`${t.id.padEnd(24)} log=${t.logId.padEnd(28)} plan=${t.plan.padEnd(10)} created ${t.createdAt}${t.disabledAt ? `  DISABLED ${t.disabledAt}` : ""}`);
      } else if (what === "tenant" && verb === "plan" && args[0] && args[1]) {
        const t = await tenancy.setPlan(args[0], args[1] as Plan, actor);
        console.log(`tenant ${t.id} on plan ${t.plan}`);
      } else if (what === "tenant" && verb === "disable" && args[0]) {
        await tenancy.disableTenant(args[0], actor);
        console.log(`tenant ${args[0]} disabled`);
      } else if (what === "token" && verb === "add" && args[0]) {
        if (!values.label) throw new Error("token add needs --label");
        const { token, tokenHash } = await tenancy.addToken(args[0], values.label, actor);
        console.error(`token for ${args[0]} (${values.label}); shown once, stored as hash ${tokenHash.slice(0, 12)}…:`);
        console.log(token);
      } else if (what === "token" && verb === "list" && args[0]) {
        for (const t of await tenancy.listTokens(args[0])) console.log(`${t.tokenHash.slice(0, 12)}  ${t.label.padEnd(24)} created ${t.createdAt}${t.revokedAt ? `  REVOKED ${t.revokedAt}` : ""}`);
      } else if (what === "token" && verb === "revoke" && args[0] && args[1]) {
        console.log(`revoked ${await tenancy.revokeToken(args[0], args[1], actor)} token(s)`);
      } else if (what === "sso" && verb === "set" && args[0]) {
        if (!(await tenancy.tenant(args[0]))) throw new Error(`unknown tenant ${args[0]}; add it first`);
        if (!values.domains) throw new Error("sso set needs --domains");
        let config: OidcConfig | SamlConfig;
        if (values["oidc-issuer"]) {
          if (!values["oidc-client-id"] || !values["oidc-secret-env"]) throw new Error("OIDC needs --oidc-issuer, --oidc-client-id, and --oidc-secret-env");
          const clientSecret = process.env[values["oidc-secret-env"]];
          if (!clientSecret) throw new Error(`environment variable ${values["oidc-secret-env"]} is not set`);
          config = { issuer: values["oidc-issuer"], clientId: values["oidc-client-id"], clientSecret };
        } else if (values["saml-entry-point"] && values["saml-cert"]) {
          config = { entryPoint: values["saml-entry-point"], idpCert: readFileSync(values["saml-cert"], "utf8"), ...(values["saml-idp-issuer"] ? { idpIssuer: values["saml-idp-issuer"] } : {}) };
        } else {
          throw new Error("sso set needs the OIDC flags or --saml-entry-point with --saml-cert");
        }
        const domains = values.domains.split(",");
        const protocol = "issuer" in config ? "oidc" : "saml";
        await new PortalStore(openPostgres(values["db-env"])).setSso({ tenant: args[0], protocol, config, domains, defaultRole: values["default-role"] as Role, enforced: values.enforce });
        await tenancy.record(actor, "sso.set", args[0], { protocol, ...("issuer" in config ? { issuer: config.issuer } : { entryPoint: config.entryPoint }), domains, defaultRole: values["default-role"], enforced: values.enforce });
        console.log(`single sign-on set for ${args[0]}: ${domains.join(", ")}${values.enforce ? " (enforced)" : ""}`);
      } else if (what === "sso" && verb === "show" && args[0]) {
        const s = await new PortalStore(openPostgres(values["db-env"])).ssoOf(args[0]);
        if (!s) throw new Error(`no single sign-on for ${args[0]}`);
        const c = s.config as Partial<OidcConfig & SamlConfig>;
        console.log([`protocol      ${s.protocol}`, ...(c.issuer ? [`issuer        ${c.issuer}`, `client id     ${c.clientId}`, "client secret  set"] : [`entry point   ${c.entryPoint}`, `idp issuer    ${c.idpIssuer ?? "(not pinned)"}`, "idp cert      set"]), `domains       ${s.domains.join(", ")}`, `default role  ${s.defaultRole}`, `enforced      ${s.enforced}`].join("\n"));
      } else if (what === "sso" && verb === "remove" && args[0]) {
        const removed = await new PortalStore(openPostgres(values["db-env"])).removeSso(args[0]);
        if (removed) await tenancy.record(actor, "sso.remove", args[0], {});
        console.log(`${removed ? "removed" : "there was no"} single sign-on for ${args[0]}`);
      } else if (what === "user" && verb === "mfa-reset" && args[0]) {
        const portal = new PortalStore(openPostgres(values["db-env"]));
        const email = args[0].trim().toLowerCase();
        const member = await portal.userByEmail(email);
        if (!member) throw new Error(`no portal account with the address ${args[0]}`);
        await portal.resetMfa(email);
        await tenancy.record(actor, "user.mfa-reset", await portal.tenantOf(member.id), { email });
        console.log(`MFA reset for ${args[0]}`);
      } else if (what === "audit") {
        for (const e of await tenancy.audit({ ...(values.tenant !== "default" ? { tenant: values.tenant } : {}), limit: 100 })) console.log(`${e.at}  ${e.actor.padEnd(40)} ${e.action.padEnd(14)} ${(e.tenantId ?? "").padEnd(20)} ${Object.entries(e.detail).map(([k, v]) => `${k}=${v}`).join(" ")}`);
      } else if (what === "import") {
        if (!values.file) throw new Error("import needs --file <log.jsonl>");
        if (!(await tenancy.tenant(values.tenant))) throw new Error(`unknown tenant ${values.tenant}; add it first`);
        const r = await importLogFile(values.file, await tenancy.log(values.tenant));
        console.log(`imported ${r.added} leaf hash(es) into ${values.tenant}; the log now has ${r.total}`);
      } else {
        console.error(USAGE);
        return 2;
      }
      return 0;
    }
    case "prune": {
      const { values } = parseArgs({ args: rest, options: { log: { type: "string" }, before: { type: "string" }, receipts: { type: "string" } } });
      if (!values.log || !values.before) throw new Error("prune needs --log and --before");
      const r = pruneLog(values.log, new Date(values.before).toISOString(), values.receipts);
      console.log(`pruned ${r.pruned.length} leaf(s), kept ${r.kept}, removed ${r.bundlesRemoved} bundle file(s)`);
      for (const p of r.pruned) console.log(`  leaf ${p.leafIndex}  ${p.timestamp}  receipt ${p.receiptId ?? "?"}`);
      return 0;
    }
    case "log": {
      const { values } = parseArgs({
        args: rest,
        options: { file: { type: "string" }, key: { type: "string" }, port: { type: "string", default: "8787" }, host: { type: "string", default: "127.0.0.1" }, "token-env": { type: "string" }, "log-id": { type: "string" }, tenants: { type: "string" }, "db-env": { type: "string" }, "signer-url": { type: "string" }, "signer-token-env": { type: "string" }, "retired-key": { type: "string", multiple: true }, "checkpoint-dir": { type: "string" }, "checkpoint-every": { type: "string", default: "300" }, "checkpoint-heartbeat": { type: "string", default: "21600" }, "admin-token-env": { type: "string" }, "public-url": { type: "string" }, "checkpoints-url": { type: "string" }, "trust-proxy": { type: "boolean", default: false }, "hash-only": { type: "boolean", default: false } },
      });
      if (!values.key === !values["signer-url"]) throw new Error("log needs exactly one of --key or --signer-url");
      const token = values["token-env"] ? process.env[values["token-env"]] : undefined;
      if (values["token-env"] && !token) throw new Error(`log: environment variable ${values["token-env"]} is not set`);
      // The signer: a key in this process, or the signer service that holds it.
      let signer: Signer;
      if (values.key) signer = localSigner(loadPrivateKey(values.key), { retired: (values["retired-key"] ?? []).map(retiredKey) });
      else {
        const st = values["signer-token-env"] ? process.env[values["signer-token-env"]] : undefined;
        if (values["signer-token-env"] && !st) throw new Error(`log: environment variable ${values["signer-token-env"]} is not set`);
        signer = await connectSigner(values["signer-url"]!, st ? { token: st } : {});
      }
      const everyMs = Number(values["checkpoint-every"]) * 1000;
      if (!(everyMs > 0)) throw new Error("--checkpoint-every must be a positive number of seconds");
      const heartbeatMs = Number(values["checkpoint-heartbeat"]) * 1000;
      if (!(heartbeatMs > 0)) throw new Error("--checkpoint-heartbeat must be a positive number of seconds");
      let resolver: LogResolver;
      let checkpoints: CheckpointStore | undefined = values["checkpoint-dir"] ? dirCheckpoints(values["checkpoint-dir"]) : undefined;
      let where: string;
      let admin: AdminOptions | undefined;
      if (values["db-env"]) {
        // Postgres: the file is not used; tenants, tokens, leaves, and checkpoints live in the database.
        const client = openPostgres(values["db-env"]);
        const tenancy = new PostgresTenancy(client);
        const defaultId = values["log-id"] ?? "default";
        if (!(await tenancy.tenant("default"))) await tenancy.addTenant("default", defaultId);
        resolver = postgresResolver(tenancy, { defaultTenant: "default", ...(token ? { staticTokens: [token] } : {}) });
        const table = postgresCheckpoints(client);
        checkpoints = checkpoints ? bothCheckpoints(table, checkpoints) : table;
        if (values["admin-token-env"]) {
          const adminToken = process.env[values["admin-token-env"]];
          if (!adminToken) throw new Error(`log: environment variable ${values["admin-token-env"]} is not set`);
          admin = { tenancy, token: adminToken, portal: new PortalStore(client), ...(values["public-url"] ? { publicUrl: values["public-url"] } : {}), ...(values["checkpoints-url"] ? { checkpointsUrl: values["checkpoints-url"] } : {}) };
        }
        where = `store=postgres default-log=${(await tenancy.tenant("default"))?.logId} ${token ? "environment token accepted for the default log; " : ""}tokens from the database`;
      } else {
        if (values["admin-token-env"]) throw new Error("the admin page needs --db-env; tenants live in the database");
        if (!values.file) throw new Error("log needs --file, or --db-env");
        // --tenants names a JSON file { "<tenant>": { "file": "...", "tokenEnv": "NAME", "logId": "..." } }; each is reached at /t/<tenant>/.
        const tenants = values.tenants ? loadTenants(values.tenants) : undefined;
        resolver = fileResolver(values.file, { ...(token ? { tokens: [token] } : {}), ...(values["log-id"] ? { logId: values["log-id"] } : {}), ...(tenants ? { tenants } : {}) });
        where = `file=${values.file}${values["log-id"] ? ` log=${values["log-id"]}` : ""} ${token ? "bearer token required" : "open, anyone may append"}${tenants ? ` tenants=${Object.keys(tenants).join(",")}` : ""}`;
      }
      const running = await serveLog(resolver, signer, { port: Number(values.port), host: values.host, ...(checkpoints ? { checkpoints } : {}), ...(admin ? { admin } : {}), trustProxy: values["trust-proxy"], hashOnly: values["hash-only"] });
      const publisher = checkpoints ? new CheckpointPublisher(resolver, signer, checkpoints, everyMs, undefined, heartbeatMs) : null;
      publisher?.start();
      console.error(`agent-custody log: ${running.url} keyid=${signer.keyid} ${values["signer-url"] ? `signer=${values["signer-url"]} ` : ""}${where}${checkpoints ? ` checkpoints every ${values["checkpoint-every"]}s${values["checkpoint-dir"] ? ` to ${values["checkpoint-dir"]}` : ""}` : ""}${admin ? " admin page at /admin" : ""}`);
      await untilStopped();
      publisher?.stop();
      await running.close();
      return 0;
    }
    case "verify": {
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          "issuer-key": { type: "string", multiple: true },
          "gateway-key": { type: "string", multiple: true },
          "principal-key": { type: "string", multiple: true },
          "approval-key": { type: "string", multiple: true },
          "log-key": { type: "string", multiple: true },
          "log-url": { type: "string" },
          "log-id": { type: "string" },
          "require-strict": { type: "boolean", default: false },
          "upstream-key": { type: "string", multiple: true },
          "stripe-secret-env": { type: "string" },
          "github-secret-env": { type: "string" },
          log: { type: "string" },
          disclose: { type: "string" },
          "capture-key-env": { type: "string" },
          json: { type: "boolean", default: false },
          markdown: { type: "boolean", default: false },
        },
      });
      const file = positionals[0];
      const issuerKeyFiles = [...(values["issuer-key"] ?? []), ...(values["gateway-key"] ?? [])];
      if (!file || issuerKeyFiles.length === 0) throw new Error("verify needs <bundle> --issuer-key (alias --gateway-key)");
      if (values.markdown && (values.json || values.disclose)) throw new Error("verify --markdown does not combine with --json or --disclose");
      const captureKey = values["capture-key-env"] ? captureKeyFrom(secretFrom(values["capture-key-env"])) : undefined;
      const disclosed = values.disclose ? (JSON.parse(readFileSync(values.disclose, "utf8")) as Record<string, unknown>) : undefined;
      const fetchedLogKeys = values["log-url"] ? (await fetchLogKeys(values["log-url"])).keys : [];
      const logKeys = [...(values["log-key"] ?? []).map(loadPublicKey), ...fetchedLogKeys];
      const verifyOptions: VerifyOptions = {
        issuerKeys: issuerKeyFiles.map(loadPublicKey),
        principalKeys: (values["principal-key"] ?? []).map(loadPublicKey),
        ...(values["approval-key"] ? { approvalKeys: values["approval-key"].map(loadPublicKey) } : {}),
        ...(logKeys.length ? { logKeys } : {}),
        ...(values["log-id"] ? { logId: values["log-id"] } : {}),
        ...(values["require-strict"] ? { requireStrict: true } : {}),
        ...(values["upstream-key"] ? { upstreamKeys: values["upstream-key"].map(loadPublicKey) } : {}),
        ...(values["stripe-secret-env"] || values["github-secret-env"] ? { providerSecrets: { ...(values["stripe-secret-env"] ? { stripe: secretFrom(values["stripe-secret-env"]) } : {}), ...(values["github-secret-env"] ? { github: secretFrom(values["github-secret-env"]) } : {}) } } : {}),
        ...(values.log ? { logFile: values.log } : {}),
        ...(captureKey ? { captureKey } : {}),
        ...(disclosed ? { disclosed } : {}),
      };
      if (values.markdown) {
        const summary = summarizeReceipts(positionals.flatMap(receiptFiles), verifyOptions);
        console.log(formatSummaryMarkdown(summary));
        return summary.ok ? 0 : 1;
      }
      const result = verifyBundle(JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle, verifyOptions);
      console.log(values.json ? JSON.stringify(result, null, 2) : formatReport(result));
      return result.ok ? 0 : 1;
    }
    case "export": {
      const { values } = parseArgs({
        args: rest,
        options: {
          receipts: { type: "string" },
          out: { type: "string" },
          "issuer-key": { type: "string", multiple: true },
          "principal-key": { type: "string", multiple: true },
          "approval-key": { type: "string", multiple: true },
          since: { type: "string" },
          "allow-clear": { type: "boolean", default: false },
        },
      });
      if (!values.receipts || !values.out || !values["issuer-key"]?.length) throw new Error("export needs --receipts <dir>, --out <dir> and --issuer-key <pub>");
      // Date.parse reads "1" as the year 2001, so the text must start with a date
      const since = values.since === undefined ? undefined : /^\d{4}-\d{2}-\d{2}/.test(values.since) ? Date.parse(values.since) : NaN;
      if (since !== undefined && !Number.isFinite(since)) throw new Error(`--since must be an ISO time; got "${values.since}"`);
      const result = exportReceipts({
        receiptsDir: values.receipts,
        outDir: values.out,
        verify: {
          issuerKeys: values["issuer-key"].map(loadPublicKey),
          principalKeys: (values["principal-key"] ?? []).map(loadPublicKey),
          ...(values["approval-key"] ? { approvalKeys: values["approval-key"].map(loadPublicKey) } : {}),
        },
        ...(since !== undefined ? { since } : {}),
        allowClear: values["allow-clear"],
      });
      for (const line of formatExportLines(result)) console.log(line);
      if (result.lines.some((l) => l.outcome === "copied" && l.clear.length)) console.error(CLEAR_WARNING);
      if (result.problem) console.error(`agent-custody export: ${result.problem}`);
      return result.refused > 0 || result.copied === 0 ? 1 : 0;
    }
    case "completeness": {
      const { values } = parseArgs({
        args: rest,
        options: {
          receipts: { type: "string" },
          "issuer-key": { type: "string", multiple: true },
          "principal-key": { type: "string", multiple: true },
          "approval-key": { type: "string", multiple: true },
          "log-key": { type: "string", multiple: true },
          log: { type: "string" },
          "log-id": { type: "string" },
          provider: { type: "string" },
          object: { type: "string", default: "refunds" },
          "key-env": { type: "string" },
          tool: { type: "string", multiple: true },
          since: { type: "string" },
          until: { type: "string" },
          "id-path": { type: "string" },
          "amount-field": { type: "string" },
          "currency-field": { type: "string" },
          beneficiary: { type: "string", multiple: true },
          json: { type: "boolean", default: false },
        },
      });
      if (!values.receipts || !values["issuer-key"]?.length || !values["key-env"] || !values.tool?.length || !values.since || !values.until) throw new Error("completeness needs --receipts, --issuer-key, --provider stripe, --key-env, --tool, --since and --until");
      if (values.provider !== "stripe") throw new Error(`completeness supports --provider stripe; got "${values.provider ?? ""}"`);
      const objects: StripeObject[] = ["refunds", "payouts", "transfers"];
      if (!objects.includes(values.object as StripeObject)) throw new Error(`--object is one of ${objects.join(", ")}; got "${values.object}"`);
      const sinceMs = Date.parse(values.since);
      const untilMs = Date.parse(values.until);
      if (!Number.isFinite(sinceMs) || !Number.isFinite(untilMs) || untilMs <= sinceMs) throw new Error("--since and --until must be ISO times, --until after --since");
      const beneficiary: Record<string, string> = {};
      for (const pair of values.beneficiary ?? []) {
        const at = pair.indexOf("=");
        if (at < 1 || at === pair.length - 1) throw new Error(`--beneficiary takes <argument>=<provider field>; got "${pair}"`);
        beneficiary[pair.slice(0, at)] = pair.slice(at + 1);
      }
      const report = await checkCompleteness({
        receiptsDir: values.receipts,
        verify: {
          issuerKeys: values["issuer-key"].map(loadPublicKey),
          principalKeys: (values["principal-key"] ?? []).map(loadPublicKey),
          ...(values["approval-key"] ? { approvalKeys: values["approval-key"].map(loadPublicKey) } : {}),
          ...(values["log-key"] ? { logKeys: values["log-key"].map(loadPublicKey) } : {}),
          ...(values.log ? { logFile: values.log } : {}),
          ...(values["log-id"] ? { logId: values["log-id"] } : {}),
        },
        source: stripeSource({ secretKey: secretFrom(values["key-env"]), object: values.object as StripeObject }),
        tools: values.tool,
        sinceMs,
        untilMs,
        ...(values["id-path"] ? { idPath: values["id-path"] } : {}),
        ...(values["amount-field"] ? { amountField: values["amount-field"] } : {}),
        ...(values["currency-field"] ? { currencyField: values["currency-field"] } : {}),
        ...(Object.keys(beneficiary).length ? { beneficiary } : {}),
      });
      console.log(values.json ? JSON.stringify(report, null, 2) : formatCompleteness(report));
      return report.complete ? 0 : 1;
    }
    case "policy": {
      const [subcommand, ...args] = rest;
      if (subcommand !== "simulate") throw new Error("policy needs the simulate subcommand: policy simulate --policy <proposed.cedar> --receipts <dir> --issuer-key <pub>");
      const { values } = parseArgs({
        args,
        options: {
          policy: { type: "string" },
          receipts: { type: "string" },
          "issuer-key": { type: "string", multiple: true },
          "principal-key": { type: "string", multiple: true },
          "approval-key": { type: "string", multiple: true },
          "log-key": { type: "string", multiple: true },
          "capture-key-env": { type: "string" },
          disclose: { type: "string", multiple: true },
          json: { type: "boolean", default: false },
          out: { type: "string" },
        },
      });
      if (!values.policy || !values.receipts || !values["issuer-key"]?.length) throw new Error("policy simulate needs --policy <proposed.cedar> --receipts <dir> --issuer-key <pub>");
      const policy = readFileSync(values.policy, "utf8");
      const keys = {
        issuerKeys: values["issuer-key"].map(loadPublicKey),
        principalKeys: (values["principal-key"] ?? []).map(loadPublicKey),
        approvalKeys: (values["approval-key"] ?? []).map(loadPublicKey),
        logKeys: (values["log-key"] ?? []).map(loadPublicKey),
      };
      const names = readdirSync(values.receipts, { withFileTypes: true })
        .filter((entry) => (entry.isFile() || entry.isSymbolicLink()) && entry.name.endsWith(".json"))
        .map((entry) => entry.name);
      const AUTHORIZATION = ".authorization.json";
      const files = names.filter((name) => !name.endsWith(AUTHORIZATION)).sort();
      const have = new Set(files);
      const fail = (file: string, error: unknown): never => { throw new Error(`policy simulate: ${file}: ${error instanceof Error ? error.message : String(error)}`); };
      // A gateway that dies after it forwards a precommit call leaves <id>.authorization.json and no <id>.json. That
      // call went upstream, so it counts as skipped and the report is incomplete.
      const unreplayable: SimulationSkip[] = names.filter((name) => name.endsWith(AUTHORIZATION) && !have.has(`${name.slice(0, -AUTHORIZATION.length)}.json`)).sort().map((name) => {
        const file = join(values.receipts!, name);
        try {
          const p = verifyOrphanAuthorization(JSON.parse(readFileSync(file, "utf8")) as AuthorizationBundle, keys.issuerKeys, keys.logKeys);
          if (`${p.receiptId}${AUTHORIZATION}` !== name) throw new Error("the file name does not match the receipt id in the authorization");
          return { receiptId: p.receiptId, tool: p.tool.name, reason: "only the authorization survives; the receipt is missing, so the outcome and the call cannot be replayed" };
        } catch (error) {
          return fail(file, error);
        }
      });
      if (!files.length && !unreplayable.length) throw new Error(`policy simulate: no receipt bundles found in ${values.receipts}`);
      const captureKey = values["capture-key-env"] ? captureKeyFrom(secretFrom(values["capture-key-env"])) : undefined;
      const disclosures = new Map<string, unknown>();
      for (const file of values.disclose ?? []) {
        try {
          const disclosure = JSON.parse(readFileSync(file, "utf8")) as { receiptId?: unknown };
          if (typeof disclosure?.receiptId !== "string") throw new Error("the disclosure names no receiptId");
          disclosures.set(disclosure.receiptId, disclosure);
        } catch (error) {
          fail(file, error);
        }
      }
      // One bundle at a time: the replay needs the predicate of the receipt it is on, not the results of the others.
      function* verified() {
        for (const name of files) {
          const file = join(values.receipts!, name);
          try {
            const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
            const result = verifyBundle(bundle, keys);
            if (!result.ok || !result.statement) {
              const failures = result.checks.filter((check) => !check.ok).map((check) => `${check.name}${check.detail ? ` (${check.detail})` : ""}`);
              throw new Error(`receipt verification failed: ${failures.join("; ")}`);
            }
            if (`${result.statement.predicate.receiptId}.json` !== name) throw new Error("the file name does not match the receipt id");
            yield result.statement.predicate;
          } catch (error) {
            fail(file, error);
          }
        }
      }
      const report = simulatePolicy(policy, verified(), { unreplayable, ...(captureKey ? { captureKey } : {}), disclosures });
      const json = JSON.stringify(report, null, 2);
      if (values.out) {
        // Reports name calls and decisions: keep them owner-only, including when replacing an existing file.
        const fd = openSync(values.out, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW, 0o600);
        try {
          fchmodSync(fd, 0o600);
          writeSync(fd, json);
        } finally {
          closeSync(fd);
        }
      }
      console.log(values.json ? json : formatSimulation(report));
      return report.complete ? 0 : 1;
    }
    case "reveal": {
      // The values a receipt withheld, under the customer's key, as a disclosure file: hand it to a reviewer with the
      // receipt, and `verify --disclose` recomputes every digest from it.
      const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: { "capture-key-env": { type: "string" }, "issuer-key": { type: "string", multiple: true }, out: { type: "string" }, "include-salts": { type: "boolean" } } });
      const file = positionals[0];
      if (!file || !values["capture-key-env"] || !values["issuer-key"]?.length) throw new Error("reveal needs <bundle> --capture-key-env NAME --issuer-key <pub> [--out disclosure.json] [--include-salts]");
      const key = captureKeyFrom(secretFrom(values["capture-key-env"]));
      const bundle = JSON.parse(readFileSync(file, "utf8")) as ReceiptBundle;
      // only the issuer's own statement is decrypted: a bundle someone assembled around another receipt's ciphertexts is refused before any value comes back
      const signed = dsseVerify(bundle.envelope, values["issuer-key"].map((f) => loadPublicKey(f)));
      if (!signed.ok) throw new Error(`reveal: the bundle is not signed by the issuer key given (${signed.error}); nothing is revealed`);
      const p = (signed.payload as ReceiptStatement).predicate;
      // Every withheld path the key reveals goes into the disclosure at its own path, value and salt. A path withheld
      // as a digest only carries no value to reveal, and its salt is not written unless asked for (--include-salts):
      // a salt beside no value would hand a reviewer the means to confirm guesses, and a file that carries one does
      // not verify until the holder fills in the value.
      const back = restorePaths(p, p.capture, undefined, key);
      for (const x of back.problems) throw new Error(x.error);
      // the id comes from the bundle: it is checked before it becomes part of a path
      const saltsFile = saltsFileFor(dirname(file), p.receiptId);
      const kept = values["include-salts"] && existsSync(saltsFile) ? (JSON.parse(readFileSync(saltsFile, "utf8")) as { salts?: Record<string, string> }).salts ?? {} : {};
      let disclosure: Record<string, unknown> = { receiptId: p.receiptId };
      let saltsWritten = 0;
      for (const path of p.capture?.withheld ?? []) {
        const k = JSON.stringify(path);
        if (back.restored.has(k)) disclosure = setAt(disclosure, path, { $custody: "disclosed", salt: back.salts.get(k), value: back.values.get(k) });
        else if (kept[k]) {
          disclosure = setAt(disclosure, path, { $custody: "disclosed", salt: kept[k] });
          saltsWritten++;
        }
      }
      // a value withheld without its value cannot be revealed by anyone but its holder; one encrypted under another key is a different matter, said separately
      const foreign = back.missing.filter((w) => (getAt(p, w) as { $custody?: string } | undefined)?.$custody === "encrypted");
      const notRevealed = back.missing.filter((w) => !foreign.includes(w)).map(pathText);
      const foreignNote = foreign.length ? ` Encrypted under key ${String((getAt(p, foreign[0]!) as { keyid: string }).keyid).slice(0, 12)}…, not the one given: ${foreign.map(pathText).join(", ")}.` : "";
      if (foreign.length && back.restored.size === 0) throw new Error(`reveal: nothing revealed; the values are encrypted under key ${String((getAt(p, foreign[0]!) as { keyid: string }).keyid).slice(0, 12)}…, not the one given`);
      const text = JSON.stringify(disclosure, null, 2);
      const how = saltsWritten ? `; their salts are written in the file for the holder to add \"value\" beside, and the file does not verify until then: do not hand it over unfinished` : values["include-salts"] ? ` (no salts file at ${saltsFile})` : `; --include-salts writes their salts from ${saltsFile} for the holder to complete`;
      const note = (notRevealed.length ? ` Not revealed, withheld without a value: ${notRevealed.join(", ")}; only the party that holds them can disclose them${how}.` : "") + foreignNote;
      if (values.out) {
        // decrypted values and salts: the owner's alone, whatever the umask, whatever mode a file already there had,
        // and never through a symlink someone left at that name
        const fd = openSync(values.out, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_TRUNC | fsConstants.O_NOFOLLOW, 0o600);
        try {
          fchmodSync(fd, 0o600);
          writeSync(fd, text);
        } finally {
          closeSync(fd);
        }
        console.log(`disclosure for receipt ${p.receiptId} written to ${values.out}; verify it with --disclose ${values.out}.${note}`);
      } else {
        console.log(text);
        if (note) console.error(note.trim());
      }
      return 0;
    }
    case "audit": {
      const { values } = parseArgs({
        args: rest,
        options: {
          older: { type: "string" },
          newer: { type: "string" },
          log: { type: "string" },
          "log-url": { type: "string" },
          "issuer-key": { type: "string", multiple: true },
          "log-key": { type: "string", multiple: true },
          "log-id": { type: "string" },
          "witness-key": { type: "string", multiple: true },
          "witness-url": { type: "string" },
          json: { type: "boolean", default: false },
        },
      });
      const keyFiles = [...(values["issuer-key"] ?? []), ...(values["log-key"] ?? [])];
      if (!values.older || !values.newer) throw new Error("audit needs --older and --newer");
      const witnessKeys = [...(values["witness-key"] ?? []).map(loadPublicKey), ...(values["witness-url"] ? await fetchWitnessKeys(values["witness-url"]) : [])];
      if (!values.log === !values["log-url"]) throw new Error("audit needs exactly one of --log or --log-url");
      const auditKeys = [...keyFiles.map(loadPublicKey), ...(values["log-url"] ? (await fetchLogKeys(values["log-url"])).keys : [])];
      if (auditKeys.length === 0) throw new Error("audit needs a key: --issuer-key, --log-key, or a --log-url that publishes its keys");
      // --older and --newer take a receipt bundle, or a checkpoint file from the log's or the witness's host
      const headOf = (file: string): Envelope => {
        const j = JSON.parse(readFileSync(file, "utf8")) as { treeHead?: Envelope; envelope?: Envelope };
        if (j.treeHead) return j.treeHead;
        if (j.envelope && j.envelope.payloadType === TREEHEAD_TYPE) return j.envelope;
        throw new Error(`${file} is neither a receipt bundle nor a checkpoint`);
      };
      const older = headOf(values.older);
      const newer = headOf(values.newer);
      const sizeOf = (env: Envelope) => (JSON.parse(Buffer.from(env.payload, "base64").toString()) as TreeHead).treeSize;
      const [m, n] = [sizeOf(older), sizeOf(newer)];
      let proof: string[];
      if (values.log) proof = new MerkleLog(values.log).consistencyProof(Math.min(m, n), Math.max(m, n));
      else {
        const res = await fetch(new URL(`consistency?old=${Math.min(m, n)}&new=${Math.max(m, n)}`, values["log-url"]!.endsWith("/") ? values["log-url"]! : `${values["log-url"]}/`), { signal: AbortSignal.timeout(10_000) });
        if (!res.ok) throw new Error(`log refused the consistency query: ${res.status}`);
        proof = ((await res.json()) as { hashes: string[] }).hashes;
      }
      const result = auditExtends(older, newer, proof, auditKeys, values["log-id"], witnessKeys.length ? { witnessKeys } : {});
      if (values.json) console.log(JSON.stringify(result, null, 2));
      else {
        for (const c of result.checks) console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.detail ? `  (${c.detail})` : ""}`);
        console.log(`\nRESULT: ${result.ok ? "NEWER LOG EXTENDS OLDER LOG" : "NOT CONSISTENT"}`);
      }
      return result.ok ? 0 : 1;
    }
    default:
      console.error(USAGE);
      return cmd === undefined || cmd === "--help" || cmd === "-h" ? 0 : 2;
  }
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (e) => {
    console.error(`error: ${e instanceof Error ? e.message : e}`);
    process.exit(1);
  },
);
