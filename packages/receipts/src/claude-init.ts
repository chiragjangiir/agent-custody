// `agent-custody init claude-code`: the key, the config, the starter policy, and the three hooks for the user's own
// Claude Code sessions, in one command. It is safe to run two times.
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir, userInfo } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { SdkConfigSchema, loadSdkConfig } from "./config.ts";
import { generateKeyPair, publicKeyFromPem, writeKeyPair } from "./crypto.ts";

export const HOOK_EVENTS = ["PreToolUse", "PostToolUse", "PostToolUseFailure"] as const;
export const HOOK_MATCHER = "Bash|Write|Edit|MultiEdit|NotebookEdit|mcp__.*";
const KEY_NAME = "claude-code";
const DEFAULT_TOKEN_ENV = "AGENT_CUSTODY_LOG_TOKEN";

export interface ClaudeInitOptions {
  /** The absolute path of the CLI script that runs now. The hook runs this script. */
  cliPath: string;
  /** The Node binary that the hook runs. Default: the binary that runs now. */
  nodePath?: string;
  /** Default: `~/.config/agent-custody` */
  dir?: string;
  /** Write the hooks to `~/.claude/settings.json`. Default: `.claude/settings.local.json` in `cwd`. */
  user?: boolean;
  /** Leave out `"mode": "observe"`, so the policy blocks a denied call. */
  enforce?: boolean;
  logUrl?: string;
  logId?: string;
  /** The NAME of the environment variable that holds the log token. Never the token. */
  logTokenEnv?: string;
  /** The log's public key file. A log URL needs it. The command copies it into the directory when it writes a new config. */
  logKey?: string;
  home?: string;
  cwd?: string;
  /** One line of progress. Default: stdout. */
  print?: (line: string) => void;
}

export interface ClaudeInitResult {
  dir: string;
  configFile: string;
  settingsFile: string;
  hookCommand: string;
}

/** A shell word for a path: bare when it is plain, in single quotes otherwise. */
export function shellQuote(s: string): string {
  return /^[A-Za-z0-9_\/.:@%+=,-]+$/.test(s) ? s : `'${s.replaceAll("'", `'\\''`)}'`;
}

type Json = Record<string, unknown>;
const isObject = (v: unknown): v is Json => !!v && typeof v === "object" && !Array.isArray(v);

/** Parses a settings file. Throws, and so changes nothing, when the text is not a JSON object with usable `hooks`. */
export function parseSettings(text: string, file: string): Json {
  let settings: unknown;
  try {
    settings = JSON.parse(text);
  } catch (e) {
    throw new Error(`${file} is not valid JSON (${e instanceof Error ? e.message : String(e)}). Fix the file and run the command again. The command changed nothing.`);
  }
  if (!isObject(settings)) throw new Error(`${file} does not hold a JSON object. The command changed nothing.`);
  const hooks = settings.hooks;
  if (hooks !== undefined && !isObject(hooks)) throw new Error(`"hooks" in ${file} is not an object. The command changed nothing.`);
  for (const event of HOOK_EVENTS) {
    if (hooks?.[event] !== undefined && !Array.isArray(hooks[event])) throw new Error(`"hooks.${event}" in ${file} is not an array. The command changed nothing.`);
  }
  return settings;
}

export type HookChange = "added" | "updated" | "kept";

/**
 * Registers the hook command for the three events and keeps every other key and hook. A hook of ours is a command
 * that ends with `hook --config <this config>`. It is updated in place when its command differs, and never added twice.
 */
export function mergeHooks(settings: Json, command: string, configFile: string): { settings: Json; changes: Record<string, HookChange> } {
  const ours = ` hook --config ${shellQuote(configFile)}`;
  const hooks: Json = { ...(isObject(settings.hooks) ? settings.hooks : {}) };
  const changes: Record<string, HookChange> = {};
  for (const event of HOOK_EVENTS) {
    const entries = ((hooks[event] as unknown[] | undefined) ?? []).map((entry) => (isObject(entry) ? { ...entry } : entry));
    let change: HookChange | undefined;
    for (const entry of entries) {
      if (!isObject(entry) || !Array.isArray(entry.hooks)) continue;
      entry.hooks = entry.hooks.map((hook: unknown) => {
        if (!isObject(hook) || typeof hook.command !== "string" || !hook.command.endsWith(ours)) return hook;
        if (hook.command === command) { change ??= "kept"; return hook; }
        change = "updated";
        return { ...hook, command };
      });
    }
    if (!change) {
      entries.push({ matcher: HOOK_MATCHER, hooks: [{ type: "command", command }] });
      change = "added";
    }
    hooks[event] = entries;
    changes[event] = change;
  }
  return { settings: { ...settings, hooks }, changes };
}

function buildConfig(o: ClaudeInitOptions, user: string): Json {
  const config: Json = {
    agentId: "claude-code",
    principalId: user,
    framework: "claude-code",
    identity: { keyFile: `keys/${KEY_NAME}.key` },
    policyFile: "policy.cedar",
    ...(o.enforce ? {} : { mode: "observe" }),
    receiptsDir: "receipts",
  };
  if (o.logUrl) {
    config.log = {
      url: o.logUrl,
      tokenEnv: o.logTokenEnv ?? DEFAULT_TOKEN_ENV,
      hashOnly: true,
      keys: ["log.pub"],
      ...(o.logId ? { logId: o.logId } : {}),
      timeoutMs: 3000,
    };
  } else {
    config.logFile = "log.jsonl";
  }
  return config;
}

/** Throws unless the file holds a PUBLIC key in PEM form. A private key is refused too, so that `log.pub` never holds one. */
function checkLogKey(file: string): void {
  const text = readFileSync(file, "utf8");
  try {
    if (!text.includes("-----BEGIN PUBLIC KEY-----")) throw new Error("no PEM public key");
    publicKeyFromPem(text);
  } catch {
    throw new Error(`init: the log key file ${file} does not hold a public key in PEM form. Give the .pub file of the log.`);
  }
}

/** True when the path is in a git work tree and git does not ignore it. False when git cannot tell. */
function notIgnoredByGit(file: string): boolean {
  return spawnSync("git", ["check-ignore", "-q", file], { cwd: dirname(file), stdio: "ignore", timeout: 5000 }).status === 1;
}

function userName(): string {
  try { return userInfo().username; } catch { return "user"; }
}

export function initClaudeCode(o: ClaudeInitOptions): ClaudeInitResult {
  const print = o.print ?? ((line: string) => console.log(line));
  const home = o.home ?? homedir();
  const dir = resolve(o.dir ?? join(home, ".config", "agent-custody"));
  const settingsFile = o.user ? join(home, ".claude", "settings.json") : join(resolve(o.cwd ?? process.cwd()), ".claude", "settings.local.json");
  const configFile = join(dir, "sdk.json");

  if (!isAbsolute(o.cliPath)) throw new Error("init: the CLI path must be absolute");
  if ((o.logId || o.logTokenEnv || o.logKey) && !o.logUrl) throw new Error("init: --log-id, --log-token-env, and --log-key need --log-url");
  if (o.logTokenEnv && !/^[A-Z_][A-Z0-9_]*$/.test(o.logTokenEnv)) throw new Error("init: --log-token-env takes the NAME of an environment variable, such as AGENT_CUSTODY_LOG_TOKEN. Never give the token itself.");
  if (o.logUrl && !o.logKey) throw new Error("init: --log-url needs --log-key <pub>, the public key of the log. Without it, `report` cannot check the tree head of any receipt, and every receipt fails.");
  if (o.logKey && !existsSync(o.logKey)) throw new Error(`init: the log key file ${o.logKey} does not exist`);
  if (o.logKey) checkLogKey(o.logKey);
  const config = buildConfig(o, userName());
  const checked = SdkConfigSchema.safeParse(config);
  if (!checked.success) throw new Error(`init: the config is not valid: ${checked.error.issues.map((i) => `${i.path.join(".") || "(config)"}: ${i.message}`).join("; ")}`);

  // Read the settings before any write, so that a settings file we cannot merge leaves the machine as it was.
  const settingsText = existsSync(settingsFile) ? readFileSync(settingsFile, "utf8") : undefined;
  const settings = settingsText === undefined ? {} : parseSettings(settingsText, settingsFile);

  print("agent-custody init claude-code");

  const keyFile = join(dir, "keys", `${KEY_NAME}.key`);
  mkdirSync(join(dir, "keys"), { recursive: true, mode: 0o700 });
  if (existsSync(keyFile)) {
    print(`1. Key: kept the existing key ${keyFile}`);
  } else {
    const kp = generateKeyPair();
    writeKeyPair(kp, join(dir, "keys"), KEY_NAME);
    print(`1. Key: made ${keyFile} (key id ${kp.keyid.slice(0, 16)}). The file is readable by you only.`);
  }

  const policyFile = join(dir, "policy.cedar");
  if (existsSync(policyFile)) {
    print(`2. Policy: kept the existing ${policyFile}`);
  } else {
    copyFileSync(new URL("../templates/claude-code.cedar", import.meta.url), policyFile);
    print(`2. Policy: wrote the starter deny set to ${policyFile}. It forbids force push (not --force-with-lease), rm -rf on /, ~, and $HOME, terraform destroy and apply -destroy, and drop database.`);
  }

  mkdirSync(join(dir, "receipts"), { recursive: true, mode: 0o700 });
  if (existsSync(configFile)) {
    print(`3. Config: kept the existing ${configFile}. The command does not change it.`);
    const ignored = ([["--enforce", o.enforce], ["--log-url", o.logUrl], ["--log-id", o.logId], ["--log-token-env", o.logTokenEnv], ["--log-key", o.logKey]] as const).filter(([, given]) => given).map(([flag]) => flag);
    if (ignored.length) print(`   Warning: ${ignored.join(", ")} not applied, because the config exists. The pinned log key stays as it is. Edit ${configFile}, or remove the file and run this command again.`);
  } else {
    if (o.logKey) copyFileSync(o.logKey, join(dir, "log.pub"));
    writeFileSync(configFile, `${JSON.stringify(config, null, 2)}\n`);
    print(`3. Config: wrote ${configFile}, ${o.enforce ? "in enforce mode: a denied call is blocked" : 'with "mode": "observe": the policy records a denied call and blocks nothing'}.`);
    print(o.logUrl ? `   Receipts go to ${o.logUrl} as hashes. The token comes from the environment variable ${o.logTokenEnv ?? DEFAULT_TOKEN_ENV}.` : `   Receipts stay on this machine in ${join(dir, "receipts")}. No log is configured.`);
  }
  loadSdkConfig(configFile);

  const nodePath = o.nodePath ?? process.execPath;
  const hookCommand = `${shellQuote(nodePath)} ${shellQuote(o.cliPath)} hook --config ${shellQuote(configFile)}`;
  const merged = mergeHooks(settings, hookCommand, configFile);
  mkdirSync(dirname(settingsFile), { recursive: true });
  writeFileSync(settingsFile, `${JSON.stringify(merged.settings, null, 2)}\n`);
  const by = (c: HookChange) => HOOK_EVENTS.filter((e) => merged.changes[e] === c);
  const parts = ([["registered", "added"], ["updated", "updated"], ["found already registered", "kept"]] as const).filter(([, c]) => by(c).length).map(([word, c]) => `${word} ${by(c).join(", ")}`);
  print(`4. Hooks: ${parts.join("; ")} in ${settingsFile}. The command keeps every other key and hook in that file.`);

  if (!o.user && notIgnoredByGit(settingsFile)) {
    print("");
    print(`Warning: ${settingsFile} is in a git repository, and git does not ignore it. The file holds absolute paths of your home directory.`);
    print("Add this line to .gitignore: .claude/settings.local.json");
  }
  if (/[\\/]_npx[\\/]/.test(o.cliPath)) {
    print("");
    print("Warning: this command runs from the npx cache, and npm can clear that cache. The hooks then stop working.");
    print("Install the package globally with `npm install -g @agent-custody/receipts`, and run this command again. The second run updates the hook paths.");
  }
  if (o.logUrl && !process.env[o.logTokenEnv ?? DEFAULT_TOKEN_ENV]) {
    print("");
    print(`Note: ${o.logTokenEnv ?? DEFAULT_TOKEN_ENV} is not set in this shell. Set it in the environment that starts Claude Code.`);
  }

  print("");
  print("Next:");
  print(`  1. Start a Claude Code session ${o.user ? "in any directory" : "in this directory"} and work as usual. Nothing is blocked${o.enforce ? " except a call that the policy denies" : ""}.`);
  print(`  2. Run: ${shellQuote(nodePath)} ${shellQuote(o.cliPath)} report --config ${shellQuote(configFile)}`);
  print("     The report lists each call that the policy would have denied.");
  return { dir, configFile, settingsFile, hookCommand };
}
