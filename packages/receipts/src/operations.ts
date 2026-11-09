// A side effect is claimed durably before it may be forwarded. An existing claim is never forwarded again,
// even after a crash: only a provider reconciliation read may resolve its outcome and release its reservation.
import { execFileSync } from "node:child_process";
import { closeSync, constants, lstatSync, mkdirSync, openSync, chmodSync, readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, resolve } from "node:path";
import { digestOf } from "./crypto.ts";

export const OPERATION_META_KEY = "agent-custody/operation";
export type OperationStatus = "submitted" | "pending" | "confirmed" | "failed" | "unknown";

/**
 * A stamp that tells one process from a later process with the same PID: the kernel start time of the process.
 * The prefix names the source, so two stamps from different sources never compare equal. Returns undefined when
 * the start time cannot be read.
 */
export function processStamp(pid: number): string | undefined {
  try {
    // Linux: field 22 of /proc/<pid>/stat, in clock ticks since boot. The command name (field 2) may hold spaces.
    const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
    const field = stat.slice(stat.lastIndexOf(")") + 2).split(" ")[19];
    if (field) return `proc:${field}`;
  } catch { /* no /proc: try ps */ }
  return psStamp(pid);
}

/**
 * The start time from `ps`, for a system without /proc. `ps` prints it in local time, so the time zone is pinned to
 * UTC: a creator and an operator that run under different TZ values must still get the same text.
 */
export function psStamp(pid: number): string | undefined {
  try {
    const started = execFileSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], { encoding: "utf8", timeout: 2000, env: { LC_ALL: "C", TZ: "UTC" }, stdio: ["ignore", "pipe", "ignore"] }).trim();
    if (started) return `ps:${started}`;
  } catch { /* unreadable */ }
  return undefined;
}
let own: string | undefined;

/**
 * This process's stamp. It cannot change while the process runs, so it is read once: without /proc, a read runs `ps`,
 * and the log lock records its owner on every append. A read that failed is tried again on the next call.
 */
export function ownProcessStamp(): string | undefined {
  return own ??= processStamp(process.pid);
}

/**
 * Whether the process that created an operation may still run. A process that is gone is not alive. A live process
 * with the same PID but another start time is a different process (a container restart gives PID 1 again). When a
 * start time cannot be compared, the answer is "alive": recovery waits, and never releases a live forward.
 */
export function ownerAlive(op: Pick<OperationRecord, "ownerPid" | "ownerStart">): boolean {
  try { process.kill(op.ownerPid, 0); } catch (error) { if ((error as NodeJS.ErrnoException).code === "ESRCH") return false; }
  const now = op.ownerStart === undefined ? undefined : processStamp(op.ownerPid);
  if (op.ownerStart === undefined || now === undefined || op.ownerStart.split(":")[0] !== now.split(":")[0]) return true;
  return now === op.ownerStart;
}

export interface OperationRecord {
  id: string;
  /** Creator process on this machine. A live submitted call cannot be reconciled underneath its forward. */
  ownerPid: number;
  /** `processStamp` of the creator, so that a later process with the same PID is not taken for it. */
  ownerStart?: string;
  issuerKeyid: string;
  providerDigest?: string;
  idempotencyKey: string;
  principal: string;
  agent: string;
  tool: string;
  argsDigest: string;
  budget: string;
  currency: string;
  amount: number;
  /** UTC date on which this operation was reserved; a retry never moves it to a new budget period. */
  period: string;
  status: OperationStatus;
  originalReceiptId: string;
  /** Signed authorization or execution bundle, saved before forwarding or returning it to the caller. */
  original?: unknown;
  /** The call as the gateway decided it, kept until `original` exists. It lets recovery sign a receipt for a call that was never forwarded. Holds raw request values: keep the database private. */
  unsent?: unknown;
  result?: unknown;
  reconciliation?: unknown;
  updatedAt: string;
}

export interface OperationReservation {
  id: string;
  issuerKeyid: string;
  /** Digest of the configured upstream and destination; prevents retrying a key against a changed provider. */
  providerDigest?: string;
  principal: string;
  agent: string;
  tool: string;
  argsDigest: string;
  budget: string;
  currency: string;
  amount: number;
  limit: number;
  originalReceiptId: string;
  /** Normally omitted; the gateway always uses the current UTC date. */
  period?: string;
  /** See `OperationRecord.unsent`. */
  unsent?: unknown;
}

export interface OperationUpdate {
  status?: OperationStatus;
  original?: unknown;
  unsent?: unknown;
  result?: unknown;
  reconciliation?: unknown;
}

interface Database {
  exec(sql: string): void;
  prepare(sql: string): { get(...args: unknown[]): unknown; all(...args: unknown[]): unknown[]; run(...args: unknown[]): unknown };
  close(): void;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATUS = new Set<OperationStatus>(["submitted", "pending", "confirmed", "failed", "unknown"]);
const BINDING = ["issuerKeyid", "providerDigest", "principal", "agent", "tool", "argsDigest", "budget", "currency", "amount"] as const;

/** One owner-only SQLite database, shared by all gateway sessions/processes using the same budgets. */
export class OperationStore {
  private readonly db: Database;

  constructor(file: string) {
    const path = resolve(file);
    const directory = dirname(path);
    mkdirSync(directory, { recursive: true, mode: 0o700 });
    const dir = lstatSync(directory);
    if (!dir.isDirectory() || dir.isSymbolicLink() || (dir.mode & 0o077) !== 0) throw new Error("operation database needs an owner-only directory (0700)");
    // Create the file without following a symlink, before SQLite can open it. An existing regular file is
    // tightened to 0600; the private parent prevents another user from swapping it while SQLite opens it.
    try {
      closeSync(openSync(path, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW, 0o600));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("operation database must be a regular file, without symlinks or hard links");
    chmodSync(path, 0o600);
    // Deliberately lazy: gateways without financial operations never load SQLite (Node 22 may warn).
    const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as { DatabaseSync: new (path: string) => Database };
    this.db = new DatabaseSync(path);
    this.db.exec("PRAGMA busy_timeout = 10000; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;");
    this.db.exec("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, budget TEXT NOT NULL, currency TEXT NOT NULL, period TEXT NOT NULL, amount INTEGER NOT NULL, status TEXT NOT NULL, json TEXT NOT NULL)");
    this.db.exec("CREATE INDEX IF NOT EXISTS operations_budget_period ON operations (budget, period, status)");
  }

  get(id: string): OperationRecord | undefined {
    const row = this.db.prepare("SELECT json FROM operations WHERE id = ?").get(id) as { json: string } | undefined;
    return row ? JSON.parse(row.json) as OperationRecord : undefined;
  }

  /** Stable enumeration for an operator recovering outstanding work after a restart. */
  list(): OperationRecord[] {
    return (this.db.prepare("SELECT json FROM operations ORDER BY id").all() as { json: string }[]).map((row) => JSON.parse(row.json) as OperationRecord);
  }

  reserve(input: OperationReservation): { created: boolean; operation: OperationRecord } {
    if (!UUID.test(input.id)) throw new Error("operation id must be a lowercase UUID");
    if (!Number.isSafeInteger(input.amount) || input.amount <= 0) throw new Error("operation amount must be a positive safe integer in minor units");
    if (!Number.isSafeInteger(input.limit) || input.limit < 0) throw new Error("operation budget limit must be a nonnegative safe integer in minor units");
    for (const name of ["issuerKeyid", "principal", "agent", "tool", "argsDigest", "budget", "currency", "originalReceiptId"] as const) {
      if (typeof input[name] !== "string" || !input[name].length) throw new Error(`operation ${name} is required`);
    }
    if (input.budget.length > 128) throw new Error("operation budget id must be at most 128 characters");
    if (!/^[A-Z]{3}$/.test(input.currency)) throw new Error("operation currency must be three uppercase letters");
    const period = input.period ?? new Date().toISOString().slice(0, 10);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(period) || !Number.isFinite(Date.parse(`${period}T00:00:00.000Z`)) || new Date(`${period}T00:00:00.000Z`).toISOString().slice(0, 10) !== period) throw new Error("operation period must be a UTC date");
    return this.transaction(() => {
      const previous = this.get(input.id);
      if (previous) {
        for (const field of BINDING) {
          if (previous[field] !== input[field]) throw new Error(`operation id is already bound to different ${field}`);
        }
        return { created: false, operation: previous };
      }
      // Bind the currency even when an older operation failed or belongs to a previous day. Changing a
      // budget's unit under the same name would otherwise make its amounts incomparable.
      const otherCurrency = this.db.prepare("SELECT 1 FROM operations WHERE budget = ? AND currency <> ? LIMIT 1").get(input.budget, input.currency);
      if (otherCurrency) throw new Error("operation budget is already bound to another currency");
      // Add with BigInt: individual minor-unit amounts are safe JS integers, but a sum need not be.
      const reserved = (this.db.prepare("SELECT amount FROM operations WHERE budget = ? AND period = ? AND status <> 'failed'").all(input.budget, period) as { amount: number }[]).reduce((sum, row) => sum + BigInt(row.amount), 0n);
      if (reserved + BigInt(input.amount) > BigInt(input.limit)) throw new Error(`operation budget ${input.budget} exceeded for ${period}`);
      const ownerStart = ownProcessStamp();
      const operation: OperationRecord = {
        id: input.id,
        ownerPid: process.pid,
        ...(ownerStart !== undefined ? { ownerStart } : {}),
        issuerKeyid: input.issuerKeyid,
        ...(input.providerDigest !== undefined ? { providerDigest: input.providerDigest } : {}),
        idempotencyKey: digestOf({ issuerKeyid: input.issuerKeyid, providerDigest: input.providerDigest ?? null, tool: input.tool, principal: input.principal, agent: input.agent, id: input.id }),
        principal: input.principal,
        agent: input.agent,
        tool: input.tool,
        argsDigest: input.argsDigest,
        budget: input.budget,
        currency: input.currency,
        amount: input.amount,
        period,
        status: "submitted",
        originalReceiptId: input.originalReceiptId,
        ...(input.unsent !== undefined ? { unsent: input.unsent } : {}),
        updatedAt: new Date().toISOString(),
      };
      this.db.prepare("INSERT INTO operations (id, budget, currency, period, amount, status, json) VALUES (?, ?, ?, ?, ?, ?, ?)").run(operation.id, operation.budget, operation.currency, operation.period, operation.amount, operation.status, JSON.stringify(operation));
      return { created: true, operation };
    });
  }

  update(id: string, patch: OperationUpdate): OperationRecord {
    if (patch.status !== undefined && !STATUS.has(patch.status)) throw new Error("invalid operation status");
    return this.transaction(() => {
      const operation = this.get(id);
      if (!operation) throw new Error("operation not found");
      if ((operation.status === "confirmed" || operation.status === "failed") && patch.status !== undefined && patch.status !== operation.status) throw new Error(`operation ${operation.status} is terminal`);
      const updated = { ...operation, ...patch, updatedAt: new Date().toISOString() };
      this.db.prepare("UPDATE operations SET status = ?, json = ? WHERE id = ?").run(updated.status, JSON.stringify(updated), id);
      return updated;
    });
  }

  /**
   * Save the signed authorization of a submitted operation, and let the gateway forward. This is a compare-and-set:
   * it refuses once recovery has closed the operation or claimed a reconciliation, whatever a liveness check said,
   * so a call that recovery closed as "not forwarded" is never forwarded afterwards.
   */
  saveAuthorization(id: string, original: unknown): OperationRecord {
    return this.transaction(() => {
      const operation = this.get(id);
      if (!operation) throw new Error("operation not found");
      if (operation.status !== "submitted" || operation.reconciliation !== undefined) throw new Error(`operation was closed (${operation.status}) before its call was forwarded`);
      const updated: OperationRecord = { ...operation, original, updatedAt: new Date().toISOString() };
      delete updated.unsent;
      this.db.prepare("UPDATE operations SET json = ? WHERE id = ?").run(JSON.stringify(updated), id);
      return updated;
    });
  }

  /**
   * Persist one terminal reconciliation intent before its asynchronous log append; later reconcilers use it.
   * With `unsent`, the claim says that the call was never forwarded, and it holds only while no authorization is saved.
   */
  claimReconciliation(id: string, candidate: unknown, unsent = false): unknown {
    if (candidate === undefined || candidate === null) throw new Error("reconciliation intent is required");
    return this.transaction(() => {
      const operation = this.get(id);
      if (!operation) throw new Error("operation not found");
      if (operation.reconciliation !== undefined) return operation.reconciliation;
      if (unsent && (operation.original !== undefined || operation.status !== "submitted")) throw new Error("the operation saved its authorization meanwhile; it may have been forwarded");
      const updated = { ...operation, reconciliation: candidate, updatedAt: new Date().toISOString() };
      this.db.prepare("UPDATE operations SET json = ? WHERE id = ?").run(JSON.stringify(updated), id);
      return candidate;
    });
  }

  /** Retain the first signed/captured receipt and its private salts, so every crash/concurrent retry uses identical bytes. */
  prepareReconciliation(id: string, prepared: unknown): unknown {
    return this.transaction(() => {
      const operation = this.get(id);
      if (!operation || !operation.reconciliation) throw new Error("reconciliation intent is required");
      const reconciliation = operation.reconciliation as Record<string, unknown>;
      if (reconciliation.prepared !== undefined) return reconciliation.prepared;
      const updated = { ...operation, reconciliation: { ...reconciliation, prepared }, updatedAt: new Date().toISOString() };
      this.db.prepare("UPDATE operations SET json = ? WHERE id = ?").run(JSON.stringify(updated), id);
      return prepared;
    });
  }

  close(): void { this.db.close(); }

  private transaction<T>(body: () => T): T {
    // The write lock covers BOTH looking up the key and checking/reserving the budget. A second process
    // cannot claim the same operation or pass the same budget check while this one is committing it.
    this.db.exec("BEGIN IMMEDIATE");
    try {
      const result = body();
      this.db.exec("COMMIT");
      return result;
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
  }
}
