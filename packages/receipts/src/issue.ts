// Signing, logging and writing a receipt. Shared by every producer: the gateway and the SDK.
import { chmodSync, closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import { RECEIPT_ID, SALTS_DIR, saltsFileFor } from "./retention.ts";
import { dirname, join } from "node:path";
import { effectiveRule, getAt, privateView, type CaptureConfig, type CaptureContext, type PrivateView } from "./capture.ts";
import { canonicalize, dsseSign, dsseVerify, type Envelope, type KeyPair } from "./crypto.ts";
import { fileLog, type LogSink } from "./log-sink.ts";
import { takeLock } from "./lock.ts";
import type { ReceiptExporter } from "./otel.ts";
import { buildAuthorizationStatement, buildStatement, RECEIPT_TYPE, type AuthorizationBundle, type AuthorizationPredicate, type ReceiptBundle, type ReceiptPredicate } from "./receipt.ts";

/** Private recovery data: includes commitment salts. Persist only in an owner-only store, never in a receipt or export. */
export interface PreparedReceipt {
  envelope: Envelope;
  view: PrivateView<ReceiptPredicate>;
}

/** The receipts whose log append failed wait here, signed, until `flushOutbox` appends them. */
export const OUTBOX_DIR = "outbox";

/** What one `flushOutbox` did. `foreign` entries are signed by another key and stay in the outbox. */
export interface FlushResult {
  sent: number;
  pending: number;
  setAside: number;
  foreign: number;
  error?: string;
}

/**
 * Thrown by `issue` with `deferLog` when the log did not take the receipt. The signed receipt is kept in the outbox and
 * no bundle is written yet: `flushOutbox` appends it later and then writes the bundle.
 */
export class ReceiptPending extends Error {
  readonly receiptId: string;
  constructor(receiptId: string, cause: unknown) {
    super(`receipt ${receiptId} is kept in the outbox; its log append is pending: ${cause instanceof Error ? cause.message : String(cause)}`, { cause });
    this.name = "ReceiptPending";
    this.receiptId = receiptId;
  }
}

export interface Issuer {
  keyid: string;
  log: LogSink;
  /**
   * Applies the tool's capture rule to the whole predicate, signs the statement, appends it to the log, writes the
   * bundle. Rejects if the log refuses the leaf; no bundle is written then. The predicate is the call in full; what
   * is signed, written, and exported is the view.
   */
  issue(predicate: ReceiptPredicate, ctx?: CaptureContext, retainPrepared?: (prepared: PreparedReceipt) => PreparedReceipt, opts?: { deferLog?: boolean }): Promise<ReceiptBundle>;
  /** The same for an authorization, signed and committed before a consequential call is forwarded. Rejects if the log refuses; the caller must then not forward. */
  authorize(predicate: AuthorizationPredicate, ctx?: CaptureContext): Promise<AuthorizationBundle>;
  /**
   * Appends each receipt in the outbox, oldest statement first, and writes its bundle. A log refusal stops the flush;
   * another failure is reported in `error` and the flush goes on. One flush runs at a time in a process, and a lock
   * file in the outbox keeps other processes out: when another process holds it, nothing is done. An entry that is
   * damaged, or that this issuer's key signed under another receipt id, is renamed to `<name>.bad` and counted in
   * `setAside`. An entry signed by another key stays in the outbox and is counted in `foreign`.
   */
  flushOutbox(): Promise<FlushResult>;
  /** the receipts in the outbox */
  pending(): number;
}

export interface IssuerOptions {
  /** told about every receipt after it is written; an exporter's failure never reaches the caller */
  exporter?: ReceiptExporter | undefined;
  /** private evidence: the capture rules by tool, and the key that encrypts (`captureKeyEnv`), applied here to every statement before it is signed */
  capture?: { rules?: CaptureConfig | undefined; key?: Buffer | undefined } | undefined;
}

/** `log` is a sink, or a file path for the local log with tree heads signed by the issuer's key. */
export function createIssuer(key: KeyPair, receiptsDir: string, log: string | LogSink, opts: IssuerOptions = {}): Issuer {
  const sink = typeof log === "string" ? fileLog(log, key) : log;
  mkdirSync(receiptsDir, { recursive: true });
  const view = <P extends AuthorizationPredicate>(predicate: P, ctx?: CaptureContext, prior?: PrivateView<AuthorizationPredicate>) => privateView(predicate, effectiveRule(opts.capture?.rules, predicate.tool.name, ctx?.unknownTool), opts.capture?.key, ctx, prior);
  /** the salts directory, checked before anything is signed or appended, so that a problem with it costs no leaf in the log */
  const saltsDir = join(receiptsDir, SALTS_DIR);
  const ensureSaltsDir = () => {
    if (!opts.capture?.rules) return;
    // mkdir's mode applies only to a directory it creates: one that was there keeps its own, so it is set after
    mkdirSync(saltsDir, { recursive: true, mode: 0o700 });
    // the directory is the issuer's own: a link left at that name would carry every salt elsewhere
    if (lstatSync(saltsDir).isSymbolicLink()) throw new Error(`${saltsDir} is a symbolic link; the salts are not written through it`);
    chmodSync(saltsDir, 0o700);
  };
  /**
   * The view committed in an authorization, by receipt id, until its receipt is issued: the receipt carries the same
   * commitments and salts for the parts they share. Set once the log has taken the authorization, released when the
   * receipt is issued, and bounded: a call that never reaches its receipt does not keep its view for ever.
   */
  const committed = new Map<string, { view: PrivateView<AuthorizationPredicate>; at: number }>();
  /** an authorization whose receipt has not followed within this long is a call that died; its view is let go */
  const COMMITTED_FOR_MS = 60 * 60 * 1000;
  const COMMITTED_AT_MOST = 100_000;
  /** a lock that its owner has not touched for this long is broken, whatever machine the owner is on */
  const LOCK_STALE_MS = 15 * 60 * 1000;
  const outboxDir = join(receiptsDir, OUTBOX_DIR);
  const outboxed = () => existsSync(outboxDir) ? readdirSync(outboxDir).filter((f) => f.endsWith(".json") && RECEIPT_ID.test(f.slice(0, -".json".length))) : [];
  /** the outbox in the order of the signed statements' timestamps; an entry that cannot be read sorts first and is dealt with when its turn comes */
  const outboxOrdered = () => outboxed().map((f) => {
    let at = 0;
    try {
      const env = (JSON.parse(readFileSync(join(outboxDir, f), "utf8")) as { envelope: Envelope }).envelope;
      at = Date.parse((JSON.parse(Buffer.from(env.payload, "base64").toString("utf8")) as { predicate: { timestamp: string } }).predicate.timestamp) || 0;
    } catch { /* unreadable: at stays 0 */ }
    return { f, at };
  }).sort((a, b) => a.at - b.at || (a.f < b.f ? -1 : 1)).map((e) => e.f);
  /** the file is whole or absent, and on disk before the caller goes on: it can be the only copy of the evidence */
  const writeDurable = (file: string, text: string) => {
    const fd = openSync(`${file}.tmp`, "w");
    try {
      writeFileSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(`${file}.tmp`, file);
    syncDir(dirname(file));
  };
  const syncDir = (dir: string) => {
    const fd = openSync(dir, "r");
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  };
  const lockFile = join(outboxDir, ".lock");
  /** Undefined when another flusher holds the lock. A lock whose owner is gone, or that no one has touched for a long time, is broken. */
  const takeOutboxLock = () => takeLock(lockFile, LOCK_STALE_MS);
  const writeBundle = async (receiptId: string, v: ReceiptPredicate, bundle: ReceiptBundle) => {
    const file = join(receiptsDir, `${receiptId}.json`);
    // whole or absent: a flush takes a bundle that is there as proof that the outbox entry is done
    writeFileSync(`${file}.tmp`, JSON.stringify(bundle, null, 2));
    renameSync(`${file}.tmp`, file);
    // After the evidence, not before, and awaited so a process that exits right after issuing still exports. The
    // exporter sees the view, never the full call.
    if (opts.exporter) await opts.exporter.exported(v, bundle).catch(() => {});
  };
  let flushing: Promise<FlushResult> | undefined;
  /** the log's answer for a receipt whose bundle could not be written yet: a retry in this process writes the bundle and does not append again */
  const appended = new Map<string, Awaited<ReturnType<LogSink["append"]>>>();
  /**
   * The salts behind a statement's digest-only commitments, kept beside the receipts and never in them:
   * `receipts/salts/<id>.json`, the owner's alone. They are what makes a disclosure possible for a value withheld
   * without its value, and what a reviewer must not be handed, since with them a guess can be confirmed. An encrypted
   * commitment carries its salt inside the ciphertext, so that salt is not written: the key alone recovers it.
   */
  const keepSalts = (v: PrivateView<AuthorizationPredicate>) => {
    const salts = Object.fromEntries((v.predicate.capture?.withheld ?? []).filter((w) => (getAt(v.predicate, w) as { $custody?: string } | undefined)?.$custody === "withheld").map((w) => [JSON.stringify(w), v.salts[JSON.stringify(w)]!]));
    if (!Object.keys(salts).length) return;
    writeFileSync(saltsFileFor(receiptsDir, v.predicate.receiptId), JSON.stringify({ receiptId: v.predicate.receiptId, salts }, null, 2), { mode: 0o600 });
  };
  return {
    keyid: key.keyid,
    log: sink,
    async issue(predicate, ctx, retainPrepared, issueOpts) {
      ensureSaltsDir();
      // the authorization's view stays until the log has taken the receipt: a producer that retries after a refusal gets the same commitments and salts
      const prior = committed.get(predicate.receiptId)?.view;
      const candidate = view(predicate, ctx, prior);
      // A durable producer may retain the first signed view, salts included, before any append. Concurrent and
      // restarted issuers then commit exactly those bytes rather than re-salting the same logical receipt.
      const prepared = retainPrepared ? retainPrepared({ envelope: dsseSign(RECEIPT_TYPE, buildStatement(candidate.predicate), key), view: candidate }) : { envelope: dsseSign(RECEIPT_TYPE, buildStatement(candidate.predicate), key), view: candidate };
      const pv = prepared.view;
      const v = pv.predicate;
      const envelope = prepared.envelope;
      if (retainPrepared) {
        const checked = dsseVerify(envelope, [key]);
        if (!checked.ok || envelope.payloadType !== RECEIPT_TYPE || v.receiptId !== predicate.receiptId || canonicalize(checked.payload) !== canonicalize(buildStatement(v))) throw new Error("prepared receipt does not match this issuer, predicate, or receipt id");
      }
      let entry: Awaited<ReturnType<LogSink["append"]>>;
      try {
        entry = await sink.append(canonicalize(envelope));
      } catch (e) {
        if (!issueOpts?.deferLog) throw e;
        // The call has happened, so its receipt is kept: signed, with its salts, and appended later. The salts go
        // first, so an outbox entry never lacks them; the rename makes the entry whole or absent.
        try {
          keepSalts(pv);
          mkdirSync(outboxDir, { recursive: true });
          writeDurable(join(outboxDir, `${predicate.receiptId}.json`), JSON.stringify({ envelope }));
          syncDir(receiptsDir);
        } catch (w) {
          throw new Error(`${e instanceof Error ? e.message : String(e)}; the receipt could not be kept in the outbox either: ${w instanceof Error ? w.message : String(w)}`, { cause: e });
        }
        committed.delete(predicate.receiptId);
        throw new ReceiptPending(predicate.receiptId, e);
      }
      committed.delete(predicate.receiptId);
      // the salts once the log has taken the leaf: a receipt the log refused leaves nothing behind
      keepSalts(pv);
      const bundle: ReceiptBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      await writeBundle(predicate.receiptId, v, bundle);
      return bundle;
    },
    async authorize(predicate, ctx) {
      ensureSaltsDir();
      const pv = view(predicate, ctx);
      const v = pv.predicate;
      const envelope = dsseSign(RECEIPT_TYPE, buildAuthorizationStatement(v), key);
      const entry = await sink.append(canonicalize(envelope));
      // committed: the receipt that follows shares this view; nothing is kept for an authorization the log refused
      const now = Date.now();
      for (const [id, c] of committed) {
        if (now - c.at <= COMMITTED_FOR_MS) break;
        committed.delete(id);
      }
      committed.set(predicate.receiptId, { view: pv, at: now });
      if (committed.size > COMMITTED_AT_MOST) committed.delete(committed.keys().next().value!);
      keepSalts(pv);
      const bundle: AuthorizationBundle = { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion };
      // On disk in its own right: if the process dies between forwarding and the receipt, this is the evidence that the call was authorized and sent.
      writeFileSync(join(receiptsDir, `${predicate.receiptId}.authorization.json`), JSON.stringify(bundle, null, 2));
      return bundle;
    },
    pending: () => outboxed().length,
    flushOutbox() {
      flushing ??= (async (): Promise<FlushResult> => {
        const idle = (): FlushResult => ({ sent: 0, pending: outboxed().length, setAside: 0, foreign: 0 });
        if (!outboxed().length) return idle();
        const release = takeOutboxLock();
        if (!release) return idle();
        try {
          let sent = 0;
          let setAside = 0;
          let foreign = 0;
          const errors: string[] = [];
          const done = () => ({ sent, pending: outboxed().length, setAside, foreign, ...(errors.length ? { error: errors.length === 1 ? errors[0]! : `${errors[0]} (and ${errors.length - 1} more)` } : {}) });
          const setAsideFile = (file: string) => {
            try {
              renameSync(file, `${file}.bad`);
              setAside++;
            } catch (e) {
              if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
            }
          };
          for (const f of outboxOrdered()) {
            const receiptId = f.slice(0, -".json".length);
            const file = join(outboxDir, f);
            try {
              // a bundle already there means the append and the write happened and only the removal did not
              if (existsSync(join(receiptsDir, f))) { rmSync(file, { force: true }); appended.delete(receiptId); sent++; continue; }
              let record: { envelope: Envelope; appended?: Awaited<ReturnType<LogSink["append"]>> };
              try {
                record = JSON.parse(readFileSync(file, "utf8")) as typeof record;
              } catch (e) {
                // gone: another flusher took it; anything else that is not readable JSON is damaged
                if ((e as NodeJS.ErrnoException).code === "ENOENT") continue;
                if (!(e instanceof SyntaxError)) throw e;
                setAsideFile(file);
                continue;
              }
              const envelope = record?.envelope;
              if (typeof envelope?.payload !== "string" || !Array.isArray(envelope.signatures) || envelope.signatures.length === 0) { setAsideFile(file); continue; }
              // a signature by another key proves nothing about this entry (a rotated key, a restored backup): it stays, and is reported
              if (!envelope.signatures.some((sig) => sig?.keyid === key.keyid)) { foreign++; continue; }
              // only this issuer's own receipt, under its own id, goes to the log; anything else is set aside, not retried
              const checked = dsseVerify(envelope, [key]);
              const statement = (checked.ok ? checked.payload : undefined) as { predicate: ReceiptPredicate } | undefined;
              if (!statement || envelope.payloadType !== RECEIPT_TYPE || statement.predicate?.receiptId !== receiptId) { setAsideFile(file); continue; }
              let entry = record.appended ?? appended.get(receiptId);
              if (!entry) {
                try {
                  entry = await sink.append(canonicalize(envelope));
                } catch (e) {
                  errors.push(e instanceof Error ? e.message : String(e));
                  return done();
                }
                // Until the bundle is written, the answer is the only proof that the log has the leaf. It is kept in
                // memory and in the entry, so that a failure now does not make the next flush append the leaf again.
                appended.set(receiptId, entry);
                try {
                  writeDurable(file, JSON.stringify({ envelope, appended: entry }));
                } catch (e) {
                  errors.push(`receipt ${receiptId} is in the log, but its outbox entry could not record that: ${e instanceof Error ? e.message : String(e)}`);
                }
              }
              await writeBundle(receiptId, statement.predicate, { envelope, treeHead: entry.treeHead, inclusion: entry.inclusion });
              rmSync(file, { force: true });
              appended.delete(receiptId);
              sent++;
              try { utimesSync(lockFile, new Date(), new Date()); } catch { /* the lock is only a hint */ }
            } catch (e) {
              if ((e as NodeJS.ErrnoException).code === "ENOENT" && !existsSync(file)) continue;
              errors.push(`outbox entry ${f}: ${e instanceof Error ? e.message : String(e)}`);
            }
          }
          return done();
        } finally {
          release();
        }
      })().finally(() => { flushing = undefined; });
      return flushing;
    },
  };
}
