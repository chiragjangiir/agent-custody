// One lock file design for the files that many processes write: the outbox and the local receipt log.
import { randomUUID } from "node:crypto";
import { closeSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { hostname } from "node:os";
import { ownerAlive, ownProcessStamp } from "./operations.ts";

/** A lock file that holds no readable owner is a lock that is being written. After this age it is a leftover. */
const UNREADABLE_STALE_MS = 60_000;
const pause = (ms: number) => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);

interface LockOwner { token: string; pid: number; start?: string; host: string }

function readOwner(lockFile: string): LockOwner | undefined {
  try {
    const o = JSON.parse(readFileSync(lockFile, "utf8")) as Partial<LockOwner> | null;
    return o && typeof o.token === "string" && typeof o.pid === "number" && typeof o.host === "string" ? (o as LockOwner) : undefined;
  } catch {
    return undefined;
  }
}

type Judgment = "held" | "gone" | { token: string | undefined; ino: number };

/**
 * A lock is stale when its owner on this host is gone. A live owner on this host keeps its lock, so a laptop that
 * sleeps while it holds the lock keeps it. The owner on another host, and a file with no readable owner, are judged by age.
 */
function judge(lockFile: string, staleMs: number): Judgment {
  try {
    const st = statSync(lockFile);
    const age = Date.now() - st.mtimeMs;
    const owner = readOwner(lockFile);
    const stale = { token: owner?.token, ino: st.ino };
    if (!owner) return age > UNREADABLE_STALE_MS ? stale : "held";
    if (owner.host === hostname()) return ownerAlive({ ownerPid: owner.pid, ...(owner.start ? { ownerStart: owner.start } : {}) }) ? "held" : stale;
    return age > staleMs ? stale : "held";
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "gone";
    throw e;
  }
}

/** Moves the lock away only if it is still the file that was judged stale. One breaker at a time holds `<lock>.break`. */
function breakLock(lockFile: string, judged: { token: string | undefined; ino: number }): void {
  const breaker = `${lockFile}.break`;
  try {
    closeSync(openSync(breaker, "wx", 0o600));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    try {
      if (Date.now() - statSync(breaker).mtimeMs > UNREADABLE_STALE_MS) rmSync(breaker, { force: true });
    } catch {}
    return;
  }
  try {
    // between the judgment and now, the judged owner can release and a live caller can take the lock
    if (statSync(lockFile).ino !== judged.ino || readOwner(lockFile)?.token !== judged.token) return;
    const gone = `${lockFile}.stale-${randomUUID()}`;
    renameSync(lockFile, gone);
    rmSync(gone, { force: true });
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  } finally {
    rmSync(breaker, { force: true });
  }
}

/**
 * Takes the lock with an exclusive create, and returns its release. The release removes the file only when it still
 * holds this call's token, so a holder whose lock was broken never removes the lock of the next holder. Returns
 * undefined when a live holder has the lock. A lock file that is gone between the create and the judgment is no
 * reason to break anything: the caller tries the create again.
 */
export function takeLock(lockFile: string, staleMs: number): (() => void) | undefined {
  const token = randomUUID();
  const body = JSON.stringify({ token, pid: process.pid, start: ownProcessStamp(), host: hostname() });
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const fd = openSync(lockFile, "wx", 0o600);
      try {
        writeFileSync(fd, body);
      } finally {
        closeSync(fd);
      }
      return () => {
        if (readOwner(lockFile)?.token === token) rmSync(lockFile, { force: true });
      };
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    }
    const j = judge(lockFile, staleMs);
    if (j === "held") return undefined;
    if (j !== "gone") breakLock(lockFile, j);
  }
  return undefined;
}

/** Runs `fn` under the lock. Waits up to `waitMs` for a live holder, then throws. */
export function withLock<T>(lockFile: string, opts: { staleMs: number; waitMs: number }, fn: () => T): T {
  const deadline = Date.now() + opts.waitMs;
  for (;;) {
    const release = takeLock(lockFile, opts.staleMs);
    if (release) {
      try {
        return fn();
      } finally {
        release();
      }
    }
    if (Date.now() > deadline) throw new Error(`${lockFile} is held by another process, so the file is not written. Remove the lock file if no agent-custody process runs.`);
    pause(2 + Math.random() * 8);
  }
}
