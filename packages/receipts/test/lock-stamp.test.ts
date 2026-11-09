// The log lock records its owner's start time so that a later process with the same PID is not taken for the owner.
// That time cannot change while a process runs, but reading it runs `ps` where there is no /proc, about a millisecond
// on every log append. The test fails if the lock reads it again for each append, or records anything but this
// process's real start time. Every read starts with /proc/<pid>/stat, on Linux and macOS alike, so that is what is counted.
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

const reads = vi.hoisted(() => ({ own: 0 }));
vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const readFileSync = ((path: unknown, ...rest: unknown[]) => {
    if (path === `/proc/${process.pid}/stat`) reads.own++;
    return (fs.readFileSync as (...a: unknown[]) => unknown)(path, ...rest);
  }) as typeof fs.readFileSync;
  return { ...fs, default: { ...fs, readFileSync }, readFileSync };
});

const { takeLock } = await import("../src/lock.ts");
const { MerkleLog } = await import("../src/log.ts");
const { processStamp } = await import("../src/operations.ts");

describe("the owner stamp of the log lock", () => {
  it("is read once per process, not once per append, and is this process's start time", () => {
    const dir = mkdtempSync(join(tmpdir(), "lock-stamp-"));
    const log = new MerkleLog(join(dir, "log.jsonl"));
    for (let i = 0; i < 5; i++) log.append(`leaf ${i}`);
    expect(reads.own).toBe(1);

    const lockFile = join(dir, "x.lock");
    const release = takeLock(lockFile, 60_000)!;
    const body = JSON.parse(readFileSync(lockFile, "utf8")) as { pid: number; start?: string };
    release();
    expect(reads.own).toBe(1);
    expect(body.pid).toBe(process.pid);
    expect(body.start).toBe(processStamp(process.pid));
    expect(body.start).toMatch(/^(proc|ps):./);
  });
});
