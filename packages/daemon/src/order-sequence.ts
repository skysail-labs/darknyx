/**
 * Durable high-water mark for deterministic order ids and trading keys.
 *
 * The daemon's SQLite database is a rebuildable cache. Keeping the next HD
 * index there made deleting that cache silently reuse index zero. This small,
 * authenticated sidecar is deliberately a separate recovery root: reserve()
 * durably advances it before an order is proved or signed, so crashes can
 * create harmless gaps but cannot reuse an index.
 */

import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import fs from "node:fs";
import { basename, dirname, join } from "node:path";

const DOMAIN = Buffer.from("darknyx-daemon-order-sequence/v1\0", "utf8");
const MAX_FILE_BYTES = 1024;
const MAX_INDEX = 0xffff_ffff;
const MAX_NEXT_INDEX = 0x1_0000_0000;

interface SequenceFileV1 {
  version: 1;
  next_index: number;
  tag: string;
}

export interface OrderSequence {
  /** Persist the advance first, then return the index reserved by this call. */
  reserve(): number;
  /** Advance to at least this value (used only for one-time DB migration). */
  advanceTo(nextIndex: number): void;
  readonly nextIndex: number;
}

function assertNextIndex(value: number, label: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_NEXT_INDEX) {
    throw new Error(`${label} must be an integer in 0..${MAX_NEXT_INDEX}`);
  }
}

function tagFor(masterSeed: Uint8Array, nextIndex: number): Buffer {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(nextIndex));
  return createHmac("sha256", masterSeed)
    .update(DOMAIN)
    .update(counter)
    .digest();
}

function encode(masterSeed: Uint8Array, nextIndex: number): string {
  const file: SequenceFileV1 = {
    version: 1,
    next_index: nextIndex,
    tag: tagFor(masterSeed, nextIndex).toString("hex"),
  };
  return `${JSON.stringify(file)}\n`;
}

function atomicReplace(path: string, contents: string): void {
  const directory = dirname(path);
  const tempPath = join(
    directory,
    `.${basename(path)}.${process.pid}.${randomBytes(8).toString("hex")}.tmp`,
  );
  let fd: number | undefined;
  let directoryFd: number | undefined;
  try {
    fd = fs.openSync(tempPath, "wx", 0o600);
    fs.writeFileSync(fd, contents, "utf8");
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tempPath, path);
    fs.chmodSync(path, 0o600);
    directoryFd = fs.openSync(directory, "r");
    fs.fsyncSync(directoryFd);
  } catch (error) {
    if (fd !== undefined) fs.closeSync(fd);
    try {
      fs.unlinkSync(tempPath);
    } catch {
      // The rename may already have installed the complete file.
    }
    throw error;
  } finally {
    if (directoryFd !== undefined) fs.closeSync(directoryFd);
  }
}

function parse(path: string, masterSeed: Uint8Array): number {
  const stat = fs.statSync(path);
  if (!stat.isFile() || stat.size <= 0 || stat.size > MAX_FILE_BYTES) {
    throw new Error(`order-sequence file must be 1..${MAX_FILE_BYTES} bytes`);
  }
  if ((stat.mode & 0o077) !== 0) {
    throw new Error(
      `order-sequence ${path} is group/world-accessible; run: chmod 600 ${path}`,
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(fs.readFileSync(path, "utf8"));
  } catch {
    throw new Error("order-sequence file is not valid JSON");
  }
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("order-sequence file must be an object");
  }
  const file = value as Record<string, unknown>;
  if (
    Object.keys(file).sort().join(",") !== "next_index,tag,version" ||
    file.version !== 1 ||
    typeof file.next_index !== "number" ||
    typeof file.tag !== "string" ||
    !/^[0-9a-f]{64}$/.test(file.tag)
  ) {
    throw new Error("unsupported or malformed order-sequence file");
  }
  assertNextIndex(file.next_index, "next_index");
  const actual = Buffer.from(file.tag, "hex");
  const expected = tagFor(masterSeed, file.next_index);
  if (!timingSafeEqual(actual, expected)) {
    throw new Error("order-sequence authentication failed");
  }
  return file.next_index;
}

export class DurableOrderSequence implements OrderSequence {
  private value: number;

  private constructor(
    private readonly path: string,
    private readonly masterSeed: Uint8Array,
    nextIndex: number,
  ) {
    this.value = nextIndex;
  }

  static create(
    path: string,
    masterSeed: Uint8Array,
    nextIndex = 0,
    overwrite = false,
  ): DurableOrderSequence {
    assertNextIndex(nextIndex, "nextIndex");
    if (fs.existsSync(path) && !overwrite) {
      throw new Error(`${path} exists; refusing to replace order sequence`);
    }
    atomicReplace(path, encode(masterSeed, nextIndex));
    return new DurableOrderSequence(path, masterSeed, nextIndex);
  }

  static open(path: string, masterSeed: Uint8Array): DurableOrderSequence {
    return new DurableOrderSequence(path, masterSeed, parse(path, masterSeed));
  }

  get nextIndex(): number {
    return this.value;
  }

  reserve(): number {
    if (this.value > MAX_INDEX) {
      throw new Error("order-sequence exhausted");
    }
    const reserved = this.value;
    this.persist(this.value + 1);
    return reserved;
  }

  advanceTo(nextIndex: number): void {
    assertNextIndex(nextIndex, "nextIndex");
    if (nextIndex > this.value) this.persist(nextIndex);
  }

  private persist(nextIndex: number): void {
    atomicReplace(this.path, encode(this.masterSeed, nextIndex));
    this.value = nextIndex;
  }
}

/** Test/embedding seam. Production entrypoints always use the durable file. */
export class MemoryOrderSequence implements OrderSequence {
  constructor(private value = 0) {
    assertNextIndex(value, "nextIndex");
  }

  get nextIndex(): number {
    return this.value;
  }

  reserve(): number {
    if (this.value > MAX_INDEX) throw new Error("order-sequence exhausted");
    return this.value++;
  }

  advanceTo(nextIndex: number): void {
    assertNextIndex(nextIndex, "nextIndex");
    if (nextIndex > this.value) this.value = nextIndex;
  }
}
