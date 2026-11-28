// A session's file calls (Session.runFiles): one operation on the files inside the
// session's sandbox, carried out by plimsoll's own helper as the guest's own user
// (docs/session-files.md).
//
// Every path is bytes end to end. A name in a sandbox may hold any byte but "/" and NUL,
// which is not always UTF-8, so a name a listing returns is a Uint8Array and is named back
// by the same bytes: this client never decodes, normalizes (no Unicode normalization) or
// cleans a path. A path may be given as a string for convenience: it is encoded as UTF-8,
// and a string holding a lone surrogate, which has no UTF-8 form, is refused before
// anything is sent (TextEncoder would have replaced it). A display form (pathText) is lossy
// and always beside the bytes it shows.

import { FILES_ENTRY_TYPE_NAMES, FILES_ERROR_NAMES, OUTCOME_NAMES } from "./tables.gen.ts";
import { PlimsollError } from "./errors.ts";
import { decodeFilesResult } from "./record.ts";
import { UINT32, UINT64, type WireFilesResult, type WireFilesRun } from "./wire.ts";

/** A path: bytes as they are, or text encoded as UTF-8. */
export type FilesPath = Uint8Array | string;

/** "work": a relative path from the session's work folder, a link at any part refused; "sandbox": an absolute path resolved as the guest resolves it. */
export type FilesScope = "work" | "sandbox";

/** One operation on a session's files. Each names its op; scope defaults to "work". */
export type FilesOperation =
  | { op: "stat"; path: FilesPath; scope?: FilesScope }
  /** At most maxBytes (1 to 8 MiB, default 8 MiB) of a file, from offset. */
  | { op: "read"; path: FilesPath; offset?: bigint | number; maxBytes?: number; scope?: FilesScope }
  /**
   * One file of at most 4 MiB. mode "replace" (the default, atomic), "create_only" (refused
   * with exists when the path is there) or "append" (not atomic: after a call that may have
   * run the file may have grown, so a blind retry is unsafe).
   */
  | { op: "write"; path: FilesPath; content: Uint8Array | string; mode?: "replace" | "create_only" | "append"; makeParents?: boolean; scope?: FilesScope }
  /** One page of a folder's entries; after is the last path of the page before; budgetBytes (8 KiB to 8 MiB, default 1 MiB) ends a page. */
  | { op: "list"; path?: FilesPath; recursive?: boolean; match?: FilesPath; after?: FilesPath; budgetBytes?: number; scope?: FilesScope }
  /** At most 16,384 files in order, each up to maxBytesEach (default 1 MiB), until budgetBytes (default 8 MiB) ends the answer. */
  | { op: "read_many"; paths: FilesPath[]; maxBytesEach?: number; budgetBytes?: number; scope?: FilesScope }
  | { op: "make_dir"; path: FilesPath; parents?: boolean; scope?: FilesScope }
  /** One file, or with dir one empty folder. */
  | { op: "remove"; path: FilesPath; dir?: boolean; scope?: FilesScope }
  | { op: "rename"; fromPath: FilesPath; toPath: FilesPath; replace?: boolean; scope?: FilesScope };

export type FilesOp = FilesOperation["op"];
export type FilesError = (typeof FILES_ERROR_NAMES)[number] | "unknown";
export type FilesEntryType = (typeof FILES_ENTRY_TYPE_NAMES)[number] | "unknown";

/** One entry of a listing: its path from the listed folder, as bytes, with a lossy display form beside it. */
export type FilesEntry = { path: Uint8Array; pathText: string; type: FilesEntryType; size: bigint };

/** One path's answer in a read_many, in the order asked: its bytes, or its error. */
export type FilesItem = { error: FilesError; errno: string; content: Uint8Array; sizeAtOpen: bigint };

/** An operation's answer, named by its op. make_dir, remove and rename answer nothing. */
export type FilesAnswer =
  | { op: "stat"; type: FilesEntryType; size: bigint; mode: number }
  | { op: "read"; content: Uint8Array; sizeAtOpen: bigint }
  | { op: "write"; written: bigint }
  | { op: "list"; entries: FilesEntry[]; more: boolean }
  | { op: "read_many"; items: FilesItem[]; more: boolean }
  | { op: "make_dir" | "remove" | "rename" };

/**
 * A file call's outcome and answer: outcome is "completed" when the helper answered (then
 * error says whether the operation succeeded: "none", or "not_found", "is_dir" ...),
 * "timed_out", "protocol_error" or "runner_failed"; answer is the operation's, or undefined
 * with an error or another outcome. A file that is not there is an answered not_found, not
 * a thrown error.
 */
export type FilesOutcome = {
  outcome: (typeof OUTCOME_NAMES)[number];
  error: FilesError;
  /** The errno name the error came from (ENOENT ...), "" with none. */
  errno: string;
  answer: FilesAnswer | undefined;
};

const MAX_READ = 8 << 20;

const refuse = (why: string): PlimsollError => new PlimsollError("invalid_argument", `plimsoll: invalid file call: ${why}`, { notDispatched: "request" });

/** p as the bytes sent: a Uint8Array unchanged, a string as UTF-8; a lone surrogate is refused. */
export function pathBytes(p: FilesPath, what = "path"): Uint8Array {
  if (p instanceof Uint8Array) return p;
  if (typeof p === "string") {
    if (!p.isWellFormed()) throw refuse(`the ${what} is a string with a lone surrogate, which has no UTF-8 form: pass its bytes`);
    return new TextEncoder().encode(p);
  }
  throw refuse(`the ${what} is a Uint8Array or a string`);
}

/** A lossy display form of a path: a byte that is not UTF-8 shows as U+FFFD. Never send it back as a path. */
export function pathText(p: Uint8Array): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(p);
}

const b64 = (b: Uint8Array): string => Buffer.from(b.buffer, b.byteOffset, b.byteLength).toString("base64");

function flag(v: unknown, what: string): boolean {
  if (v === undefined) return false;
  if (typeof v !== "boolean") throw refuse(`${what} is a boolean`);
  return v;
}

function count(v: unknown, what: string, top: bigint, dflt: number): string {
  const n = v === undefined ? BigInt(dflt) : typeof v === "bigint" ? v : typeof v === "number" && Number.isSafeInteger(v) ? BigInt(v) : undefined;
  if (n === undefined || n < 0n || n > top) throw refuse(`${what} is a whole number from 0 to ${top}`);
  return n.toString();
}

const SCOPES = { work: "FILES_SCOPE_WORK", sandbox: "FILES_SCOPE_SANDBOX" } as const;

/**
 * @internal The scopes a session's open states (OpenSessionResponse.fileScopes), each once, in
 * the enum's order (work, then sandbox). A value this client does not know (a newer daemon's)
 * is left out, never taken for one it is not; a statement that is not a list states none.
 */
export function statedScopes(v: unknown): readonly FilesScope[] {
  if (!Array.isArray(v)) return [];
  const has = (name: string, n: number) => v.some((x) => x === name || x === n);
  const out: FilesScope[] = [];
  if (has(SCOPES.work, 1)) out.push("work");
  if (has(SCOPES.sandbox, 2)) out.push("sandbox");
  return Object.freeze(out);
}
const MODES = { replace: "FILES_WRITE_MODE_REPLACE", create_only: "FILES_WRITE_MODE_CREATE_ONLY", append: "FILES_WRITE_MODE_APPEND" } as const;

/** @internal The operation's wire form (FilesRun). A malformed operation is refused before anything is sent. */
export function filesPayload(o: FilesOperation): WireFilesRun {
  if (o === null || typeof o !== "object") throw refuse("the operation is an object naming its op");
  // Own keys only: an inherited one ("constructor", "__proto__") names no scope or mode, and once
  // read off the table it reached the wire as a function or an object (the pre-scan clients review).
  const scopeName = o.scope ?? "work";
  const scope = Object.hasOwn(SCOPES, scopeName) ? SCOPES[scopeName as FilesScope] : undefined;
  if (scope === undefined) throw refuse('the scope is "work" or "sandbox"');
  const u32 = (v: unknown, what: string, dflt: number) => Number(count(v, what, UINT32[1], dflt));
  switch (o.op) {
    case "stat":
      return { scope, stat: { path: b64(pathBytes(o.path)) } };
    case "read":
      return { scope, read: { path: b64(pathBytes(o.path)), offset: count(o.offset, "offset", UINT64[1], 0), maxBytes: u32(o.maxBytes, "maxBytes", MAX_READ) } };
    case "write": {
      const modeName = o.mode ?? "replace";
      const mode = Object.hasOwn(MODES, modeName) ? MODES[modeName as keyof typeof MODES] : undefined;
      if (mode === undefined) throw refuse('the write mode is "replace", "create_only" or "append"');
      const content = typeof o.content === "string" ? pathBytes(o.content, "content") : o.content;
      if (!(content instanceof Uint8Array)) throw refuse("the content is a Uint8Array or a string");
      return { scope, write: { path: b64(pathBytes(o.path)), content: b64(content), mode, makeParents: flag(o.makeParents, "makeParents") } };
    }
    case "list":
      return {
        scope,
        list: {
          path: b64(pathBytes(o.path ?? ".")),
          recursive: flag(o.recursive, "recursive"),
          match: b64(pathBytes(o.match ?? "", "match")),
          after: b64(pathBytes(o.after ?? "", "after")),
          budgetBytes: u32(o.budgetBytes, "budgetBytes", 1 << 20),
        },
      };
    case "read_many":
      if (!Array.isArray(o.paths)) throw refuse("paths is an array of paths");
      return {
        scope,
        readMany: { paths: o.paths.map((p) => b64(pathBytes(p, "paths"))), maxBytesEach: u32(o.maxBytesEach, "maxBytesEach", 1 << 20), budgetBytes: u32(o.budgetBytes, "budgetBytes", MAX_READ) },
      };
    case "make_dir":
      return { scope, makeDir: { path: b64(pathBytes(o.path)), parents: flag(o.parents, "parents") } };
    case "remove":
      return { scope, remove: { path: b64(pathBytes(o.path)), dir: flag(o.dir, "dir") } };
    case "rename":
      return { scope, rename: { fromPath: b64(pathBytes(o.fromPath, "fromPath")), toPath: b64(pathBytes(o.toPath, "toPath")), replace: flag(o.replace, "replace") } };
    default:
      throw refuse(`unknown op ${JSON.stringify((o as { op?: unknown }).op)}`);
  }
}

/** The word of an enum's number, "unknown" for a number this client does not know. */
const named = <T extends readonly string[]>(names: T, n: number): T[number] | "unknown" => (names[n] as T[number] | undefined) ?? "unknown";
const errorOf = (n: number): FilesError => named(FILES_ERROR_NAMES, n);
const typeOf = (n: number): FilesEntryType => named(FILES_ENTRY_TYPE_NAMES, n);
const bytesOf = (b: Buffer): Uint8Array => new Uint8Array(b);

/**
 * @internal A file call's result as this client states it; paths and contents stay bytes.
 * Every value is the one the record's digest covered: both come from decodeFilesResult, which
 * refuses a field of the wrong type (WireShapeError) where the record check refused the answer
 * already (finding session-files-20).
 */
export function filesOutcome(f: WireFilesResult): FilesOutcome {
  const d = decodeFilesResult(f);
  const a = d.answer;
  let answer: FilesAnswer | undefined;
  switch (a?.op) {
    case "stat":
      answer = { op: "stat", type: typeOf(a.type), size: a.size, mode: a.mode };
      break;
    case "read":
      answer = { op: "read", content: bytesOf(a.content), sizeAtOpen: a.sizeAtOpen };
      break;
    case "write":
      answer = { op: "write", written: a.written };
      break;
    case "list":
      answer = {
        op: "list",
        entries: a.entries.map((e) => {
          const path = bytesOf(e.path);
          return { path, pathText: pathText(path), type: typeOf(e.type), size: e.size };
        }),
        more: a.more,
      };
      break;
    case "read_many":
      answer = {
        op: "read_many",
        items: a.items.map((it) => ({ error: errorOf(it.error), errno: it.errno, content: bytesOf(it.content), sizeAtOpen: it.sizeAtOpen })),
        more: a.more,
      };
      break;
    case "make_dir":
    case "remove":
    case "rename":
      answer = { op: a.op };
      break;
  }
  const outcome = named(OUTCOME_NAMES, d.outcome);
  return { outcome: outcome === "unknown" ? "unspecified" : outcome, error: errorOf(d.error), errno: d.errno, answer };
}

