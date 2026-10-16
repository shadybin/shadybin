/**
 * Verifies shadybin statements: that a release file was rebuilt byte for byte from its
 * tagged source and passed review. This is what an updater calls before it installs a
 * release.
 *
 * No dependencies: Ed25519 is WebCrypto's, in Node 20+, Deno, Bun and browsers. No I/O:
 * fetch the release's statement and signature file from the registry (statementUrl,
 * signatureUrl) and hand over the bytes.
 *
 * ```ts
 * import { verify, defaultKeys, statementUrl, signatureUrl, DEFAULT_REGISTRY, Rejected } from "@shadybin/verify";
 *
 * const get = async (u: string) => new Uint8Array(await (await fetch(u)).arrayBuffer()); // a 404: not certified yet
 * try {
 *   await verify(await get(statementUrl(DEFAULT_REGISTRY, repo, tag)), await get(signatureUrl(DEFAULT_REGISTRY, repo, tag)),
 *     defaultKeys(), repo, tag, "tool_Linux_x86_64.tar.gz", new Uint8Array(await crypto.subtle.digest("SHA-256", archive)));
 * } catch (e) {
 *   if (e instanceof Rejected) { } // reviewed and refused: never install, do not ask again
 *   // otherwise not certified: do not install
 * }
 * ```
 *
 * See spec/SPEC.md in https://github.com/shadybin/shadybin.
 */

/** Where shadybin publishes statements. */
export const DEFAULT_REGISTRY = "https://shadybin.dev/registry";

/** shadybin's signing keys, the public halves, hex. During a rotation there are two. */
export const KEY_HEX: readonly string[] = ["d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc"];

const HEADER = "shadybin statement v1";
const MAX_STATEMENT = 1 << 20;
const MAX_SIGNATURE = 4096;
const NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]*$/;
const SEGMENT = /^[a-z0-9][a-z0-9._-]*$/;
const HEX64 = /^[0-9a-f]{64}$/;
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

/**
 * The file is not certified: do not install it. A missing statement (a 404 from the
 * registry) means not certified *yet*: wait and ask again, and do not fall back to
 * another release.
 */
export class ShadybinError extends Error {
  readonly code: string = "not_certified";
}
/** No line of the signature file is a signature over the statement by a pinned key. */
export class BadSignature extends ShadybinError {
  override readonly code = "bad_signature";
}
/** The statement is signed but is not a statement this package reads. */
export class BadStatement extends ShadybinError {
  override readonly code = "bad_statement";
}
/** The statement is for another repository or tag than asked. */
export class WrongRelease extends ShadybinError {
  override readonly code = "wrong_release";
}
/** shadybin reviewed the release and rejected it. This is final. */
export class Rejected extends ShadybinError {
  override readonly code = "rejected";
}
/** The release is certified, but not with this file and digest. */
export class NotListed extends ShadybinError {
  override readonly code = "not_listed";
}

/** A parsed statement. */
export interface Statement {
  repo: string;
  tag: string;
  verdict: "certified" | "rejected";
  report: Uint8Array;
  manifest: Uint8Array;
  review: Uint8Array;
  /** The release's files and their digests, sorted by name. */
  files: ReadonlyArray<readonly [name: string, digest: Uint8Array]>;
}

/**
 * Checks a release's statement and signature file, as fetched from the registry: the
 * signature against the pinned keys, that the statement is for repo and tag, that its
 * verdict is certified, and that it lists the file name with digest. Resolves when all
 * hold; rejects with a ShadybinError at the first check that fails.
 */
export async function verify(
  statement: Uint8Array,
  signature: Uint8Array,
  keys: readonly Uint8Array[],
  repo: string,
  tag: string,
  name: string,
  digest: Uint8Array,
): Promise<void> {
  const s = await openStatement(statement, signature, keys);
  if (s.repo !== repo.toLowerCase() || s.tag !== tag) {
    throw new WrongRelease(`the statement is for ${s.repo} ${s.tag}`);
  }
  if (s.verdict !== "certified") {
    throw new Rejected(`shadybin rejected ${s.repo} ${s.tag} on review`);
  }
  const listed = s.files.find(([n]) => n === name)?.[1];
  if (!listed || !equal(listed, digest)) {
    throw new NotListed(`${s.repo} ${s.tag} does not certify ${name} with that digest`);
  }
}

/**
 * Checks the signature file against the pinned keys, then parses the statement. One line
 * per signature: a statement signed while a key is rotated carries one per key.
 */
export async function openStatement(statement: Uint8Array, signature: Uint8Array, keys: readonly Uint8Array[]): Promise<Statement> {
  if (signature.length > MAX_SIGNATURE) throw new BadSignature("signature file too large");
  const imported = await Promise.all(
    keys.map((k) => crypto.subtle.importKey("raw", owned(k), { name: "Ed25519" }, false, ["verify"])),
  );
  const message = owned(statement);
  for (const raw of new TextDecoder().decode(signature).split("\n")) {
    const line = raw.trim();
    if (!BASE64.test(line)) continue;
    const sig = Uint8Array.from(atob(line), (c) => c.charCodeAt(0));
    if (sig.length !== 64) continue;
    for (const k of imported) {
      if (await crypto.subtle.verify({ name: "Ed25519" }, k, sig, message)) {
        return parseStatement(statement);
      }
    }
  }
  throw new BadSignature("no signature by a pinned key");
}

/**
 * Parses a statement, accepting only its canonical encoding: every line exact, files
 * sorted by name, each name once.
 */
export function parseStatement(data: Uint8Array): Statement {
  const bad = () => new BadStatement("not a canonical shadybin statement");
  if (data.length > MAX_STATEMENT || data[data.length - 1] !== 0x0a) throw bad();
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(0, data.length - 1));
  } catch {
    throw bad();
  }
  const lines = text.split("\n");
  const fields = ["repo", "tag", "verdict", "report", "manifest", "review"] as const;
  if (lines.length < 2 + fields.length || lines[0] !== HEADER) throw bad();
  const v: Record<string, string> = {};
  fields.forEach((f, i) => {
    const line = lines[1 + i]!;
    if (!line.startsWith(f + " ")) throw bad();
    v[f] = line.slice(f.length + 1);
  });
  const repo = v.repo!;
  const segments = repo.split("/");
  if (segments.length < 3 || !segments.every((s) => SEGMENT.test(s))) throw bad();
  if (!NAME.test(v.tag!) || (v.verdict !== "certified" && v.verdict !== "rejected")) throw bad();
  const files: (readonly [string, Uint8Array])[] = [];
  for (const line of lines.slice(1 + fields.length)) {
    const parts = line.split(" ");
    if (parts.length !== 3 || parts[0] !== "file" || !NAME.test(parts[2]!)) throw bad();
    // Names are ASCII, so string order is byte order.
    if (files.length > 0 && files[files.length - 1]![0] >= parts[2]!) throw bad();
    files.push([parts[2]!, parseDigest(parts[1]!)]);
  }
  if (files.length === 0) throw bad();
  return {
    repo,
    tag: v.tag!,
    verdict: v.verdict as "certified" | "rejected",
    report: parseDigest(v.report!),
    manifest: parseDigest(v.manifest!),
    review: parseDigest(v.review!),
    files,
  };
}

/** Reads a digest as a statement writes it: sha256: and 64 lowercase hex digits. */
export function parseDigest(text: string): Uint8Array {
  if (!text.startsWith("sha256:") || !HEX64.test(text.slice(7))) {
    throw new BadStatement(`digest ${JSON.stringify(text)}: want sha256:<64 lowercase hex>`);
  }
  return fromHex(text.slice(7));
}

/** Reads a public key as shadybin publishes it: 64 hex digits. */
export function parseKey(hex: string): Uint8Array {
  if (!HEX64.test(hex.toLowerCase())) throw new Error("a public key is 64 hex digits");
  return fromHex(hex.toLowerCase());
}

/** shadybin's public keys, to pass to verify. */
export function defaultKeys(): Uint8Array[] {
  return KEY_HEX.map(parseKey);
}

/** The registry URL of a release's statement. The repository is lowercased, as the registry holds it. */
export function statementUrl(registry: string, repo: string, tag: string): string {
  return releaseUrl(registry, repo, tag, "statement.txt");
}

/** The registry URL of a release's signature file, beside its statement. */
export function signatureUrl(registry: string, repo: string, tag: string): string {
  return releaseUrl(registry, repo, tag, "statement.txt.sig");
}

function releaseUrl(registry: string, repo: string, tag: string, file: string): string {
  return `${registry.replace(/\/+$/, "")}/${repo.toLowerCase()}/${tag}/${file}`;
}

/** A copy in its own ArrayBuffer, as WebCrypto takes: the caller's may be shared. */
function owned(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(bytes);
}

function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
