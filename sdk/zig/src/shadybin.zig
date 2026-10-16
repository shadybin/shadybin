//! Verifies shadybin statements: that a release file was rebuilt byte for byte from its
//! tagged source and passed review. This is what an updater calls before it installs a
//! release. It uses the standard library only and allocates nothing: the caller fetches
//! the statement and its signature file from the registry (statementUrl, signatureUrl) and
//! hands over the bytes. See spec/SPEC.md in github.com/shadybin/shadybin.

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// A SHA-256 digest.
pub const Digest = [Sha256.digest_length]u8;

/// A shadybin public key, to pin in the binary.
pub const PublicKey = Ed25519.PublicKey;

/// Where shadybin publishes statements.
pub const default_registry = "https://shadybin.dev/registry";

/// shadybin's signing keys, the public halves, hex. During a rotation there are two.
pub const key_hex = [_][]const u8{"d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc"};

/// shadybin's public keys, parsed, to pass to verify.
pub fn defaultKeys() [key_hex.len]PublicKey {
    var keys: [key_hex.len]PublicKey = undefined;
    for (key_hex, 0..) |h, i| keys[i] = parseKey(h) catch unreachable;
    return keys;
}

/// Why a file is not certified, in the order the checks run. Every error means: do not
/// install. A missing statement (a 404 from the registry) means not certified *yet*: wait
/// and ask again, and do not fall back to another release.
pub const Error = error{
    /// No line of the signature file is a signature over the statement by a pinned key.
    BadSignature,
    /// The statement is signed but is not a statement this SDK reads.
    BadStatement,
    /// The statement is for another repository or tag than asked.
    WrongRelease,
    /// shadybin reviewed the release and rejected it. This is final.
    Rejected,
    /// The release is certified, but not with this file and digest.
    NotListed,
};

pub const Verdict = enum { certified, rejected };

/// A statement, its fields pointing into the bytes it was parsed from.
pub const Statement = struct {
    repo: []const u8,
    tag: []const u8,
    verdict: Verdict,
    report: Digest,
    manifest: Digest,
    review: Digest,
    /// The file lines, already checked: use find.
    files: []const u8,

    /// Returns the digest the statement lists for a file, or null.
    pub fn find(s: Statement, name: []const u8) ?Digest {
        var it = std.mem.splitScalar(u8, s.files, '\n');
        while (it.next()) |line| {
            if (line.len == 0) continue;
            const f = parseFileLine(line) catch return null;
            if (std.mem.eql(u8, f.name, name)) return f.digest;
        }
        return null;
    }
};

const header = "shadybin statement v1";
const max_statement = 1 << 20;
const max_signature = 4096;

/// Checks a release's statement and signature file, as fetched from the registry: the
/// signature against the pinned keys, that the statement is for repo and tag, that its
/// verdict is certified, and that it lists the file name with digest.
pub fn verify(statement: []const u8, signature: []const u8, keys: []const PublicKey, repo: []const u8, tag: []const u8, name: []const u8, digest: Digest) Error!void {
    const s = try open(statement, signature, keys);
    if (!std.ascii.eqlIgnoreCase(s.repo, repo) or !std.mem.eql(u8, s.tag, tag)) return error.WrongRelease;
    if (s.verdict != .certified) return error.Rejected;
    const listed = s.find(name) orelse return error.NotListed;
    if (!std.mem.eql(u8, &listed, &digest)) return error.NotListed;
}

/// Checks the signature file against the pinned keys, then parses the statement. One line
/// per signature: a statement signed while a key is rotated carries one per key.
pub fn open(statement: []const u8, signature: []const u8, keys: []const PublicKey) Error!Statement {
    if (signature.len > max_signature) return error.BadSignature;
    var lines = std.mem.splitScalar(u8, signature, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        var bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
        const n = std.base64.standard.Decoder.calcSizeForSlice(line) catch continue;
        if (n != bytes.len) continue;
        std.base64.standard.Decoder.decode(&bytes, line) catch continue;
        const sig = Ed25519.Signature.fromBytes(bytes);
        for (keys) |k| {
            sig.verify(statement, k) catch continue;
            return parseStatement(statement) catch error.BadStatement;
        }
    }
    return error.BadSignature;
}

/// Parses a statement. It accepts only the canonical encoding, so one statement has
/// exactly one form: every line exact, files sorted by name, each name once.
pub fn parseStatement(data: []const u8) error{BadStatement}!Statement {
    if (data.len > max_statement or data.len == 0 or data[data.len - 1] != '\n') return error.BadStatement;
    var it = std.mem.splitScalar(u8, data[0 .. data.len - 1], '\n');
    if (!std.mem.eql(u8, it.next() orelse "", header)) return error.BadStatement;
    var s: Statement = undefined;
    s.repo = try field(&it, "repo ");
    if (!validRepo(s.repo)) return error.BadStatement;
    s.tag = try field(&it, "tag ");
    if (!validName(s.tag)) return error.BadStatement;
    const verdict = try field(&it, "verdict ");
    s.verdict = if (std.mem.eql(u8, verdict, "certified")) .certified else if (std.mem.eql(u8, verdict, "rejected")) .rejected else return error.BadStatement;
    s.report = try parseDigest(try field(&it, "report "));
    s.manifest = try parseDigest(try field(&it, "manifest "));
    s.review = try parseDigest(try field(&it, "review "));

    const files_start = it.index orelse return error.BadStatement;
    var previous: ?[]const u8 = null;
    while (it.next()) |line| {
        const f = try parseFileLine(line);
        if (previous) |p| if (std.mem.order(u8, p, f.name) != .lt) return error.BadStatement;
        previous = f.name;
    }
    if (previous == null) return error.BadStatement;
    s.files = data[files_start..];
    return s;
}

/// Reads a digest as a statement writes it: sha256: and 64 lowercase hex digits.
pub fn parseDigest(text: []const u8) error{BadStatement}!Digest {
    const prefix = "sha256:";
    if (text.len != prefix.len + 2 * @sizeOf(Digest) or !std.mem.startsWith(u8, text, prefix)) return error.BadStatement;
    const hex = text[prefix.len..];
    for (hex) |c| if (!(std.ascii.isDigit(c) or (c >= 'a' and c <= 'f'))) return error.BadStatement;
    var d: Digest = undefined;
    _ = std.fmt.hexToBytes(&d, hex) catch return error.BadStatement;
    return d;
}

/// Reads a public key as shadybin publishes it: 64 hex digits.
pub fn parseKey(hex: []const u8) !PublicKey {
    var bytes: [PublicKey.encoded_length]u8 = undefined;
    if (hex.len != 2 * bytes.len) return error.InvalidKey;
    _ = try std.fmt.hexToBytes(&bytes, hex);
    return PublicKey.fromBytes(bytes);
}

/// The registry URL of a release's statement; signatureUrl is beside it. The repository
/// is lowercased, as the registry holds it.
pub fn statementUrl(gpa: std.mem.Allocator, registry: []const u8, repo: []const u8, tag: []const u8) ![]u8 {
    return releaseUrl(gpa, registry, repo, tag, "statement.txt");
}

pub fn signatureUrl(gpa: std.mem.Allocator, registry: []const u8, repo: []const u8, tag: []const u8) ![]u8 {
    return releaseUrl(gpa, registry, repo, tag, "statement.txt.sig");
}

fn releaseUrl(gpa: std.mem.Allocator, registry: []const u8, repo: []const u8, tag: []const u8, file: []const u8) ![]u8 {
    const base = std.mem.trimEnd(u8, registry, "/");
    const url = try std.fmt.allocPrint(gpa, "{s}/{s}/{s}/{s}", .{ base, repo, tag, file });
    _ = std.ascii.lowerString(url[base.len + 1 ..][0..repo.len], repo);
    return url;
}

fn field(it: *std.mem.SplitIterator(u8, .scalar), comptime prefix: []const u8) error{BadStatement}![]const u8 {
    const line = it.next() orelse return error.BadStatement;
    if (!std.mem.startsWith(u8, line, prefix)) return error.BadStatement;
    return line[prefix.len..];
}

const FileLine = struct { name: []const u8, digest: Digest };

fn parseFileLine(line: []const u8) error{BadStatement}!FileLine {
    if (!std.mem.startsWith(u8, line, "file ")) return error.BadStatement;
    const rest = line["file ".len..];
    const space = std.mem.indexOfScalar(u8, rest, ' ') orelse return error.BadStatement;
    const name = rest[space + 1 ..];
    if (!validName(name)) return error.BadStatement;
    return .{ .name = name, .digest = try parseDigest(rest[0..space]) };
}

/// A tag or file name: a letter or digit, then letters, digits and ._+-.
fn validName(s: []const u8) bool {
    if (s.len == 0 or !std.ascii.isAlphanumeric(s[0])) return false;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '+' or c == '-')) return false;
    return true;
}

/// host/owner/name, lowercase: three or more segments of a lowercase letter or digit, then
/// lowercase letters, digits and ._-.
fn validRepo(s: []const u8) bool {
    var segments: usize = 0;
    var it = std.mem.splitScalar(u8, s, '/');
    while (it.next()) |seg| {
        segments += 1;
        if (seg.len == 0 or !(std.ascii.isDigit(seg[0]) or std.ascii.isLower(seg[0]))) return false;
        for (seg) |c| if (!(std.ascii.isDigit(c) or std.ascii.isLower(c) or c == '.' or c == '_' or c == '-')) return false;
    }
    return segments >= 3;
}

const vectors_json = @embedFile("testdata/vectors.json");

test "conformance vectors" {
    const Case = struct { name: []const u8, statement: []const u8, signature: []const u8, repo: []const u8, tag: []const u8, file: []const u8, digest: []const u8, result: []const u8 };
    const Vectors = struct { comment: []const u8, keys: []const []const u8, cases: []const Case };
    const parsed = try std.json.parseFromSlice(Vectors, std.testing.allocator, vectors_json, .{});
    defer parsed.deinit();

    var keys: [4]PublicKey = undefined;
    for (parsed.value.keys, 0..) |h, i| keys[i] = try parseKey(h);
    const pinned = keys[0..parsed.value.keys.len];

    for (parsed.value.cases) |c| {
        const digest = try parseDigest(c.digest);
        const got: []const u8 = if (verify(c.statement, c.signature, pinned, c.repo, c.tag, c.file, digest)) |_| "ok" else |err| switch (err) {
            error.BadSignature => "bad_signature",
            error.BadStatement => "bad_statement",
            error.WrongRelease => "wrong_release",
            error.Rejected => "rejected",
            error.NotListed => "not_listed",
        };
        std.testing.expectEqualStrings(c.result, got) catch |err| {
            std.debug.print("case {s}\n", .{c.name});
            return err;
        };
    }
}

test "default keys parse" {
    _ = defaultKeys();
}

test "urls" {
    const url = try statementUrl(std.testing.allocator, default_registry ++ "/", "github.com/Acme/Tool", "v1.2.0");
    defer std.testing.allocator.free(url);
    try std.testing.expectEqualStrings("https://shadybin.dev/registry/github.com/acme/tool/v1.2.0/statement.txt", url);
}
