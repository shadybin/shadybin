// Verifies shadybin statements: that a release file was rebuilt byte for byte from its
// tagged source and passed review. This is what an updater calls before it installs a
// release.
//
// It uses Foundation and CryptoKit only and does no I/O: fetch the release's statement and
// its signature file from the registry (statementURL, signatureURL) with whatever HTTP
// client the program already has, and hand over the bytes:
//
//     let repo = "github.com/acme/tool", tag = "v1.2.0"
//     // A 404 from the registry means not certified yet: wait, and ask again later.
//     let statement = try await fetch(Shadybin.statementURL(repo: repo, tag: tag))
//     let signature = try await fetch(Shadybin.signatureURL(repo: repo, tag: tag))
//     do {
//         try Shadybin.verify(statement: statement, signature: signature, keys: Shadybin.defaultKeys(),
//                             repo: repo, tag: tag, file: "tool_Darwin_arm64.zip",
//                             digest: Data(SHA256.hash(data: archive)))
//     } catch .rejected {
//         // Reviewed and refused: never install it, and do not ask again.
//     } catch {
//         // Not certified: do not install it.
//     }
//
// See spec/SPEC.md in https://github.com/shadybin/shadybin.

import CryptoKit
import Foundation

public enum Shadybin {
    /// Where shadybin publishes statements.
    public static let defaultRegistry = "https://shadybin.dev/registry"

    /// shadybin's signing keys, the public halves, hex. During a rotation there are two.
    public static let keyHex = ["d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc"]

    /// Why a file is not certified. Every case means: do not install it. A missing statement
    /// (a 404 from the registry) means not certified *yet*: wait and ask again, and do not
    /// fall back to another release.
    public enum VerifyError: Error, Equatable, Sendable {
        /// No line of the signature file is a signature over the statement by a pinned key.
        case badSignature(String)
        /// The statement is signed but is not a statement this package reads.
        case badStatement(String)
        /// The statement is for another repository or tag than asked.
        case wrongRelease(String)
        /// shadybin reviewed the release and rejected it. This is final.
        case rejected(String)
        /// The release is certified, but not with this file and digest.
        case notListed(String)
    }

    public enum Verdict: String, Sendable {
        case certified, rejected
    }

    /// A parsed statement: the signed record of one release.
    public struct Statement: Equatable, Sendable {
        public struct File: Equatable, Sendable {
            public let name: String
            /// SHA-256 of the published file.
            public let digest: Data
        }

        public let repo: String
        public let tag: String
        public let verdict: Verdict
        public let report: Data
        public let manifest: Data
        public let review: Data
        /// Sorted by name, each name once.
        public let files: [File]

        /// The digest the statement lists for a file, or nil.
        public func digest(of name: String) -> Data? {
            files.first { $0.name == name }?.digest
        }
    }

    /// Checks a release's statement and signature file, as fetched from the registry: the
    /// signature against the pinned keys, that the statement is for repo and tag, that its
    /// verdict is certified, and that it lists the file with digest. Throws at the first
    /// check that fails.
    public static func verify(
        statement: Data, signature: Data, keys: [Curve25519.Signing.PublicKey],
        repo: String, tag: String, file: String, digest: Data
    ) throws(VerifyError) {
        let s = try openStatement(statement, signature: signature, keys: keys)
        guard s.repo == repo.lowercased(), s.tag == tag else {
            throw .wrongRelease("the statement is for \(s.repo) \(s.tag)")
        }
        guard s.verdict == .certified else {
            throw .rejected("shadybin rejected \(s.repo) \(s.tag) on review")
        }
        guard s.digest(of: file) == digest else {
            throw .notListed("\(s.repo) \(s.tag) does not certify \(file) with that digest")
        }
    }

    /// Checks the signature file against the pinned keys, then parses the statement. One
    /// line per signature: a statement signed while a key is rotated carries one per key.
    public static func openStatement(
        _ statement: Data, signature: Data, keys: [Curve25519.Signing.PublicKey]
    ) throws(VerifyError) -> Statement {
        guard !keys.isEmpty else { throw .badSignature("no shadybin keys pinned") }
        guard signature.count <= maxSignature else { throw .badSignature("signature file too large") }
        for line in signature.split(separator: UInt8(ascii: "\n"), omittingEmptySubsequences: true) {
            guard let text = String(bytes: line, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  let sig = Data(base64Encoded: text), sig.count == 64
            else { continue }
            if keys.contains(where: { $0.isValidSignature(sig, for: statement) }) {
                return try parseStatement(statement)
            }
        }
        throw .badSignature("no signature by a pinned key")
    }

    /// Parses a statement, accepting only its canonical encoding: every line exact, files
    /// sorted by name, each name once.
    public static func parseStatement(_ data: Data) throws(VerifyError) -> Statement {
        let bad = VerifyError.badStatement("not a canonical shadybin statement")
        guard data.count <= maxStatement, data.last == UInt8(ascii: "\n"),
              let text = String(data: data.dropLast(), encoding: .utf8)
        else { throw bad }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        let fields = ["repo", "tag", "verdict", "report", "manifest", "review"]
        guard lines.count >= 2 + fields.count, lines[0] == header else { throw bad }
        var values: [String: String] = [:]
        for (i, field) in fields.enumerated() {
            guard lines[1 + i].hasPrefix(field + " ") else { throw bad }
            values[field] = String(lines[1 + i].dropFirst(field.count + 1))
        }
        let repo = values["repo"] ?? "", tag = values["tag"] ?? ""
        let segments = repo.split(separator: "/", omittingEmptySubsequences: false)
        guard segments.count >= 3, segments.allSatisfy({ isRepoSegment($0) }), isName(tag),
              let verdict = Verdict(rawValue: values["verdict"] ?? "")
        else { throw bad }

        var files: [Statement.File] = []
        for line in lines[(1 + fields.count)...] {
            let parts = line.split(separator: " ", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0] == "file", isName(parts[2]) else { throw bad }
            let name = String(parts[2])
            if let last = files.last, !Array(last.name.utf8).lexicographicallyPrecedes(Array(name.utf8)) {
                throw bad
            }
            files.append(.init(name: name, digest: try parseDigest(String(parts[1]))))
        }
        guard !files.isEmpty else { throw bad }
        return Statement(
            repo: repo, tag: tag, verdict: verdict,
            report: try parseDigest(values["report"] ?? ""), manifest: try parseDigest(values["manifest"] ?? ""),
            review: try parseDigest(values["review"] ?? ""), files: files)
    }

    /// Reads a digest as a statement writes it: sha256: and 64 lowercase hex digits.
    public static func parseDigest(_ text: String) throws(VerifyError) -> Data {
        guard text.hasPrefix("sha256:"), let digest = lowercaseHex(text.dropFirst(7)), digest.count == 32 else {
            throw .badStatement("digest \(text): want sha256:<64 lowercase hex>")
        }
        return digest
    }

    /// Reads a public key as shadybin publishes it: 64 hex digits.
    public static func parseKey(hex: String) throws -> Curve25519.Signing.PublicKey {
        guard let raw = lowercaseHex(Substring(hex.lowercased())), raw.count == 32 else {
            throw VerifyError.badSignature("a public key is 64 hex digits")
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }

    /// shadybin's public keys, to pass to verify.
    public static func defaultKeys() -> [Curve25519.Signing.PublicKey] {
        keyHex.compactMap { try? parseKey(hex: $0) }
    }

    /// The registry URL of a release's statement. The repository is lowercased, as the
    /// registry holds it.
    public static func statementURL(registry: String = defaultRegistry, repo: String, tag: String) -> String {
        releaseURL(registry, repo, tag, "statement.txt")
    }

    /// The registry URL of a release's signature file, beside its statement.
    public static func signatureURL(registry: String = defaultRegistry, repo: String, tag: String) -> String {
        releaseURL(registry, repo, tag, "statement.txt.sig")
    }

    // MARK: Private

    private static let header = "shadybin statement v1"
    private static let maxStatement = 1 << 20
    private static let maxSignature = 4096

    private static func releaseURL(_ registry: String, _ repo: String, _ tag: String, _ file: String) -> String {
        var base = registry
        while base.hasSuffix("/") { base.removeLast() }
        return "\(base)/\(repo.lowercased())/\(tag)/\(file)"
    }

    /// A repository segment: a lowercase letter or digit, then lowercase letters, digits and `._-`.
    private static func isRepoSegment(_ s: Substring) -> Bool {
        let bytes = Array(s.utf8)
        guard let first = bytes.first, isLowerAlnum(first) else { return false }
        return bytes.allSatisfy { isLowerAlnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: "-") }
    }

    /// A tag or file name: a letter or digit, then letters, digits and `._+-`.
    private static func isName<S: StringProtocol>(_ s: S) -> Bool {
        let bytes = Array(s.utf8)
        guard let first = bytes.first, isAlnum(first) else { return false }
        return bytes.allSatisfy {
            isAlnum($0) || $0 == UInt8(ascii: ".") || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: "+") || $0 == UInt8(ascii: "-")
        }
    }

    private static func isLowerAlnum(_ b: UInt8) -> Bool {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(b) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(b)
    }

    private static func isAlnum(_ b: UInt8) -> Bool {
        isLowerAlnum(b) || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(b)
    }

    /// Decodes lowercase hex; nil for anything else, uppercase included.
    private static func lowercaseHex(_ s: Substring) -> Data? {
        let bytes = Array(s.utf8)
        guard bytes.count % 2 == 0 else { return nil }
        func nibble(_ b: UInt8) -> UInt8? {
            switch b {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): b - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): b - UInt8(ascii: "a") + 10
            default: nil
            }
        }
        var out = Data(capacity: bytes.count / 2)
        for i in stride(from: 0, to: bytes.count, by: 2) {
            guard let hi = nibble(bytes[i]), let lo = nibble(bytes[i + 1]) else { return nil }
            out.append(hi << 4 | lo)
        }
        return out
    }
}
