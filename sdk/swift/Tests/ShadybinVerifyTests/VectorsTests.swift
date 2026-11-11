import CryptoKit
import Foundation
import Testing

@testable import ShadybinVerify

struct Vectors: Decodable {
    struct Case: Decodable {
        let name, statement, signature, repo, tag, file, digest, result: String
    }

    let keys: [String]
    let cases: [Case]

    static let shared: Vectors = {
        // A copy of spec/vectors.json; `make vectors` keeps it in step.
        guard let url = Bundle.module.url(forResource: "vectors", withExtension: "json"),
              let data = try? Data(contentsOf: url),
              let vectors = try? JSONDecoder().decode(Vectors.self, from: data)
        else { fatalError("vectors.json is missing or malformed") }
        return vectors
    }()
}

func result(of c: Vectors.Case, keys: [Curve25519.Signing.PublicKey]) -> String {
    let digest = (try? Shadybin.parseDigest(c.digest)) ?? Data()
    do {
        try Shadybin.verify(
            statement: Data(c.statement.utf8), signature: Data(c.signature.utf8), keys: keys,
            repo: c.repo, tag: c.tag, file: c.file, digest: digest)
        return "ok"
    } catch {
        switch error {
        case .badSignature: return "bad_signature"
        case .badStatement: return "bad_statement"
        case .wrongRelease: return "wrong_release"
        case .rejected: return "rejected"
        case .notListed: return "not_listed"
        }
    }
}

@Test(arguments: Vectors.shared.cases.map(\.name))
func vector(_ name: String) throws {
    let vectors = Vectors.shared
    let keys = try vectors.keys.map { try Shadybin.parseKey(hex: $0) }
    let c = try #require(vectors.cases.first { $0.name == name })
    #expect(result(of: c, keys: keys) == c.result)
}

@Test func urls() {
    #expect(
        Shadybin.statementURL(registry: Shadybin.defaultRegistry + "/", repo: "github.com/Acme/Tool", tag: "v1.2.0")
            == "https://shadybin.dev/registry/github.com/acme/tool/v1.2.0/statement.txt")
    #expect(Shadybin.signatureURL(repo: "github.com/acme/tool", tag: "v1").hasSuffix("/v1/statement.txt.sig"))
}

@Test func defaultKeysParse() {
    #expect(Shadybin.defaultKeys().count == Shadybin.keyHex.count)
}

@Test func noKeysPinned() {
    let c = Vectors.shared.cases[0]
    #expect(result(of: c, keys: []) == "bad_signature")
}
