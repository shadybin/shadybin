# ShadybinVerify

Verifies a release file against its shadybin statement before an updater installs it. It
does no I/O: fetch the statement and its signature file with your own HTTP client, then
call `Shadybin.verify`. It has no dependencies: Ed25519 comes from CryptoKit, so it runs on
Apple platforms (macOS 13, iOS 16 and later). `swift test` runs the shared conformance
vectors in `spec/vectors.json`. SwiftPM fetches packages from a repository's root, so the
manifest is the repository's `Package.swift`; run `swift test` there.

```swift
.package(url: "https://github.com/shadybin/shadybin", from: "1.0.0")
```

```swift
import CryptoKit
import ShadybinVerify

let repo = "github.com/acme/tool", tag = "v1.2.0"
// A 404 from the registry means not certified yet: wait and ask again, and do not fall
// back to another release.
let statement = try await fetch(Shadybin.statementURL(repo: repo, tag: tag))
let signature = try await fetch(Shadybin.signatureURL(repo: repo, tag: tag))
do {
    try Shadybin.verify(statement: statement, signature: signature, keys: Shadybin.defaultKeys(),
                        repo: repo, tag: tag, file: "tool_Darwin_arm64.zip",
                        digest: Data(SHA256.hash(data: archive)))
} catch .rejected {
    // Reviewed and refused: never install it, and do not ask again.
} catch {
    // Not certified: do not install it.
}
```

`verify` throws `Shadybin.VerifyError` at the first check that fails: `badSignature`,
`badStatement`, `wrongRelease`, `rejected` or `notListed`. Only `rejected` is final.
