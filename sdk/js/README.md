# @shadybin/verify

Verifies a release file against its shadybin statement before an updater installs it.
No dependencies: Ed25519 is WebCrypto's, so it runs in Node 20+, Deno, Bun and browsers.
No I/O: fetch the statement and its signature file yourself, then `await verify(...)`.
Works from JavaScript and TypeScript. `npm test` runs the shared conformance vectors in
`spec/vectors.json`.
