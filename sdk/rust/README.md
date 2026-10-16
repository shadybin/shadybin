# shadybin-verify

Verifies a release file against its shadybin statement before an updater installs it. It
does no I/O: fetch the statement and its signature file with your own HTTP client, then
call `verify`. Its only dependencies are `ed25519-dalek` and `base64`. `cargo test` runs
the shared conformance vectors in `spec/vectors.json`.
