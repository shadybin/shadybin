# AGENTS.md

Guidance for coding agents working in this repository. Start with the README, then
spec/SPEC.md.

## Commands

```bash
make check   # before committing
make build   # → bin/shadybin
```

## Rules

- The SDKs (`verify/` for Go, `sdk/zig`, `sdk/rust`, `sdk/python`, `sdk/js`) are what
  vendors put in their updaters. Go, Zig and Python use their standard libraries only
  (Python's Ed25519 is RFC 8032's reference algorithm, tested against its vectors);
  TypeScript uses WebCrypto and has no dependencies; Rust uses `ed25519-dalek` and
  `base64`. Keep them small: everything they add is attack surface in every binary that
  uses them. `verify/` is its own Go module, so vendors never get this module's
  dependencies.
- Every SDK gives the result `spec/vectors.json` names for every case. A change to what
  verification accepts starts as new cases in `verify/vectors_test.go`, then `make
  vectors`, then each SDK until `make check` passes.
- The statement format, the signature file, the registry layout and the release asset
  names (`shadybin-statement.txt`, `shadybin-report.md`, `shadybin-manifest.json`,
  `shadybin-review.json`), and the cache entries' signing prefix are
  contracts with binaries and workflows already in use. Once anything is shipped, change
  them only with a new `shadybin statement vN` header.
- A statement has one encoding. `ParseStatement` rejects anything `Marshal` would not
  write. Keep it that way.
- No person approves a signature, so whether something is signed must follow from checks
  anyone can rerun. The key is used only by the registry's intake, in the `signing`
  environment, which deploys from `main` only.
- Anything taken from a vendor's release is data: copied, hashed and parsed, never run.
- A verdict comes only from `review.Decide`, which reads only review.json and the
  manifests, so intake and anyone else can rerun it. A model error or refusal fails the
  run; it is never a verdict.
- The model's input is untrusted. Every file goes between digest-carrying markers, the
  API endpoint is fixed in code, and the cache is read only with valid signatures.
- Which code the review sees is decided by each language's `review.Source`, never by
  file extensions alone: what the build compiles in, and nothing it does not.
- Changing the system prompt, the input format or the model means bumping
  `review.PromptVersion` (or `Model`), so cached answers are never reused for a
  different question.
- Workflows pass inputs through `env`, never interpolated into `run:`.
