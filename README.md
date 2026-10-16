# shadybin

shadybin certifies that a released binary has no shady code in it.

It rebuilds the release from its tag, on the same kinds of runners the vendor's release
uses, and checks the result is byte for byte what the vendor published. Claude then
reviews the code that goes in:

- all of the vendor's own code;
- every third-party dependency whose version changed, as a diff;
- every new third-party dependency at its surface, the parts a supply-chain attack would
  use;
- third-party packages are checked against their source repositories, so an xz-style
  release that carries files its repository lacks is caught.

The verdict follows from the review by a fixed rule with no person involved. shadybin
signs it in a public registry, along with a manifest of what the code can do and the full
review, and the project gets a badge:

```markdown
![shadybin](https://img.shields.io/endpoint?url=https://shadybin.dev/registry/github.com/<owner>/<repo>/badge.json)
```

which names the latest release: "v0.2.7 not shady", "v0.2.7 shady", "v0.2.7 pending" for
its first day, then "v0.2.7 not certified" if nobody certified it. The vendor pays for it all, on its own
Actions minutes and Claude API key. Reviews of third-party code are cached and shared, so
a popular module is reviewed once for everyone.

Go, Zig and Rust projects can be certified. An updater that uses an SDK installs only
certified releases, so a certified binary updates only to other certified binaries:

- **Go:** `github.com/shadybin/shadybin/verify`, standard library only.
- **Zig:** `sdk/zig`, standard library only, no allocation.
- **Rust:** `sdk/rust`, the `shadybin-verify` crate.

```go
c := verify.Checker{} // trusts verify.DefaultKeys, shadybin's pinned keys
err := c.Check(ctx, "github.com/acme/tool", tag, "tool_Linux_x86_64.tar.gz", sha256.Sum256(archive))
if errors.Is(err, verify.ErrPending) { /* not certified yet: wait, don't install */ }
if errors.Is(err, verify.ErrRejected) { /* reviewed and refused: never install */ }
```

Anyone can check a file:

```sh
shadybin verify -key <hex> -repo github.com/acme/tool -tag v1.2.0 tool_Linux_x86_64.tar.gz
```

See [spec/SPEC.md](spec/SPEC.md) for the formats and the flow.

## Layout

```text
verify/                 the Go SDK (its own module, standard library only)
sdk/zig/, sdk/rust/     the Zig and Rust SDKs
spec/                   SPEC.md, and vectors.json, the conformance tests every SDK runs
cmd/shadybin/           the CLI: keygen, rebuild, compare, manifest, capabilities, review,
                        statement, sign, verify
internal/review/        finding the code compiled in (Go, Zig, Rust), the tiers, the model, the rule
internal/               the CLI's other parts
.github/workflows/      certify.yml, the reusable workflow vendors call
```

The registry is its own repository,
[shadybin/registry](https://github.com/shadybin/registry), served at
`shadybin.dev/registry`. Its history is the record of every signature. The site is
[shadybin/shadybin.github.io](https://github.com/shadybin/shadybin.github.io), at
`shadybin.dev`.

## Development

```sh
make check     # Go, Zig and Rust: format, vet, lint, every test, the vectors in sync
make vectors   # regenerate spec/vectors.json and copy it into each SDK
make build     # → bin/shadybin
```
