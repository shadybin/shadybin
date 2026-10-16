# shadybin v1

What shadybin certifies, how it is published, and how a verifier checks it.

## What a certification means

shadybin certifies a release when two things hold:

1. The files shadybin built from the release's git tag are byte for byte the files the
   vendor published, or, for an archive (`.tar.gz`, `.tgz`, `.zip`), install exactly the
   same thing: the same entries, each with the same name, kind, permissions, link target
   and bytes. An archive's entry times, owners and groups, entry order and gzip header
   may differ, since they record where and when it was made, not what it holds. The
   statement lists the published file's digest either way, so an updater checks exactly
   what it downloaded.
2. A model reviewed the code that goes into them and found nothing shady, by the rule in
   [Deciding](#deciding). That covers all of the vendor's own code, and third-party code
   wherever a supply-chain attack would get in (see [Review](#review)).

A release that rebuilds but fails review is **rejected**. Its statement is still signed,
so updaters get a final answer instead of waiting forever. A release that does not
rebuild gets no statement at all. No person approves either verdict.

The vendor pays for all of it: the rebuild and review run on the vendor's GitHub Actions
minutes and Claude API key. shadybin itself runs only the registry, on GitHub Pages, and
its intake, on a public repository's free Actions minutes.

## Statement

A statement is the signed record of one release. It is UTF-8 text with `\n` line endings,
and it has exactly one encoding: verifiers reject any other form of the same content.

```text
shadybin statement v1
repo github.com/miradorlabs/terma-cli
tag v0.2.7
verdict certified
report sha256:<64 lowercase hex>
manifest sha256:<64 lowercase hex>
review sha256:<64 lowercase hex>
file sha256:<64 lowercase hex> terma_Darwin_arm64.tar.gz
file sha256:<64 lowercase hex> terma_Linux_x86_64.tar.gz
```

- `repo`: host/owner/name, lowercase, at least three segments, each a lowercase letter or
  digit followed by lowercase letters, digits and `._-`.
- `tag`: a letter or digit, then letters, digits and `._+-`. Tags with slashes cannot be
  certified in v1.
- `verdict`: `certified` or `rejected`.
- `report`, `manifest`, `review`: the SHA-256 of `report.md`, `manifest.json` and
  `review.json`, published beside the statement.
- `file`: one line per file rebuilt and found identical, sorted by name in byte order,
  each name once. Names follow the tag's rule. At least one file.
- The last line ends in `\n`. A statement is at most 1 MiB.

The first line separates the domain: a shadybin signature covers the whole statement
and so can never be read as a signature over anything else.

## Signature

`statement.txt.sig` holds one Ed25519 signature per line, base64 (standard alphabet,
padded), over the statement's bytes. During a key rotation a statement carries a
signature from each key. A verifier accepts the statement if any line verifies under any
key it has pinned. The file is at most 4096 bytes.

## Verifying

To check a file `name`, with SHA-256 `digest`, from release `tag` of `repo`:

1. Fetch `<registry>/<repo>/<tag>/statement.txt` and `statement.txt.sig`, with `repo`
   lowercased. A 404 means the release is not certified **yet**. An updater waits and
   asks again. It does not install the release and does not fall back to another one.
2. Check the signature against the pinned keys (`bad_signature`), then parse the
   statement, accepting only its canonical form (`bad_statement`).
3. Check the statement's `repo` and `tag` are the ones asked for, `repo` compared without
   case (`wrong_release`). Otherwise one release's statement could be served for another.
4. Check the verdict is `certified` (`rejected`). A rejected release is final: do not
   install it, and do not ask again.
5. Check the statement lists `name` with `digest` (`not_listed`).

There is an SDK for each of Go (`verify/`, module `github.com/shadybin/shadybin/verify`),
Zig (`sdk/zig`) and Rust (`sdk/rust`, crate `shadybin-verify`). Each does steps 2 to 5
with its standard library and, for Rust, `ed25519-dalek` and `base64`. Each must give
the result named in `spec/vectors.json` for every case there, the first check that
fails, or `ok`.

## Registry

The registry is the public repository `shadybin/registry`, served by GitHub Pages at
`https://shadybin.dev/registry`. Its commit history is the record of every certification.

```text
<repo>/project.json             how shadybin rebuilds and reviews the project
<repo>/badge.json               shields.io badge: the newest release's version and verdict
<repo>/latest                   the newest certified release's tag
<repo>/<tag>/statement.txt
<repo>/<tag>/statement.txt.sig
<repo>/<tag>/badge.json         the release's own badge, for its release notes
<repo>/<tag>/manifest.json
<repo>/<tag>/review.json
<repo>/<tag>/report.md
deps/<module>@<version>/<digest>.json      a cached review of a module
deps/<module>@<version>/<digest>.json.sig
```

The project's badge names its **latest release**, the one GitHub's `releases/latest`
points to, the one users are getting, whatever shadybin has made of it:

| The latest release is | The badge reads |
|---|---|
| certified | `v0.2.8 not shady`, green |
| rejected | `v0.2.8 shady`, red |
| unsigned, published under 24 hours ago | `v0.2.8 pending`, grey |
| unsigned after that | `v0.2.8 not certified`, orange |

A vendor therefore cannot keep an old release's green badge by not certifying a new one,
and a release whose certification failed says so. Intake updates it on every pass. Each
release also has its own badge, which never moves on to a later release, for its release
notes. Embed the project's badge with
`https://img.shields.io/endpoint?url=https://shadybin.dev/registry/<repo>/badge.json`.

`latest` moves only to a certified release. It is the base the next release is reviewed
against, and rejected code must never become that base, or what it hid would never be
shown to a reviewer again.

A certified release is never rewritten.

## project.json

How a project is rebuilt and reviewed lives in the registry, not the vendor's
repository, so a vendor cannot change how its release is checked from the release being
checked.

- `language`: `go`, `zig` or `rust`.
- `builds`: one per published binary set. Each has a GitHub-hosted `runner`, the
  `toolchain` to install (`go`: a version or `go.mod`; `zig`: a version; `rust`: a
  version or `rust-toolchain.toml`), the shell commands to `run` in the checked-out tag,
  and the `artifacts` they make. The build sees `SOURCE_DATE_EPOCH`, the tag's commit
  time, and `TAG`.
- `checksums`: the release asset with the published digests in sha256sum's format, or a
  pattern for one file per asset, such as `*.sha256`.
- `analyze`: for Go, the main `packages` and the GOOS `targets`; for Rust, the binary
  crates (empty: all) and target triples; for all, `files` that shape the binary outside
  the code (such as `.goreleaser.yaml`), and `exclude`, git pathspecs of files never
  compiled in (tests, docs), for languages whose build does not list what it reads.
- `owned`: module prefixes the vendor controls besides its repository. Default: the
  repository's owner, `github.com/<owner>/`.
- `vendored`: third-party copies kept in the repository. Each has its `path`, the
  upstream release's `name` and `version`, and its archive's `url` and `sha256`.

Everything a rebuild runs is either in `project.json`, which shadybin controls, or in
the reviewed source: `build.zig`, `build.rs`, `.goreleaser.yaml` (name it in `files`).
Build code could otherwise fetch the published binary and present it as rebuilt.
`project.json` therefore never calls a vendor's own actions or scripts that the review
does not cover; it installs toolchains itself.

A build is reproducible only if the vendor's release build is. Go needs `-trimpath`,
pinned archive metadata and a pinned GoReleaser. Rust needs `--remap-path-prefix` and a
pinned toolchain. Archives are compared by what they install, so their file times and
owners need not be fixed. Zig
and C embed absolute paths, so the toolchain must be installed where the vendor's release
installs it. The rebuild checks out the tag at the workspace root, as the release job
does.

## Manifest

`manifest.json` lists every package compiled into the binary, the version of each
module, and for Go, the capabilities each package uses *directly*: files, network,
running programs, system calls, unsafe pointers and so on. These come from
[Capslock](https://github.com/google/capslock), at a pinned version, run for each target
GOOS, with the manifest recording the union. Transitive capabilities are left out,
because in a real binary nearly every package reaches nearly everything. The report also
leaves out reflection, runtime and unanalyzed calls, for the same reason. Zig and Rust
have no capability analysis; their manifests list packages and versions only.

## Review

Each language's tools say which code is compiled in:

- **Go:** `go list` for each target, file by file.
- **Zig:** the files `build.zig.zon` `.paths` name, and the dependency tree as `zig
  build --fetch` fetches it. A lazy dependency the build never needs is not compiled in.
- **Rust:** `cargo metadata` for each target, through normal and build dependencies.
  Build scripts and proc macros run at build time, so they count. Dev-dependencies do
  not.

Code is either **the vendor's** or **third-party**. The vendor's is whatever it can edit
without anyone else's checksum noticing: everything in its repository, vendored copies
included, and modules under its `owned` prefixes. Third-party is everything fetched by a
checksum that someone else's published code must match.

The exception is a vendored copy declared in `vendored`. shadybin downloads the upstream
archive, checks its digest, and compares the copy file by file. Files identical to
upstream are third-party. Anything edited or added is the vendor's.

The code is split into units, one model call each:

- **The vendor's code in its repository** is one unit (split by size). It is the `git
  diff` since the previous certified tag, or the whole code for a first review, without
  the vendored files that match upstream. The README goes along as the vendor's own
  description of the tool.
- **A vendor module outside the repository** is reviewed whole, or as a diff since its
  previous version.
- **A third-party module whose version changed** is reviewed as the diff since its
  previous version. Takeovers like the xz backdoor arrive in a new version.
- **A third-party module new to the project** is reviewed at its **surface**: the parts a
  supply-chain attack would use. That is build scripts and build-time code; code run when
  the program loads (`init`, constructors); binary, assembly and C files; files with
  embedding, linking or foreign-function markers; files that run programs, use the
  network or load code; and, for Go, every file of a package with a sensitive capability.
  A surface over about 500k tokens is not reviewed: the module stays pinned to its exact
  release, the report says so, and every later version change is reviewed as a diff.
- **A third-party module at the version the previous certified release had** needs no
  unit: it was reviewed then.

Before a new or changed third-party package is reviewed, it is checked against its
source repository:

- **Go modules** cannot differ: `proxy.golang.org` builds them from the repository, and
  the checksum database pins them.
- **Zig packages** fetched from git, or as an archive GitHub makes from a tag or
  commit, come from their repository. Any other archive is not checkable, and the report
  says so.
- **Rust crates** are whatever the maintainer uploaded, so each is compared, file by
  file, with its repository at the commit its `.cargo_vcs_info.json` names. A file the
  crate has and the repository does not, or one with different content there, is
  **foreign**. That is how the xz backdoor's build step reached its users. Foreign files
  are always shown to the model, marked, and listed in the report.

Each file goes between markers that carry its SHA-256, so the code cannot close its own
marker. The model (`claude-opus-5-5`, effort `high`, structured output) is told that
everything inside the markers is untrusted data, and that text addressing a reviewer is
itself a malicious finding. For each unit it returns a pass or fail verdict; findings
(info, concern or malicious); an explanation for each capability it was asked about; and
the data that leaves the process. If the model declines or errors, the run fails and can
be retried; that never becomes a verdict.

### Deciding

A release is certified only if every unit was reviewed, no unit failed, no finding is
malicious, and every capability below has a non-empty explanation from a unit that
covered its package:

- **With a previous certified release:** every capability a package gained since then.
- **For a first review:** every sensitive capability: EXEC, NETWORK, OPERATING_SYSTEM,
  MODIFY_SYSTEM_STATE, ARBITRARY_EXECUTION and CGO.

The rule reads only `review.json` and the two manifests. Intake reruns it before signing
and refuses to sign a statement whose verdict it does not give. Anyone can rerun it from
the registry.

### Cache

A non-project unit's input is the same for every project that compiles in the same code
at the same version, from the same previous version: Go's checksum database, Zig's
package hashes and Cargo's lockfile checksums fix it. The unit's digest is the SHA-256
of the model, the prompt version and that exact input. Once intake signs a release,
every such unit reviewed afresh goes into the registry under
`deps/<module>@<version>/<digest>.json`. The entry is signed with the shadybin key over
`shadybin review cache v1\n` followed by the entry. A later review that asks the same
question takes the answer from the cache and makes no call. It accepts an entry only with
a valid signature, so the host need not be trusted. A popular module is therefore
reviewed once, paid for by the first vendor who compiles it in.

## Certifying

1. The vendor's release workflow calls `shadybin/shadybin/.github/workflows/certify.yml`
   after the release is published, pinned to a commit. It runs on the vendor's
   GitHub-hosted runners:
   - `plan` builds shadybin and reads `project.json` from the registry.
   - `rebuild` runs each build on its own runner, with the tag checked out at the
     workspace root as the vendor's release job has it.
   - `certify` compares the rebuilt files with the published checksums, writes the
     manifest, reviews the code on the vendor's Claude API key, and writes the statement
     and report.

   It attests all four files with the workflow's Sigstore identity and attaches them to
   the release as `shadybin-statement.txt`, `shadybin-report.md`, `shadybin-manifest.json`
   and `shadybin-review.json`.
2. Every 15 minutes the registry's `intake` workflow looks at each registered project's
   recent releases. For any release not yet in the registry, it checks that all four
   files were attested by that workflow, for that tag, on a GitHub-hosted runner. It
   reruns the rule, signs the statement, caches the module reviews and commits.

No person approves a signature. What gets signed follows from checks anyone can rerun.
The signing key is a secret of the registry's `signing` environment, which deploys from
`main` only.
