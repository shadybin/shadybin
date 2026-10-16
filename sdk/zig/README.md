# shadybin for Zig

Verifies a release file against its shadybin statement before an updater installs it.
Standard library only; it allocates nothing and does no I/O. Fetch the statement and its
signature file with your own HTTP client, then:

```zig
const shadybin = @import("shadybin");

const keys = shadybin.defaultKeys();
// statementUrl / signatureUrl give the registry URLs; a 404 means not certified yet.
shadybin.verify(statement, signature, &keys, "github.com/acme/tool", tag, "tool-x86_64-linux", digest) catch |err| switch (err) {
    error.Rejected => {}, // reviewed and refused: never install, do not ask again
    else => {}, // not certified: do not install
};
```

Add it with `zig fetch --save git+https://github.com/shadybin/shadybin#<commit>` and
`b.dependency("shadybin", .{}).module("shadybin")`. `zig build test` runs the shared
conformance vectors in `spec/vectors.json`.
