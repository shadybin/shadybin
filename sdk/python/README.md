# shadybin-verify

Verifies a release file against its shadybin statement before an updater installs it.
Standard library only, Ed25519 included, and no I/O: fetch the statement and its
signature file with your own HTTP client, then call `verify`. Python 3.9 or later.
`python -m unittest discover -s tests` runs the shared conformance vectors in
`spec/vectors.json`.
