"""Verifies shadybin statements: that a release file was rebuilt byte for byte from its
tagged source and passed review. This is what an updater calls before it installs a
release.

It uses the standard library only and does no I/O: fetch the release's statement and its
signature file from the registry (statement_url, signature_url) with whatever HTTP client
the program already has, and hand over the bytes::

    import hashlib, urllib.request
    import shadybin_verify as sb

    repo, tag = "github.com/acme/tool", "v1.2.0"
    fetch = lambda url: urllib.request.urlopen(url).read()  # a 404: not certified yet
    try:
        sb.verify(fetch(sb.statement_url(sb.DEFAULT_REGISTRY, repo, tag)),
                  fetch(sb.signature_url(sb.DEFAULT_REGISTRY, repo, tag)),
                  sb.default_keys(), repo, tag, "tool_Linux_x86_64.tar.gz",
                  hashlib.sha256(archive).digest())
    except sb.Rejected:
        ...  # reviewed and refused: never install, do not ask again
    except sb.Error:
        ...  # not certified: do not install

See spec/SPEC.md in https://github.com/shadybin/shadybin.
"""

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

from . import _ed25519

__all__ = [
    "DEFAULT_REGISTRY", "KEY_HEX", "Error", "BadSignature", "BadStatement", "WrongRelease",
    "Rejected", "NotListed", "Statement", "verify", "open_statement", "parse_statement",
    "parse_digest", "parse_key", "default_keys", "statement_url", "signature_url",
]

#: Where shadybin publishes statements.
DEFAULT_REGISTRY = "https://shadybin.dev/registry"

#: shadybin's signing keys, the public halves, hex. During a rotation there are two.
KEY_HEX = ("d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc",)

_HEADER = "shadybin statement v1"
_MAX_STATEMENT = 1 << 20
_MAX_SIGNATURE = 4096
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]*\Z")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]*\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Error(Exception):
    """The file is not certified: do not install it. A missing statement (a 404 from the
    registry) means not certified *yet*: wait and ask again, and do not fall back to
    another release."""


class BadSignature(Error):
    """No line of the signature file is a signature over the statement by a pinned key."""


class BadStatement(Error):
    """The statement is signed but is not a statement this package reads."""


class WrongRelease(Error):
    """The statement is for another repository or tag than asked."""


class Rejected(Error):
    """shadybin reviewed the release and rejected it. This is final."""


class NotListed(Error):
    """The release is certified, but not with this file and digest."""


@dataclass(frozen=True)
class Statement:
    repo: str
    tag: str
    verdict: str  # "certified" or "rejected"
    report: bytes
    manifest: bytes
    review: bytes
    files: Tuple[Tuple[str, bytes], ...]  # sorted by name

    def find(self, name: str) -> Optional[bytes]:
        """The digest the statement lists for a file, or None."""
        for n, d in self.files:
            if n == name:
                return d
        return None


def verify(statement: bytes, signature: bytes, keys: Iterable[bytes], repo: str, tag: str,
           name: str, digest: bytes) -> None:
    """Checks a release's statement and signature file, as fetched from the registry: the
    signature against the pinned keys, that the statement is for repo and tag, that its
    verdict is certified, and that it lists the file name with digest. Returns nothing;
    raises a subclass of Error at the first check that fails."""
    s = open_statement(statement, signature, keys)
    if s.repo != repo.lower() or s.tag != tag:
        raise WrongRelease(f"the statement is for {s.repo} {s.tag}")
    if s.verdict != "certified":
        raise Rejected(f"shadybin rejected {s.repo} {s.tag} on review")
    if s.find(name) != digest:
        raise NotListed(f"{s.repo} {s.tag} does not certify {name} with that digest")


def open_statement(statement: bytes, signature: bytes, keys: Iterable[bytes]) -> Statement:
    """Checks the signature file against the pinned keys, then parses the statement. One
    line per signature: a statement signed while a key is rotated carries one per key."""
    keys = list(keys)
    if len(signature) > _MAX_SIGNATURE:
        raise BadSignature("signature file too large")
    for line in signature.decode("ascii", "replace").splitlines():
        try:
            sig = base64.b64decode(line.strip(), validate=True)
        except (binascii.Error, ValueError):
            continue
        if len(sig) != 64:
            continue
        if any(_ed25519.verify(k, statement, sig) for k in keys):
            return parse_statement(statement)
    raise BadSignature("no signature by a pinned key")


def parse_statement(data: bytes) -> Statement:
    """Parses a statement, accepting only its canonical encoding: every line exact, files
    sorted by name, each name once."""
    bad = BadStatement("not a canonical shadybin statement")
    if len(data) > _MAX_STATEMENT or not data.endswith(b"\n"):
        raise bad
    try:
        text = data[:-1].decode("utf-8")
    except UnicodeDecodeError:
        raise bad from None
    lines = text.split("\n")
    fields = ["repo", "tag", "verdict", "report", "manifest", "review"]
    if len(lines) < 2 + len(fields) or lines[0] != _HEADER:
        raise bad
    values: Dict[str, str] = {}
    for i, f in enumerate(fields):
        prefix = f + " "
        if not lines[1 + i].startswith(prefix):
            raise bad
        values[f] = lines[1 + i][len(prefix):]
    repo = values["repo"]
    segments = repo.split("/")
    if len(segments) < 3 or not all(_SEGMENT.match(s) for s in segments):
        raise bad
    if not _NAME.match(values["tag"]) or values["verdict"] not in ("certified", "rejected"):
        raise bad
    files: List[Tuple[str, bytes]] = []
    for line in lines[1 + len(fields):]:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != "file" or not _NAME.match(parts[2]):
            raise bad
        if files and files[-1][0].encode() >= parts[2].encode():
            raise bad
        files.append((parts[2], parse_digest(parts[1])))
    if not files:
        raise bad
    return Statement(repo=repo, tag=values["tag"], verdict=values["verdict"],
                     report=parse_digest(values["report"]), manifest=parse_digest(values["manifest"]),
                     review=parse_digest(values["review"]), files=tuple(files))


def parse_digest(text: str) -> bytes:
    """Reads a digest as a statement writes it: sha256: and 64 lowercase hex digits."""
    if not text.startswith("sha256:") or not _HEX64.match(text[7:]):
        raise BadStatement(f"digest {text!r}: want sha256:<64 lowercase hex>")
    return bytes.fromhex(text[7:])


def parse_key(hex_key: str) -> bytes:
    """Reads a public key as shadybin publishes it: 64 hex digits."""
    key = bytes.fromhex(hex_key)
    if len(key) != 32:
        raise ValueError("a public key is 32 bytes")
    return key


def default_keys() -> List[bytes]:
    """shadybin's public keys, to pass to verify."""
    return [parse_key(h) for h in KEY_HEX]


def statement_url(registry: str, repo: str, tag: str) -> str:
    """The registry URL of a release's statement. The repository is lowercased, as the
    registry holds it."""
    return _release_url(registry, repo, tag, "statement.txt")


def signature_url(registry: str, repo: str, tag: str) -> str:
    """The registry URL of a release's signature file, beside its statement."""
    return _release_url(registry, repo, tag, "statement.txt.sig")


def _release_url(registry: str, repo: str, tag: str, file: str) -> str:
    return f"{registry.rstrip('/')}/{repo.lower()}/{tag}/{file}"
