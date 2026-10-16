//! Verifies shadybin statements: that a release file was rebuilt byte for byte from its
//! tagged source and passed review. This is what an updater calls before it installs a
//! release.
//!
//! The crate does no I/O. Fetch a release's statement and signature file from the
//! registry ([`statement_url`], [`signature_url`]) with whatever HTTP client the program
//! already has, and hand over the bytes:
//!
//! ```no_run
//! # fn fetch(_: &str) -> Vec<u8> { unimplemented!() }
//! # fn sha256(_: &[u8]) -> [u8; 32] { unimplemented!() }
//! # let archive: Vec<u8> = vec![];
//! use shadybin_verify::{verify, parse_key, statement_url, signature_url, DEFAULT_REGISTRY, Error};
//!
//! let keys = shadybin_verify::default_keys();
//! let (repo, tag) = ("github.com/acme/tool", "v1.2.0");
//! let statement = fetch(&statement_url(DEFAULT_REGISTRY, repo, tag)); // a 404: not certified yet
//! let signature = fetch(&signature_url(DEFAULT_REGISTRY, repo, tag));
//! match verify(&statement, &signature, &keys, repo, tag, "tool_Linux_x86_64.tar.gz", &sha256(&archive)) {
//!     Ok(()) => { /* install */ }
//!     Err(Error::Rejected) => { /* reviewed and refused: never install, do not ask again */ }
//!     Err(_) => { /* not certified: do not install */ }
//! }
//! ```
//!
//! See `spec/SPEC.md` in <https://github.com/shadybin/shadybin>.

#![forbid(unsafe_code)]

use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};

/// A SHA-256 digest.
pub type Digest = [u8; 32];

/// A shadybin public key, to pin in the binary.
pub type PublicKey = VerifyingKey;

/// Where shadybin publishes statements.
pub const DEFAULT_REGISTRY: &str = "https://shadybin.dev/registry";

/// shadybin's signing keys, the public halves, hex. During a rotation there are two.
pub const KEY_HEX: &[&str] = &["d971638b671326b3831fb6962e0da516593a1af317b29521651bdf02bb2ed8fc"];

/// shadybin's public keys, parsed, to pass to [`verify`].
pub fn default_keys() -> Vec<PublicKey> {
    KEY_HEX
        .iter()
        .map(|h| parse_key(h).expect("shadybin's own key parses"))
        .collect()
}

const HEADER: &str = "shadybin statement v1";
const MAX_STATEMENT: usize = 1 << 20;
const MAX_SIGNATURE: usize = 4096;

/// Why a file is not certified, in the order the checks run. Every error means: do not
/// install. A missing statement (a 404 from the registry) means not certified *yet*: wait
/// and ask again, and do not fall back to another release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// No line of the signature file is a signature over the statement by a pinned key.
    BadSignature,
    /// The statement is signed but is not a statement this crate reads.
    BadStatement,
    /// The statement is for another repository or tag than asked.
    WrongRelease,
    /// shadybin reviewed the release and rejected it. This is final.
    Rejected,
    /// The release is certified, but not with this file and digest.
    NotListed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Error::BadSignature => "not certified by shadybin: bad signature",
            Error::BadStatement => "not certified by shadybin: bad statement",
            Error::WrongRelease => "not certified by shadybin: statement for another release",
            Error::Rejected => "not certified by shadybin: rejected",
            Error::NotListed => "not certified by shadybin: file not listed",
        })
    }
}

impl std::error::Error for Error {}

/// A release's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Certified,
    Rejected,
}

/// A parsed statement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Statement {
    pub repo: String,
    pub tag: String,
    pub verdict: Verdict,
    pub report: Digest,
    pub manifest: Digest,
    pub review: Digest,
    /// The release's files and their digests, sorted by name.
    pub files: Vec<(String, Digest)>,
}

impl Statement {
    /// The digest the statement lists for a file.
    pub fn find(&self, name: &str) -> Option<&Digest> {
        self.files.iter().find(|(n, _)| n == name).map(|(_, d)| d)
    }
}

/// Checks a release's statement and signature file, as fetched from the registry: the
/// signature against the pinned keys, that the statement is for `repo` and `tag`, that its
/// verdict is certified, and that it lists the file `name` with `digest`.
pub fn verify(
    statement: &[u8],
    signature: &[u8],
    keys: &[PublicKey],
    repo: &str,
    tag: &str,
    name: &str,
    digest: &Digest,
) -> Result<(), Error> {
    let s = open(statement, signature, keys)?;
    if !s.repo.eq_ignore_ascii_case(repo) || s.tag != tag {
        return Err(Error::WrongRelease);
    }
    if s.verdict != Verdict::Certified {
        return Err(Error::Rejected);
    }
    match s.find(name) {
        Some(d) if d == digest => Ok(()),
        _ => Err(Error::NotListed),
    }
}

/// Checks the signature file against the pinned keys, then parses the statement. One line
/// per signature: a statement signed while a key is rotated carries one per key.
pub fn open(statement: &[u8], signature: &[u8], keys: &[PublicKey]) -> Result<Statement, Error> {
    if signature.len() > MAX_SIGNATURE {
        return Err(Error::BadSignature);
    }
    let text = std::str::from_utf8(signature).map_err(|_| Error::BadSignature)?;
    for line in text.lines() {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(line.trim()) else {
            continue;
        };
        let Ok(bytes) = <[u8; 64]>::try_from(bytes.as_slice()) else {
            continue;
        };
        let sig = Signature::from_bytes(&bytes);
        if keys
            .iter()
            .any(|k| k.verify_strict(statement, &sig).is_ok())
        {
            return parse_statement(statement);
        }
    }
    Err(Error::BadSignature)
}

/// Parses a statement. It accepts only the canonical encoding, so one statement has
/// exactly one form: every line exact, files sorted by name, each name once.
pub fn parse_statement(data: &[u8]) -> Result<Statement, Error> {
    let bad = Error::BadStatement;
    if data.len() > MAX_STATEMENT {
        return Err(bad);
    }
    let text = std::str::from_utf8(data).map_err(|_| bad)?;
    let text = text.strip_suffix('\n').ok_or(bad)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(HEADER) {
        return Err(bad);
    }
    let mut field = |prefix: &str| lines.next().and_then(|l| l.strip_prefix(prefix)).ok_or(bad);
    let repo = field("repo ")?.to_string();
    let tag = field("tag ")?.to_string();
    let verdict = match field("verdict ")? {
        "certified" => Verdict::Certified,
        "rejected" => Verdict::Rejected,
        _ => return Err(bad),
    };
    let report = parse_digest(field("report ")?)?;
    let manifest = parse_digest(field("manifest ")?)?;
    let review = parse_digest(field("review ")?)?;
    if !valid_repo(&repo) || !valid_name(&tag) {
        return Err(bad);
    }
    let mut files: Vec<(String, Digest)> = Vec::new();
    for line in lines {
        let rest = line.strip_prefix("file ").ok_or(bad)?;
        let (d, name) = rest.split_once(' ').ok_or(bad)?;
        if !valid_name(name) {
            return Err(bad);
        }
        if let Some((prev, _)) = files.last() {
            if prev.as_str() >= name {
                return Err(bad);
            }
        }
        files.push((name.to_string(), parse_digest(d)?));
    }
    if files.is_empty() {
        return Err(bad);
    }
    Ok(Statement {
        repo,
        tag,
        verdict,
        report,
        manifest,
        review,
        files,
    })
}

/// Reads a digest as a statement writes it: `sha256:` and 64 lowercase hex digits.
pub fn parse_digest(text: &str) -> Result<Digest, Error> {
    let hex = text.strip_prefix("sha256:").ok_or(Error::BadStatement)?;
    lower_hex::<32>(hex).ok_or(Error::BadStatement)
}

/// Reads a public key as shadybin publishes it: 64 hex digits.
pub fn parse_key(hex: &str) -> Option<PublicKey> {
    VerifyingKey::from_bytes(&lower_hex::<32>(&hex.to_ascii_lowercase())?).ok()
}

/// The registry URL of a release's statement. The repository is lowercased, as the
/// registry holds it.
pub fn statement_url(registry: &str, repo: &str, tag: &str) -> String {
    release_url(registry, repo, tag, "statement.txt")
}

/// The registry URL of a release's signature file, beside its statement.
pub fn signature_url(registry: &str, repo: &str, tag: &str) -> String {
    release_url(registry, repo, tag, "statement.txt.sig")
}

fn release_url(registry: &str, repo: &str, tag: &str, file: &str) -> String {
    format!(
        "{}/{}/{}/{}",
        registry.trim_end_matches('/'),
        repo.to_ascii_lowercase(),
        tag,
        file
    )
}

fn lower_hex<const N: usize>(hex: &str) -> Option<[u8; N]> {
    let b = hex.as_bytes();
    if b.len() != 2 * N {
        return None;
    }
    let nibble = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nibble(b[2 * i])? << 4 | nibble(b[2 * i + 1])?;
    }
    Some(out)
}

/// A tag or file name: a letter or digit, then letters, digits and `._+-`.
fn valid_name(s: &str) -> bool {
    let mut chars = s.bytes();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
}

/// host/owner/name, lowercase: three or more segments of a lowercase letter or digit, then
/// lowercase letters, digits and `._-`.
fn valid_repo(s: &str) -> bool {
    let low = |c: u8| c.is_ascii_digit() || c.is_ascii_lowercase();
    s.split('/').count() >= 3
        && s.split('/').all(|seg| {
            let mut b = seg.bytes();
            matches!(b.next(), Some(c) if low(c)) && b.all(|c| low(c) || b"._-".contains(&c))
        })
}
