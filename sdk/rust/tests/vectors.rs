//! The conformance vectors every shadybin SDK runs; see spec/vectors.json.

use serde::Deserialize;
use shadybin_verify::{
    DEFAULT_REGISTRY, Error, parse_digest, parse_key, signature_url, statement_url, verify,
};

#[derive(Deserialize)]
struct Vectors {
    keys: Vec<String>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    statement: String,
    signature: String,
    repo: String,
    tag: String,
    file: String,
    digest: String,
    result: String,
}

#[test]
fn conformance_vectors() {
    let v: Vectors = serde_json::from_str(include_str!("vectors.json")).unwrap();
    let keys: Vec<_> = v.keys.iter().map(|h| parse_key(h).unwrap()).collect();
    for c in &v.cases {
        let digest = parse_digest(&c.digest).unwrap();
        let got = match verify(
            c.statement.as_bytes(),
            c.signature.as_bytes(),
            &keys,
            &c.repo,
            &c.tag,
            &c.file,
            &digest,
        ) {
            Ok(()) => "ok",
            Err(Error::BadSignature) => "bad_signature",
            Err(Error::BadStatement) => "bad_statement",
            Err(Error::WrongRelease) => "wrong_release",
            Err(Error::Rejected) => "rejected",
            Err(Error::NotListed) => "not_listed",
        };
        assert_eq!(got, c.result, "case {}", c.name);
    }
}

#[test]
fn default_keys_parse() {
    assert_eq!(
        shadybin_verify::default_keys().len(),
        shadybin_verify::KEY_HEX.len()
    );
}

#[test]
fn urls() {
    assert_eq!(
        statement_url(
            &format!("{DEFAULT_REGISTRY}/"),
            "github.com/Acme/Tool",
            "v1.2.0"
        ),
        "https://shadybin.dev/registry/github.com/acme/tool/v1.2.0/statement.txt"
    );
    assert!(
        signature_url(DEFAULT_REGISTRY, "github.com/acme/tool", "v1")
            .ends_with("/v1/statement.txt.sig")
    );
}
