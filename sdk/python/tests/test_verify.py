"""The conformance vectors every shadybin SDK runs (spec/vectors.json), and RFC 8032's
own vectors for the Ed25519 verification under them."""

import json
import pathlib
import unittest

import shadybin_verify as sb
from shadybin_verify import _ed25519

RESULTS = {
    sb.BadSignature: "bad_signature",
    sb.BadStatement: "bad_statement",
    sb.WrongRelease: "wrong_release",
    sb.Rejected: "rejected",
    sb.NotListed: "not_listed",
}


class Vectors(unittest.TestCase):
    def test_conformance_vectors(self):
        v = json.loads((pathlib.Path(__file__).parent / "vectors.json").read_text())
        keys = [sb.parse_key(h) for h in v["keys"]]
        for c in v["cases"]:
            with self.subTest(c["name"]):
                try:
                    sb.verify(c["statement"].encode(), c["signature"].encode(), keys, c["repo"],
                              c["tag"], c["file"], sb.parse_digest(c["digest"]))
                    got = "ok"
                except sb.Error as e:
                    got = RESULTS[type(e)]
                self.assertEqual(c["result"], got)

    def test_default_keys(self):
        self.assertEqual(len(sb.default_keys()), len(sb.KEY_HEX))

    def test_urls(self):
        self.assertEqual(
            sb.statement_url(sb.DEFAULT_REGISTRY + "/", "github.com/Acme/Tool", "v1.2.0"),
            "https://shadybin.dev/registry/github.com/acme/tool/v1.2.0/statement.txt")
        self.assertTrue(sb.signature_url(sb.DEFAULT_REGISTRY, "github.com/acme/tool", "v1").endswith("/v1/statement.txt.sig"))


class Ed25519(unittest.TestCase):
    # RFC 8032, section 7.1: TEST 1 (empty message), TEST 2 (one byte), TEST 3 (two bytes).
    CASES = [
        ("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
        ("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
         "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
        ("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
         "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"),
    ]

    def test_rfc8032(self):
        for pub, msg, sig in self.CASES:
            pub, msg, sig = bytes.fromhex(pub), bytes.fromhex(msg), bytes.fromhex(sig)
            self.assertTrue(_ed25519.verify(pub, msg, sig))
            self.assertFalse(_ed25519.verify(pub, msg + b"x", sig))
            bent = bytearray(sig)
            bent[0] ^= 1
            self.assertFalse(_ed25519.verify(pub, msg, bytes(bent)))
            other = self.CASES[0][0] if pub.hex() != self.CASES[0][0] else self.CASES[1][0]
            self.assertFalse(_ed25519.verify(bytes.fromhex(other), msg, sig))

    def test_rejects_non_canonical_s(self):
        pub, _, sig = self.CASES[0]
        sig = bytes.fromhex(sig)
        s = int.from_bytes(sig[32:], "little") + _ed25519._q  # the same signature, S + L
        self.assertFalse(_ed25519.verify(bytes.fromhex(pub), b"", sig[:32] + s.to_bytes(32, "little")))


if __name__ == "__main__":
    unittest.main()
