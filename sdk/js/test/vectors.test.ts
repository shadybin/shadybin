// The conformance vectors every shadybin SDK runs; see spec/vectors.json.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  verify, parseKey, parseDigest, defaultKeys, KEY_HEX, statementUrl, signatureUrl, DEFAULT_REGISTRY, ShadybinError,
} from "../src/index.ts";

interface Case { name: string; statement: string; signature: string; repo: string; tag: string; file: string; digest: string; result: string }

const vectors = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url), "utf8")) as { keys: string[]; cases: Case[] };
const enc = new TextEncoder();

test("conformance vectors", async () => {
  const keys = vectors.keys.map(parseKey);
  for (const c of vectors.cases) {
    let got = "ok";
    try {
      await verify(enc.encode(c.statement), enc.encode(c.signature), keys, c.repo, c.tag, c.file, parseDigest(c.digest));
    } catch (e) {
      if (!(e instanceof ShadybinError)) throw e;
      got = e.code;
    }
    assert.equal(got, c.result, `case ${c.name}`);
  }
});

test("default keys parse", () => {
  assert.equal(defaultKeys().length, KEY_HEX.length);
});

test("urls", () => {
  assert.equal(
    statementUrl(DEFAULT_REGISTRY + "/", "github.com/Acme/Tool", "v1.2.0"),
    "https://shadybin.dev/registry/github.com/acme/tool/v1.2.0/statement.txt",
  );
  assert.ok(signatureUrl(DEFAULT_REGISTRY, "github.com/acme/tool", "v1").endsWith("/v1/statement.txt.sig"));
});
