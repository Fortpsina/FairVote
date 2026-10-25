#!/usr/bin/env node
/*
 * Passphrase-derived secret: browser vs server.
 *
 * Compares (tests/test_payload_js.py):
 *   1. salt: SHA-256("fairvote/secret/v1|" + pollId)[:16] (WebCrypto, realm-safe);
 *   2. Argon2id(passphrase, salt) computed by the vendored libsodium (sumo) — the
 *      exact code the browser runs — inside its own vm context.
 *
 * stdin: {"passphrase": "...", "pollId": "..."}
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { webcrypto } = require("crypto");

const vendor = path.resolve(__dirname, "..", "fairvote", "web", "static", "vendor");

const context = {
  console,
  crypto: webcrypto,
  atob: (value) => Buffer.from(String(value), "base64").toString("binary"),
  btoa: (value) => Buffer.from(String(value), "binary").toString("base64"),
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(vendor, "libsodium.js"), "utf8"), context, {
  filename: "libsodium.js",
});
vm.runInContext(
  fs.readFileSync(path.join(vendor, "libsodium-wrappers.js"), "utf8"),
  context,
  { filename: "libsodium-wrappers.js" }
);

async function loadPayloadModule() {
  const source = fs.readFileSync(
    path.resolve(__dirname, "..", "fairvote", "web", "static", "js", "payload.js"),
    "utf8"
  );
  return import("data:text/javascript;base64," + Buffer.from(source).toString("base64"));
}

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));

  const payloadModule = await loadPayloadModule();
  const salt = await payloadModule.passphraseSalt(request.pollId);
  const saltHex = Buffer.from(salt).toString("hex");

  await context.sodium.ready;
  const secretHex = await vm.runInContext(
    "(() => {" +
      "  const salt = window.sodium.from_hex(" + JSON.stringify(saltHex) + ");" +
      "  const out = window.sodium.crypto_pwhash(" +
      "    32," +
      "    " + JSON.stringify(request.passphrase) + "," +
      "    salt," +
      "    window.sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE," +
      "    window.sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE," +
      "    window.sodium.crypto_pwhash_ALG_ARGON2ID13);" +
      "  return window.sodium.to_hex(out);" +
      "})()",
    context
  );

  process.stdout.write(JSON.stringify({ saltHex, secretHex }) + "\n");
}

main().catch((error) => {
  process.stderr.write(String((error && error.message) || error) + "\n");
  process.exit(1);
});
