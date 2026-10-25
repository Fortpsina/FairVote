#!/usr/bin/env node
/*
 * Acceptance check for the vendored libsodium build.
 *
 * The two vendored files are classic global scripts: the core defines `libsodium`,
 * the wrapper replaces it with the friendlier `sodium` API. This script loads them
 * into a browser-like context (window/self/crypto/atob) and proves that
 * `crypto_box_seal` round-trips — i.e. the exact bytes we serve work without a
 * network fetch and without a bundler.
 *
 * Exit codes: 0 = ok, 1 = the bundle is broken, 2 = files missing.
 */

"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { webcrypto } = require("crypto");

const vendorDir = path.resolve(__dirname, "..", "fairvote", "web", "static", "vendor");
const corePath = path.join(vendorDir, "libsodium.js");
const wrapperPath = path.join(vendorDir, "libsodium-wrappers.js");

for (const file of [corePath, wrapperPath]) {
  if (!fs.existsSync(file)) {
    process.stderr.write(`missing vendor file: ${file}\n`);
    process.exit(2);
  }
}

function toBase64(buffer) {
  return Buffer.from(buffer).toString("base64");
}

function fromBase64(text) {
  return Buffer.from(text, "base64");
}

const context = {
  console,
  crypto: webcrypto,
  atob: (value) => atob(String(value)),
  btoa: (value) => btoa(String(value)),
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);

vm.runInContext(fs.readFileSync(corePath, "utf8"), context, { filename: "libsodium.js" });
vm.runInContext(fs.readFileSync(wrapperPath, "utf8"), context, { filename: "libsodium-wrappers.js" });

(async () => {
  const sodium = context.sodium;
  if (!sodium || typeof sodium.ready === "undefined") {
    process.stderr.write("no `sodium` global after loading the bundle\n");
    process.exit(1);
  }
  await sodium.ready;
  if (typeof sodium.crypto_box_seal !== "function" || typeof sodium.crypto_box_seal_open !== "function") {
    process.stderr.write("crypto_box_seal is unavailable in the vendored build\n");
    process.exit(1);
  }
  const result = await vm.runInContext(
    `(async () => {
       const pair = sodium.crypto_box_keypair();
       const message = new Uint8Array([1, 2, 3, 4, 5]);
       const sealed = sodium.crypto_box_seal(message, pair.publicKey);
       const opened = sodium.crypto_box_seal_open(sealed, pair.publicKey, pair.privateKey);
       return {
         version: sodium.SODIUM_VERSION_STRING,
         sealedLength: sealed.length,
         roundtrip: Array.from(opened).join(",") === "1,2,3,4,5",
       };
     })()`,
    context
  );
  process.stdout.write(
    JSON.stringify({ ok: result.roundtrip, libsodium: result.version, sealedLength: result.sealedLength }) + "\n"
  );
  process.exit(result.roundtrip ? 0 : 1);
})().catch((error) => {
  process.stderr.write(`vendor check failed: ${error && error.message}\n`);
  process.exit(1);
});
