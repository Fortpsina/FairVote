#!/usr/bin/env node
/*
 * Cross-implementation check for the ballot payload format.
 *
 * Reads a JSON vector from stdin:
 *   {"options": {...}, "pollId": "...", "secretHex": "...", "pad": "ab..."}
 * and prints:
 *   {"payloadHex": "...", "ballotId": "..."}
 *
 * `tests/test_payload_js.py` compares this output with the Python implementation.
 * The padding source is injected so the comparison is deterministic.
 */

"use strict";

const fs = require("fs");
const path = require("path");

async function main() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));

  const modulePath = path.resolve(
    __dirname,
    "..",
    "fairvote",
    "web",
    "static",
    "js",
    "payload.js"
  );
  // Import through a data: URL: the module is plain ESM, and Node would
  // otherwise treat a .js file in this tree as CommonJS.
  const source = fs.readFileSync(modulePath, "utf8");
  const moduleUrl = "data:text/javascript;base64," + Buffer.from(source).toString("base64");
  const payloadModule = await import(moduleUrl);

  const pad = request.pad ? (length) => request.pad.slice(0, length) : undefined;
  const payload = payloadModule.buildPayload({ ...request.options, pad });
  const secret = Uint8Array.from(Buffer.from(request.secretHex, "hex"));
  const ballotId = await payloadModule.deriveBallotId(secret, request.options.pollId);
  const encoded = payloadModule.secretToWords(secret);

  let derived = null;
  if (request.passphrase) {
    // Requires the vendored libsodium (sumo) to be loaded into this process:
    // the caller passes a small shim module path for that.
    const decoded = payloadModule.secretFromWords(encoded);
    derived = {
      secretHex: Buffer.from(decoded).toString("hex"),
      roundTrip: Buffer.from(decoded).toString("hex") === Buffer.from(secret).toString("hex"),
    };
  }

  process.stdout.write(
    JSON.stringify({
      payloadHex: Buffer.from(payload).toString("hex"),
      payloadLength: payload.length,
      ballotId,
      encoded,
      derived,
    }) + "\n"
  );
}

main().catch((error) => {
  process.stderr.write(String(error && error.stack) + "\n");
  process.exit(1);
});
