/* Execute the real submit handler with DOM/network adapters and real payload.js. */
"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { webcrypto } = require("node:crypto");

async function main() {
  if (!global.crypto) global.crypto = webcrypto;
  const config = {
    poll_id: "poll-ui", district: "RU-MOW-77-012", public_key_hex: "00".repeat(32),
    ballot_plaintext_bytes: 1024, contests: [{ id: "c1" }],
  };
  const nodes = new Map();
  for (const id of ["poll-config", "vote-app", "ballot-form", "vote-status", "receipt",
    "submit-ballot", "receipt-secret", "receipt-ballot-id", "use-passphrase", "spoil"]) {
    nodes.set(id, { textContent: "", hidden: true, dataset: {}, checked: false });
  }
  nodes.get("poll-config").textContent = JSON.stringify(config);
  let submit;
  nodes.get("ballot-form").addEventListener = (event, handler) => { submit = handler; };
  nodes.get("ballot-form").querySelector = () => ({ value: "o1" });
  nodes.get("ballot-form").querySelectorAll = () => [];
  global.document = {
    getElementById: (id) => nodes.get(id),
    querySelector: () => ({ content: "csrf-test" }),
  };
  let removed = false;
  global.localStorage = {
    removeItem: (key) => { assert.equal(key, "fairvote.receipts"); removed = true; },
    setItem: () => { throw new Error("ballot secrets must not be persisted"); },
    getItem: () => { throw new Error("ballot secrets must not be loaded"); },
  };
  let plaintext;
  global.window = { sodium: {
    ready: Promise.resolve(), from_hex: () => new Uint8Array(32),
    crypto_box_seal: (payload) => {
      plaintext = JSON.parse(new TextDecoder().decode(payload));
      return new Uint8Array(payload.length + 48);
    },
  } };
  const bodies = [];
  global.fetch = async (url, options) => {
    assert.equal(url, "/vote/poll-ui");
    // The recovery secret must already be visible if the server response is lost.
    assert.ok(nodes.get("receipt-secret").textContent.length > 40);
    assert.equal(nodes.get("receipt").hidden, false);
    bodies.push(options.body);
    if (bodies.length === 1) throw new Error("response lost");
    return { ok: true, json: async () => ({ ballot_id: JSON.parse(options.body).ballot_id }) };
  };
  const dir = path.resolve(__dirname, "..", "fairvote", "web", "static", "js");
  const moduleUrl = (source) => "data:text/javascript;base64," + Buffer.from(source).toString("base64");
  const payloadUrl = moduleUrl(fs.readFileSync(path.join(dir, "payload.js"), "utf8"));
  const source = fs.readFileSync(path.join(dir, "vote.js"), "utf8")
    .replace('"./payload.js"', JSON.stringify(payloadUrl));
  await import(moduleUrl(source));
  await submit({ preventDefault() {} });
  assert.equal(plaintext.district, config.district);
  assert.deepEqual(plaintext.contests, { c1: "o1" });
  assert.equal(nodes.get("submit-ballot").disabled, false);
  const secret = nodes.get("receipt-secret").textContent;
  await submit({ preventDefault() {} });
  assert.equal(bodies.length, 2);
  assert.equal(bodies[0], bodies[1]);
  assert.equal(nodes.get("receipt-secret").textContent, secret);
  assert.equal(nodes.get("ballot-form").hidden, true);
  assert.ok(nodes.get("vote-status").textContent.includes("Голос принят"));
  assert.ok(removed);
}
main().catch((error) => { console.error(error); process.exitCode = 1; });
