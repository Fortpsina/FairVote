/**
 * Ballot payload construction, shared contract with `fairvote/ballots/payload.py`.
 *
 * Every function here is pure: no DOM, no network, no libsodium. The page logic
 * lives in `vote.js`. Keeping the format in one small module means the browser and
 * the server can be compared byte-for-byte (`tools/check_payload.js`).
 *
 * The payload is canonical JSON padded to exactly `size` bytes, so all ciphertexts
 * of a poll have the same length and leak nothing about the number of choices.
 */

export const PAYLOAD_VERSION = 1;
export const SEAL_OVERHEAD = 48;
export const MIN_PAYLOAD = 512;
export const MAX_PAYLOAD = 8192;
export const BALLOT_ID_DOMAIN = "fairvote/ballot/v1\u0000";

const encoder = new TextEncoder();

/** Canonical JSON: sorted keys, no whitespace, integers only. */
export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("only integers are allowed");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalJson).join(",") + "]";
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    const parts = keys.map((key) => JSON.stringify(key) + ":" + canonicalJson(value[key]));
    return "{" + parts.join(",") + "}";
  }
  throw new Error("unsupported value in canonical JSON");
}

function defaultPad(length) {
  if (length <= 0) return "";
  const bytes = new Uint8Array(Math.ceil(length / 2));
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex.slice(0, length);
}

/**
 * Build the plaintext of a ballot.
 *
 * @param {object} options
 * @param {string} options.pollId
 * @param {string} options.district
 * @param {Record<string,string>} options.choices contest id -> option id
 * @param {boolean} [options.spoil]
 * @param {number} options.size exact plaintext size in bytes
 * @param {(length: number) => string} [options.pad]
 * @returns {Uint8Array}
 */
export function buildPayload(options) {
  const { pollId, district, choices = {}, spoil = false, size } = options;
  const pad = options.pad || defaultPad;
  if (!Number.isInteger(size) || size < MIN_PAYLOAD || size > MAX_PAYLOAD) {
    throw new Error("payload size is out of range");
  }
  if (!pollId || !district) throw new Error("pollId and district are required");

  const base = {
    v: PAYLOAD_VERSION,
    poll: pollId,
    district,
    contests: { ...choices },
    spoil: Boolean(spoil),
  };
  const unpadded = encoder.encode(canonicalJson(base));
  if (unpadded.length === size) return unpadded;

  const padOverhead = ',"pad":""'.length;
  const padLength = size - unpadded.length - padOverhead;
  if (padLength < 0) throw new Error("ballot does not fit the requested size");
  const filler = pad(padLength);
  if (typeof filler !== "string" || filler.length !== padLength) {
    throw new Error("padding source returned a wrong length");
  }
  const payload = encoder.encode(canonicalJson({ ...base, pad: filler }));
  if (payload.length !== size) throw new Error("payload size mismatch");
  return payload;
}

function toHex(bytes) {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

/**
 * ballot_id = HMAC-SHA256(secret, "fairvote/ballot/v1\0" + pollId), hex.
 * The secret never leaves the browser.
 */
export async function deriveBallotId(secretBytes, pollId) {
  const key = await crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const message = new Uint8Array([
    ...encoder.encode(BALLOT_ID_DOMAIN),
    ...encoder.encode(pollId),
  ]);
  const signature = await crypto.subtle.sign("HMAC", key, message);
  return toHex(new Uint8Array(signature));
}

/** Random 32-byte secret, displayed once to the voter. */
export function randomSecret() {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return secret;
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Crockford base32 with dashes, so a human can write the secret down. */
export function secretToWords(secretBytes) {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of secretBytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += CROCKFORD[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += CROCKFORD[(value << (5 - bits)) & 31];
  return output.match(/.{1,4}/g).join("-");
}

/** base64 without padding, for JSON transport. */
export function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}


/**
 * Decode a secret written down by a human (Crockford base32 with dashes).
 * Accepts the usual confusions: O->0, I/L->1.
 */
export function secretFromWords(text) {
  const cleaned = String(text || "")
    .toUpperCase()
    .replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1");
  const bytes = [];
  let buffer = 0;
  let bits = 0;
  for (const character of cleaned) {
    const value = CROCKFORD.indexOf(character);
    if (value < 0) throw new Error("секрет содержит недопустимый символ");
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (bytes.length < 32) throw new Error("секрет слишком короткий");
  return new Uint8Array(bytes.slice(0, 32));
}


/**
 * Optional: derive the ballot secret from a passphrase the voter remembers, instead
 * of a generated phrase they must store. Argon2id via libsodium (the sumo build is
 * vendored precisely for `crypto_pwhash`).
 *
 * Salt = SHA-256("fairvote/secret/v1" || pollId) truncated to 16 bytes, so the same
 * passphrase yields the same secret for the same poll and a different one elsewhere.
 *
 * A passphrase is only as strong as its entropy: `validatePassphrase` refuses short
 * ones, because `ballot_id = HMAC(secret, poll_id)` is public and an attacker can
 * test guesses offline.
 */
export const SECRET_DOMAIN = "fairvote/secret/v1";
export const MIN_PASSPHRASE_LENGTH = 20;
export const MIN_PASSPHRASE_WORDS = 4;

export function validatePassphrase(passphrase) {
  const text = String(passphrase || "").trim();
  if (text.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(`кодовое слово короче ${MIN_PASSPHRASE_LENGTH} символов`);
  }
  const words = text.split(/\s+/).filter(Boolean);
  if (words.length < MIN_PASSPHRASE_WORDS) {
    throw new Error(`нужно не меньше ${MIN_PASSPHRASE_WORDS} слов`);
  }
  return text;
}

export async function passphraseSalt(pollId) {
  const message = new TextEncoder().encode(SECRET_DOMAIN + "|" + pollId);
  const digest = await crypto.subtle.digest("SHA-256", message);
  return new Uint8Array(digest).slice(0, 16);
}

export async function deriveSecretFromPassphrase(passphrase, pollId) {
  const text = validatePassphrase(passphrase);
  if (!window.sodium || typeof window.sodium.crypto_pwhash !== "function") {
    throw new Error("криптографическая библиотека не поддерживает Argon2id");
  }
  const sodium = window.sodium;
  await sodium.ready;
  const salt = await passphraseSalt(pollId);
  return sodium.crypto_pwhash(
    32,
    text,
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}
