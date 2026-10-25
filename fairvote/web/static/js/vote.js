/**
 * Ballot page logic.
 *
 * Flow: collect the choices, build the fixed-size payload, encrypt it with the
 * poll's public key (`crypto_box_seal`), derive `ballot_id` from a fresh secret and
 * POST the ciphertext. The secret stays in this browser; only `ballot_id` is sent,
 * and it is a keyed hash the server cannot invert.
 *
 * The library is loaded as two classic scripts before this module (see the
 * template); `window.sodium` is the friendly API built on top of `window.libsodium`.
 */

import {
  buildPayload,
  deriveBallotId,
  deriveSecretFromPassphrase,
  randomSecret,
  secretToWords,
  toBase64,
} from "./payload.js";

const configNode = document.getElementById("poll-config");
const config = JSON.parse(configNode.textContent);
const app = document.getElementById("vote-app");
const form = document.getElementById("ballot-form");
const statusBox = document.getElementById("vote-status");
const receipt = document.getElementById("receipt");
const submitButton = document.getElementById("submit-ballot");

const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
// Retain the exact request only in memory: a network retry must not create a
// new pseudonym, nonce or ciphertext for a vote that may already be accepted.
let preparedBallot = null;

// Previous versions persisted receipts automatically. Remove that legacy copy
// on this page; a shared browser must not retain a durable link to a vote.
try {
  localStorage.removeItem("fairvote.receipts");
} catch (error) {
  // Storage can be disabled.
}

function showStatus(message, kind = "notice") {
  statusBox.textContent = message;
  statusBox.className = kind;
  statusBox.hidden = false;
}

function collectChoices() {
  const choices = {};
  for (const contest of config.contests) {
    const selected = form.querySelector(`input[name="contest-${contest.id}"]:checked`);
    if (selected && selected.value) {
      choices[contest.id] = selected.value;
    }
  }
  return choices;
}

async function chooseSecret(sodium) {
  const passphraseBox = document.getElementById("use-passphrase");
  if (!passphraseBox || !passphraseBox.checked) return randomSecret();
  const passphrase = document.getElementById("passphrase")?.value || "";
  return deriveSecretFromPassphrase(passphrase, config.poll_id);
}

async function waitForSodium() {
  if (!window.sodium) {
    throw new Error("криптографическая библиотека не загрузилась");
  }
  await window.sodium.ready;
  return window.sodium;
}

async function submitBallot(event) {
  event.preventDefault();
  submitButton.disabled = true;
  showStatus("Шифруем бюллетень в браузере…");

  try {
    const sodium = await waitForSodium();
    if (!preparedBallot) {
      const secret = await chooseSecret(sodium);
      const payload = buildPayload({
        pollId: config.poll_id,
        district: config.district,
        choices: collectChoices(),
        spoil: document.getElementById("spoil").checked,
        size: config.ballot_plaintext_bytes,
      });
      const publicKey = sodium.from_hex(config.public_key_hex);
      const sealed = sodium.crypto_box_seal(payload, publicKey);
      const ballotId = await deriveBallotId(secret, config.poll_id);
      const nonce = new Uint8Array(16);
      crypto.getRandomValues(nonce);

      preparedBallot = {
        ballot_id: ballotId,
        nonce: toBase64(nonce),
        ciphertext: toBase64(sealed),
      };
      // Show recovery information before I/O, including when the response is lost.
      document.getElementById("receipt-secret").textContent = secretToWords(secret);
      document.getElementById("receipt-ballot-id").textContent = ballotId;
      receipt.hidden = false;
      for (const input of form.querySelectorAll("input")) input.disabled = true;
    }

    const response = await fetch(`/vote/${config.poll_id}`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "X-CSRFToken": csrfToken,
      },
      body: JSON.stringify(preparedBallot),
    });

    if (!response.ok) {
      showStatus(
        response.status === 409
          ? "Голос не принят: возможно, вы уже голосовали в этом опросе."
          : "Приём не подтверждён. Сохраните секрет и повторите отправку с этой страницы.",
        "notice notice--danger"
      );
      submitButton.disabled = false;
      return;
    }

    const result = await response.json();
    document.getElementById("receipt-ballot-id").textContent = result.ballot_id;
    receipt.hidden = false;
    form.hidden = true;
    showStatus("Голос принят и будет опубликован в ящике после закрытия опроса.");

  } catch (error) {
    showStatus(
      `Не удалось подтвердить приём: ${error.message}. ` +
      "Сохраните секрет. Повторная отправка с этой страницы использует тот же бюллетень.",
      "notice notice--danger"
    );
    submitButton.disabled = false;
  }
}

if (form) {
  form.addEventListener("submit", submitBallot);
}
