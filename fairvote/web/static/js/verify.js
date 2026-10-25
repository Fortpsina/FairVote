/**
 * Local ballot lookup: entirely in the browser.
 *
 * The server deliberately has no "is this ballot in the box?" endpoint: that would be
 * an oracle a coercer could use ("show me your ballot is there"). Instead the voter
 * downloads the published JSONL and the page compares `HMAC(secret, poll_id)` with
 * the `ballot_id` of each row — locally, with no network request.
 */

import { deriveBallotId, secretFromWords } from "./payload.js";

const secretInput = document.getElementById("secret");
const fileInput = document.getElementById("ballots");
const button = document.getElementById("check-ballot");
const result = document.getElementById("verify-result");

function show(message, kind = "notice") {
  result.textContent = message;
  result.className = kind;
  result.hidden = false;
}

async function parseBallots(file) {
  const text = await file.text();
  const rows = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      rows.push(JSON.parse(line));
    } catch (error) {
      throw new Error("файл повреждён: одна из строк не является JSON");
    }
  }
  if (!rows.length) throw new Error("в файле нет бюллетеней");
  return rows;
}

async function findBallot() {
  try {
    const file = fileInput.files && fileInput.files[0];
    if (!file) {
      show("Выберите файл ballots.jsonl", "notice notice--danger");
      return;
    }
    const secret = secretFromWords(secretInput.value);
    const rows = await parseBallots(file);
    const pollId = rows[0].poll;
    if (!pollId) throw new Error("в файле нет идентификатора опроса");

    const ballotId = await deriveBallotId(secret, pollId);
    const matches = rows.filter((row) => row.ballot_id === ballotId);
    if (!matches.length) {
      show(
        "Бюллетень не найден. Проверьте секрет и опрос: возможно, вы смотрите чужой опрос " +
          "или файл скачан до закрытия.",
        "notice notice--danger"
      );
      return;
    }
    const row = matches[matches.length - 1];
    show(
      `Бюллетень найден: №${row.seq}, округ ${row.district}, час ${row.slot}. ` +
        `Идентификатор ${ballotId.slice(0, 16)}… Выбор в файле зашифрован — ` +
        `прочитать его можно только опубликованным ключом опроса.`
    );
  } catch (error) {
    show(error.message, "notice notice--danger");
  }
}

if (button) {
  button.addEventListener("click", findBallot);
}
