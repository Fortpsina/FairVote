-- FairVote ballot box store (docs/02 §2.3.3).
-- No user id, no IP, no session, no user agent: nothing here identifies a person.
-- `ballot_id` is a public pseudonym used only so a voter can find their own row.

CREATE TABLE IF NOT EXISTS ballot_queue (
  id            INTEGER PRIMARY KEY,
  poll_id       TEXT NOT NULL,
  ballot_id     TEXT NOT NULL,
  district_code TEXT NOT NULL,
  client_nonce  BLOB NOT NULL,
  ciphertext    BLOB NOT NULL,
  received_slot TEXT NOT NULL,
  confirmed     INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  UNIQUE (poll_id, client_nonce),
  UNIQUE (poll_id, ballot_id)
);
CREATE INDEX IF NOT EXISTS ix_queue_pending ON ballot_queue(confirmed, created_at);

CREATE TABLE IF NOT EXISTS ballot (
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  poll_id       TEXT NOT NULL,
  ballot_id     TEXT NOT NULL,
  district_code TEXT NOT NULL,
  ciphertext    BLOB NOT NULL,
  slot          TEXT NOT NULL,
  batch_id      INTEGER NOT NULL,
  UNIQUE (poll_id, ballot_id)
);
CREATE INDEX IF NOT EXISTS ix_ballot_poll_seq ON ballot(poll_id, seq);

CREATE TABLE IF NOT EXISTS ballot_batch (
  id          INTEGER PRIMARY KEY,
  poll_id     TEXT NOT NULL,
  size        INTEGER NOT NULL,
  merkle_root BLOB NOT NULL,
  slot        TEXT NOT NULL,
  audit_seq   INTEGER NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS published_key (
  poll_id      TEXT PRIMARY KEY,
  public_key   BLOB NOT NULL,
  private_key  BLOB,
  fingerprint  TEXT NOT NULL,
  published_at TEXT NOT NULL
);

-- The published ballot box is append-only: rows are written once, at batch commit.
CREATE TRIGGER IF NOT EXISTS ballot_no_update BEFORE UPDATE ON ballot
BEGIN SELECT RAISE(ABORT, 'ballot box is append-only'); END;
CREATE TRIGGER IF NOT EXISTS ballot_no_delete BEFORE DELETE ON ballot
BEGIN SELECT RAISE(ABORT, 'ballot box is append-only'); END;
