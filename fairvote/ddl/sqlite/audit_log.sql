-- FairVote audit store (docs/02 §2.3.4): append-only hash chain.

CREATE TABLE IF NOT EXISTS entry (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,
  kind      TEXT NOT NULL,
  poll_id   TEXT,
  payload   TEXT NOT NULL,
  prev_hash BLOB NOT NULL,
  hash      BLOB NOT NULL UNIQUE,
  sig       BLOB
);
CREATE INDEX IF NOT EXISTS ix_entry_poll ON entry(poll_id, seq);
CREATE INDEX IF NOT EXISTS ix_entry_kind ON entry(kind, seq);

CREATE TABLE IF NOT EXISTS checkpoint (
  seq         INTEGER PRIMARY KEY,
  hash        BLOB NOT NULL,
  signature   BLOB NOT NULL,
  anchor_note TEXT,
  created_at  TEXT NOT NULL
);

-- Even a direct SQL session cannot rewrite history; deleting the file is a
-- different attack, detected by comparing the published head hash.
CREATE TRIGGER IF NOT EXISTS entry_no_update BEFORE UPDATE ON entry
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS entry_no_delete BEFORE DELETE ON entry
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
