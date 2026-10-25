-- FairVote registry store (docs/02 §2.3.1).
-- Minimum personal data: no names, no addresses, no documents, no files.
-- Statements are idempotent so that `flask init-db` is safe to re-run.

CREATE TABLE IF NOT EXISTS district (
  id          INTEGER PRIMARY KEY,
  code        TEXT NOT NULL UNIQUE,
  level       TEXT NOT NULL CHECK (level IN ('country','region','district','precinct')),
  parent_id   INTEGER REFERENCES district(id),
  name        TEXT NOT NULL,
  path        TEXT NOT NULL,
  is_active   INTEGER NOT NULL DEFAULT 1,
  CHECK (level <> 'precinct' OR parent_id IS NOT NULL)
);
CREATE INDEX IF NOT EXISTS ix_district_parent ON district(parent_id);
CREATE INDEX IF NOT EXISTS ix_district_path   ON district(path);

CREATE TABLE IF NOT EXISTS app_user (
  id                    INTEGER PRIMARY KEY,
  login                 TEXT NOT NULL,
  login_display         TEXT NOT NULL,
  password_hash         TEXT NOT NULL,
  totp_secret_enc       BLOB,
  totp_confirmed_at     TEXT,
  totp_last_step        INTEGER,
  totp_fail_count       INTEGER NOT NULL DEFAULT 0,
  recovery_seen_at      TEXT,
  district_id           INTEGER NOT NULL REFERENCES district(id),
  status                TEXT NOT NULL CHECK (status IN
                          ('registered','proof_submitted','verified','rejected','suspended')),
  role                  TEXT NOT NULL DEFAULT 'voter' CHECK (role IN ('voter','admin')),
  verify_method         TEXT CHECK (verify_method IN ('demo','manual','idp','esign')),
  verify_decided_at     TEXT,
  verify_reason_code    TEXT,
  voter_key             BLOB,
  voter_key_version     INTEGER NOT NULL DEFAULT 1,
  failed_login_count    INTEGER NOT NULL DEFAULT 0,
  locked_until          TEXT,
  last_login_at         TEXT,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  deletion_requested_at TEXT,
  deleted_at            TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_login ON app_user(login);
CREATE UNIQUE INDEX IF NOT EXISTS ux_user_voter_key ON app_user(voter_key)
  WHERE voter_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS ix_user_district_status ON app_user(district_id, status);

CREATE TABLE IF NOT EXISTS recovery_code (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  idx        INTEGER NOT NULL,
  code_hash  TEXT NOT NULL,
  used_at    TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (user_id, idx)
);

CREATE TABLE IF NOT EXISTS session (
  id              BLOB PRIMARY KEY,
  user_id         INTEGER REFERENCES app_user(id) ON DELETE CASCADE,
  pending_user_id INTEGER REFERENCES app_user(id) ON DELETE CASCADE,
  auth_level      TEXT NOT NULL CHECK (auth_level IN ('anon','password','full','admin')),
  data            BLOB NOT NULL,
  csrf_token      BLOB NOT NULL,
  created_at      TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL,
  expires_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_session_expires ON session(expires_at);
CREATE INDEX IF NOT EXISTS ix_session_user ON session(user_id);

-- One-time verification code: the applicant gives it to the provider operator,
-- who records the decision out of band. No documents are uploaded (docs/05 D-3).
CREATE TABLE IF NOT EXISTS verification_request (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  method        TEXT NOT NULL CHECK (method IN ('demo','manual','idp','esign')),
  code_hash     BLOB NOT NULL UNIQUE,
  code_attempts INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  decided_at    TEXT,
  decision      TEXT CHECK (decision IN ('approved','rejected')),
  reason_code   TEXT,
  decided_by    TEXT
);
CREATE INDEX IF NOT EXISTS ix_vreq_user ON verification_request(user_id, created_at);

-- The only trace of participation: no time of day, no ballot reference.
CREATE TABLE IF NOT EXISTS participation (
  poll_id  TEXT NOT NULL,
  user_id  INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  voted_on TEXT NOT NULL,
  PRIMARY KEY (poll_id, user_id)
);

-- NOTE: there is intentionally no live_vote / superseded_ballot table here.
-- The link "person <-> ballot_id" does not exist in the schema (docs/05 D-2).

CREATE TABLE IF NOT EXISTS rate_counter (
  scope        TEXT NOT NULL,
  key          TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  counter      INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  PRIMARY KEY (scope, key, window_start)
);
CREATE INDEX IF NOT EXISTS ix_rate_expires ON rate_counter(expires_at);

CREATE TABLE IF NOT EXISTS auth_event (
  id      INTEGER PRIMARY KEY,
  ts      TEXT NOT NULL,
  user_id INTEGER,
  event   TEXT NOT NULL,
  detail  TEXT
);
CREATE INDEX IF NOT EXISTS ix_auth_event_ts ON auth_event(ts);
