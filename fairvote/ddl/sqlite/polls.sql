-- FairVote polls store (docs/02 §2.3.2): public content and eligibility commitments.
-- Nothing here is personal data.

CREATE TABLE IF NOT EXISTS poll (
  id                     TEXT PRIMARY KEY,
  slug                   TEXT NOT NULL UNIQUE,
  title                  TEXT NOT NULL,
  summary                TEXT NOT NULL,
  description_md         TEXT NOT NULL,
  description_html       TEXT NOT NULL,
  system                 TEXT NOT NULL CHECK (system IN ('list','district','mixed')),
  status                 TEXT NOT NULL CHECK (status IN
                           ('draft','scheduled','open','closed','published','cancelled')),
  starts_at              TEXT NOT NULL,
  ends_at                TEXT NOT NULL,
  k_threshold            INTEGER NOT NULL DEFAULT 10 CHECK (k_threshold >= 1),
  revote_policy          TEXT NOT NULL DEFAULT 'first_wins'
                           CHECK (revote_policy IN ('first_wins')),
  ballot_plaintext_bytes INTEGER NOT NULL DEFAULT 1024
                           CHECK (ballot_plaintext_bytes BETWEEN 512 AND 8192),
  key_publish_after      TEXT,
  public_key             BLOB,
  key_fingerprint        TEXT,
  eligibility_root       BLOB,
  eligible_total         INTEGER,
  started_committed_at   TEXT,
  closed_at              TEXT,
  private_key_published_at TEXT,
  js_manifest_hash       TEXT,
  created_by             INTEGER,
  created_at             TEXT NOT NULL,
  updated_at             TEXT NOT NULL,
  CHECK (ends_at > starts_at),
  CHECK (status <> 'open' OR (public_key IS NOT NULL AND eligibility_root IS NOT NULL))
);

-- Poll content is frozen once voting starts. The application also refuses edits;
-- this trigger is the second line of defence at the storage level.
CREATE TRIGGER IF NOT EXISTS poll_immutable_after_start
BEFORE UPDATE ON poll
WHEN OLD.status IN ('open','closed','published')
 AND (NEW.title                   IS NOT OLD.title
   OR NEW.summary                 IS NOT OLD.summary
   OR NEW.description_md          IS NOT OLD.description_md
   OR NEW.system                  IS NOT OLD.system
   OR NEW.starts_at               IS NOT OLD.starts_at
   OR NEW.ends_at                 IS NOT OLD.ends_at
   OR NEW.k_threshold             IS NOT OLD.k_threshold
   OR NEW.revote_policy           IS NOT OLD.revote_policy
   OR NEW.key_publish_after       IS NOT OLD.key_publish_after
   OR NEW.public_key              IS NOT OLD.public_key
   OR NEW.ballot_plaintext_bytes  IS NOT OLD.ballot_plaintext_bytes)
BEGIN SELECT RAISE(ABORT, 'poll content is immutable after start'); END;

CREATE TABLE IF NOT EXISTS contest (
  id                TEXT PRIMARY KEY,
  poll_id           TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  scope             TEXT NOT NULL CHECK (scope IN ('nationwide','district')),
  district_code     TEXT,
  kind              TEXT NOT NULL CHECK (kind IN ('party_list','candidate','referendum')),
  title             TEXT NOT NULL,
  description_html  TEXT NOT NULL DEFAULT '',
  allow_against_all INTEGER NOT NULL DEFAULT 1,
  display_order     INTEGER NOT NULL,
  CHECK ((scope = 'nationwide' AND district_code IS NULL)
      OR (scope = 'district'   AND district_code IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS ix_contest_poll ON contest(poll_id, display_order);

CREATE TABLE IF NOT EXISTS option (
  id            TEXT PRIMARY KEY,
  contest_id    TEXT NOT NULL REFERENCES contest(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('candidate','party','against_all')),
  name          TEXT NOT NULL,
  bio_html      TEXT,
  link_url      TEXT CHECK (link_url IS NULL
                            OR link_url LIKE 'https://%'
                            OR link_url LIKE 'http://%'),
  display_order INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_option_contest ON option(contest_id, display_order);

CREATE TABLE IF NOT EXISTS poll_district (
  poll_id       TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  district_code TEXT NOT NULL,
  display_name  TEXT NOT NULL,
  PRIMARY KEY (poll_id, district_code)
);

CREATE TABLE IF NOT EXISTS eligibility_commitment (
  poll_id        TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  district_code  TEXT NOT NULL,
  eligible_count INTEGER NOT NULL,
  subtree_root   BLOB NOT NULL,
  PRIMARY KEY (poll_id, district_code)
);

CREATE TABLE IF NOT EXISTS poll_revision (
  poll_id       TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  revision      INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  content_hash  BLOB NOT NULL,
  created_at    TEXT NOT NULL,
  PRIMARY KEY (poll_id, revision)
);

CREATE TABLE IF NOT EXISTS admin_action (
  id        INTEGER PRIMARY KEY,
  ts        TEXT NOT NULL,
  admin_id  INTEGER NOT NULL,
  action    TEXT NOT NULL,
  poll_id   TEXT,
  audit_seq INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_admin_action_poll ON admin_action(poll_id, id);
