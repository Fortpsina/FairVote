# FairVote — 2. Архитектура и схема БД

Статус: проектное решение, код не написан. Версия 1.0. См. docs/01 (модель угроз),
docs/03 (эндпоинты), docs/04 (допущения и открытые вопросы).

---

## 2.1. Общая картина

```
                     ┌──────────────────────────────┐
   браузер           │  Flask (WSGI) на PythonAnywhere│
   ────────           │  4 воркера, без общего state  │
   GET /polls ───────▶│  ┌─────────────────────────┐  │
   POST /vote  ──────▶│  │ web/ (blueprints)       │  │
   (шифртекст)        │  └───┬───────┬───────┬─────┘  │
                      │      │       │       │        │
                      │  ┌───▼──┐ ┌──▼───┐ ┌─▼─────┐  │
                      │  │polls │ │regist│ │ballots│  │
                      │  │svc   │ │ry svc│ │svc    │  │
                      │  └───┬──┘ └──┬───┘ └─┬─────┘  │
                      │      │       │       │        │
                      │  ┌───▼──┐ ┌──▼───┐ ┌─▼─────┐  │
                      │  │polls │ │regist│ │ballot │  │
                      │  │.sqlite│ │ry.sql│ │_box   │  │
                      │  └───┬──┘ └──┬───┘ └─┬─────┘  │
                      │      └───┬───┴───────┘        │
                      │      ┌───▼──────────────┐     │
                      │      │ audit_log.sqlite │     │
                      │      └──────────────────┘     │
                      └───────────────┬───────────────┘
                                      │ ежедневный экспорт (подпись Ed25519)
                                      ▼
                     /transparency/export/*.jsonl + *.sig  ← зеркала, verify.py
```

Свойства, на которых держится конструкция:

1. **Четыре независимых SQLite-файла** и четыре независимых модуля доступа. Нет
   внешних ключей между файлами; целостность между ними — через `audit_log`.
2. **Нет состояния в памяти процесса**: серверные сессии, rate limit, lockout, очередь
   бюллетеней, «начать опрос» — всё в БД. Любой воркер может обработать любой запрос.
3. **Сервер не может расшифровать бюллетень**, пока не опубликован приватный ключ.
   Промежуточные результаты недоступны не по политике, а криптографически.
4. **Публичная часть — статический, дешёвый HTML** (без JS), дорогая криптография — в
   браузере; это экономит CPU-квоту PA.
5. **Идемпотентность и детерминизм** всех операций, которые пишут в журнал: повторный
   запуск не создаёт дублей (см. §2.6.4).

## 2.2. Структура кода

```
fairvote/
├── __init__.py              # create_app(): конфиг, движки, blueprints, error handlers
├── config.py                # Config, DemoConfig, TestConfig; load_secrets()
├── i18n.py                  # каталог строк (ru), _(), get_locale()
├── db.py                    # EngineRegistry: 4 engine, PRAGMA, scoped sessions, helpers
├── security/
│   ├── crypto.py            # HKDF, AES-256-GCM, HMAC, Ed25519, sealed box (PyNaCl)
│   ├── canonical.py         # canonical_json() по RFC 8785-подмножеству
│   ├── passwords.py         # Argon2id wrapper, параметры, dummy-hash, needs_rehash
│   ├── sessions.py          # DBSessionInterface (flask SessionInterface)
│   ├── csrf.py              # CSRFProtect + Origin/Sec-Fetch-Site guard
│   ├── ratelimit.py         # Flask-Limiter + DBStorage(limits.storage.Storage)
│   ├── lockout.py           # учёт неудачных попыток, экспоненциальный backoff
│   ├── headers.py           # CSP, HSTS, Referrer-Policy, Cache-Control
│   └── redact.py            # logging filter: никаких PII/IP в логах
├── registry/
│   ├── models.py            # district, app_user, session, recovery_code, ...
│   ├── identity.py          # voter_key: нормализация + Argon2id + UNIQUE
│   ├── service.py           # регистрация, статусы, удаление, purge voter_key
│   └── provider.py          # VerificationProvider (ABC) + DemoProvider + ManualProvider
│                            # файлы документов НЕ принимаются (docs/05 D-3)
├── polls/
│   ├── models.py            # poll, contest, option, poll_district, commitments
│   ├── content.py           # Markdown → HTML через nh3 (whitelist)
│   ├── service.py           # CRUD до старта, старт, закрытие, публикация ключа
│   └── eligibility.py       # снапшот допущенных, Меркл-корни, персональные пути
├── ballots/
│   ├── models.py            # ballot_queue, ballot, ballot_batch, published_key
│   ├── service.py           # приём, идемпотентность, запрет второго бюллетеня
│   ├── queue.py             # commit_batch: перемешивание, задержки, корень пачки
│   └── tally.py             # (только для verify-страницы) расшифровка+подсчёт
├── audit/
│   ├── models.py            # entry, checkpoint
│   ├── chain.py             # append(kind, poll_id, payload) — цепочка хэшей
│   └── exporter.py          # JSONL + Ed25519-подпись + дешёвая пагинация
├── web/
│   ├── public.py            # лендинг, опросы, прозрачность, политика
│   ├── auth.py              # регистрация, вход, TOTP, recovery
│   ├── account.py           # профиль, смена пароля, удаление
│   ├── verify.py            # подача доказательств
│   ├── vote.py              # страница бюллетеня, приём шифртекста
│   ├── admin.py             # опросы/контент/расписание (без registry!)
│   ├── templates/
│   └── static/              # css, js (модули), vendor/libsodium-wrappers.min.js
├── cli.py                   # flask-команды (см. §2.10)
└── ddl/
    ├── sqlite/*.sql
    └── mysql/*.sql
scripts/
├── verify.py                # независимая проверка: цепочка, подписи, расшифровка, итоги
└── poll_keygen.py           # ОФЛАЙН: генерация пары ключей опроса (+ Shamir, опционально)
tests/                       # pytest, см. §2.12
docs/                        # этот проект
```

Правила зависимостей (проверяются тестом `test_import_graph`):

* `web/admin.py` **не может** импортировать `registry.*` — только `polls.*`,
  `audit.*` и агрегаты через `registry.aggregates` (только числа, без строк).
* `ballots.*` не может импортировать `registry.*`; связь «пользователь → участие»
  выполняет `web/vote.py` (координатор), который пишет в оба хранилища.
* `polls.*` не импортирует `ballots.*` (кроме `tally` — только чтение публичных данных).
* `security/*` не импортирует бизнес-модули.

## 2.3. Хранилища

Четыре файла в `instance/db/` (вне web-root, `chmod 700` на каталог):

| Файл | Модуль | Что внутри | PII | Публичность |
|------|--------|------------|-----|-------------|
| `registry.sqlite` | `registry` | аккаунты, округа, сессии, заявки верификации (код/метод/дата), участие | минимум | никогда, только агрегаты |
| `polls.sqlite` | `polls` | опросы, контесты, варианты, commitment допущенных | нет | да (без черновиков) |
| `ballot_box.sqlite` | `ballots` | очередь, шифртексты, пачки, опубликованный ключ | нет | да, после закрытия |
| `audit_log.sqlite` | `audit` | цепочка хэшей, контрольные точки | нет | да |

Общие PRAGMA на каждое соединение (через `connect` event): `journal_mode=WAL`,
`foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`, `trusted_schema=OFF`.
Режим «один писатель»: все пишущие транзакции открываются как `BEGIN IMMEDIATE`
(SQLAlchemy: `engine.begin()` + `conn.exec_driver_sql("BEGIN IMMEDIATE")` для SQLite;
для MySQL — `SELECT ... FOR UPDATE` в портируемом слое `db.write_tx()`).

### 2.3.1. registry.sqlite

```sql
CREATE TABLE district (
  id          INTEGER PRIMARY KEY,
  code        TEXT NOT NULL UNIQUE,          -- 'RU' | 'RU-MOW' | 'RU-MOW-77-012' | 'RU-MOW-77-012-0041'
  level       TEXT NOT NULL CHECK (level IN ('country','region','district','precinct')),
  parent_id   INTEGER REFERENCES district(id),
  name        TEXT NOT NULL,
  path        TEXT NOT NULL,                 -- 'RU/RU-MOW/RU-MOW-77-012'
  is_active   INTEGER NOT NULL DEFAULT 1,
  CHECK (level <> 'precinct' OR parent_id IS NOT NULL)
);
CREATE INDEX ix_district_parent ON district(parent_id);
CREATE INDEX ix_district_path   ON district(path);

CREATE TABLE app_user (
  id                    INTEGER PRIMARY KEY,
  login                 TEXT NOT NULL,       -- casefold(NFKC(login)), 3..32, [a-z0-9._-]
  login_display         TEXT NOT NULL,
  password_hash         TEXT NOT NULL,       -- argon2id PHC
  totp_secret_enc       BLOB,                -- AES-256-GCM, AAD='totp:<id>'
  totp_confirmed_at     TEXT,
  totp_last_step        INTEGER,             -- анти-replay
  totp_fail_count       INTEGER NOT NULL DEFAULT 0,
  recovery_seen_at      TEXT,
  district_id           INTEGER NOT NULL REFERENCES district(id),
  status                TEXT NOT NULL CHECK (status IN
                          ('registered','proof_submitted','verified','rejected','suspended')),
  role                  TEXT NOT NULL DEFAULT 'voter' CHECK (role IN ('voter','admin')),
  verify_method         TEXT CHECK (verify_method IN ('demo','manual','idp','esign')),
  verify_decided_at     TEXT,
  verify_reason_code    TEXT,                -- код, не свободный текст
  voter_key             BLOB,                -- 32 байта; NULL после purge
  voter_key_version     INTEGER NOT NULL DEFAULT 1,
  failed_login_count    INTEGER NOT NULL DEFAULT 0,
  locked_until          TEXT,
  last_login_at         TEXT,
  created_at            TEXT NOT NULL,
  updated_at            TEXT NOT NULL,
  deletion_requested_at TEXT,
  deleted_at            TEXT
);
CREATE UNIQUE INDEX ux_user_login ON app_user(login);
CREATE UNIQUE INDEX ux_user_voter_key ON app_user(voter_key) WHERE voter_key IS NOT NULL;
CREATE INDEX ix_user_district_status ON app_user(district_id, status);

CREATE TABLE recovery_code (
  id         INTEGER PRIMARY KEY,
  user_id    INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  idx        INTEGER NOT NULL,
  code_hash  TEXT NOT NULL,                  -- argon2id
  used_at    TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (user_id, idx)
);

CREATE TABLE session (
  id             BLOB PRIMARY KEY,           -- SHA-256(cookie token), 32 байта
  user_id        INTEGER REFERENCES app_user(id) ON DELETE CASCADE,
  pending_user_id INTEGER REFERENCES app_user(id) ON DELETE CASCADE,
  auth_level     TEXT NOT NULL CHECK (auth_level IN ('anon','password','full','admin')),
  data           BLOB NOT NULL,              -- JSON payload Flask-сессии (flash и пр.)
  csrf_token     BLOB NOT NULL,
  created_at     TEXT NOT NULL,
  last_seen_at   TEXT NOT NULL,
  expires_at     TEXT NOT NULL
);
CREATE INDEX ix_session_expires ON session(expires_at);
CREATE INDEX ix_session_user ON session(user_id);

-- D-3: файлы документов не принимаются. Хранится только заявка (код, метод, решение).
CREATE TABLE verification_request (
  id            INTEGER PRIMARY KEY,
  user_id       INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  method        TEXT NOT NULL CHECK (method IN ('demo','manual','idp','esign')),
  code_hash     BLOB NOT NULL UNIQUE,        -- SHA-256(одноразовый код); сам код не хранится
  code_attempts INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,               -- 14 дней
  decided_at    TEXT,
  decision      TEXT CHECK (decision IN ('approved','rejected')),
  reason_code   TEXT,
  decided_by    TEXT                         -- 'demo' | 'manual:<provider>' — без ПДн
);
CREATE INDEX ix_vreq_user ON verification_request(user_id, created_at);

CREATE TABLE participation (
  poll_id  TEXT NOT NULL,
  user_id  INTEGER NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
  voted_on TEXT NOT NULL,                    -- 'YYYY-MM-DD' (без времени!)
  PRIMARY KEY (poll_id, user_id)
);

-- D-2: таблиц live_vote / superseded_ballot в схеме НЕТ. Связи «человек ↔ ballot_id»
-- не существует вообще; переголосование невозможно (docs/05 D-2).

CREATE TABLE rate_counter (
  scope         TEXT NOT NULL,               -- 'ip' | 'acct' | 'user' | 'global'
  key           TEXT NOT NULL,               -- HMAC(k_ip_hash, ...) hex, без открытого IP
  window_start  INTEGER NOT NULL,            -- unix-время начала окна
  counter       INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (scope, key, window_start)
);
CREATE INDEX ix_rate_expires ON rate_counter(expires_at);

CREATE TABLE auth_event (                    -- внутренний аудит входов, без PII
  id         INTEGER PRIMARY KEY,
  ts         TEXT NOT NULL,
  user_id    INTEGER,                        -- NULL для неудачных попыток
  event      TEXT NOT NULL,                  -- 'login_ok','login_fail','totp_fail','lockout',...
  detail     TEXT                            -- код, без свободного текста
);
```

Особенности:

* `login` хранится нормализованным (casefold+NFKC), отображаемое имя — отдельно.
* `voter_key` — BLOB, не строка: нельзя случайно залогировать.
* `verification_request` хранит только `SHA-256` одноразового кода, метод и решение:
  ни файлов, ни ФИО, ни адреса (docs/05 D-3).
* Таблиц `live_vote`/`superseded_ballot` нет: связи «человек ↔ ballot_id» в схеме
  не существует (docs/05 D-2). `participation` — единственный след участия.

### 2.3.2. polls.sqlite

```sql
CREATE TABLE poll (
  id                     TEXT PRIMARY KEY,   -- uuid4 hex
  slug                   TEXT NOT NULL UNIQUE,
  title                  TEXT NOT NULL,
  summary                TEXT NOT NULL,
  description_md         TEXT NOT NULL,
  description_html       TEXT NOT NULL,      -- nh3-санитизированный кэш
  system                 TEXT NOT NULL CHECK (system IN ('list','district','mixed')),
  status                 TEXT NOT NULL CHECK (status IN
                           ('draft','scheduled','open','closed','published','cancelled')),
  starts_at              TEXT NOT NULL,      -- UTC ISO-8601 'Z'
  ends_at                TEXT NOT NULL,
  k_threshold            INTEGER NOT NULL DEFAULT 10 CHECK (k_threshold >= 1),
  revote_policy          TEXT NOT NULL DEFAULT 'first_wins'
                           CHECK (revote_policy IN ('first_wins')),  -- см. docs/05 D-2
  ballot_plaintext_bytes INTEGER NOT NULL DEFAULT 1024
                           CHECK (ballot_plaintext_bytes BETWEEN 512 AND 8192),
  key_publish_after      TEXT,               -- NULL = ключ публикуется сразу (docs/05 D-4)
  public_key             BLOB,               -- 32 байта X25519 (crypto_box_seal)
  key_fingerprint        TEXT,               -- hex(BLAKE2b-256(pubkey)), commitment
  eligibility_root       BLOB,               -- агрегатный корень
  eligible_total         INTEGER,
  started_committed_at   TEXT,
  closed_at              TEXT,
  private_key_published_at TEXT,
  js_manifest_hash       TEXT,               -- хэш манифеста статики на момент старта
  created_by             INTEGER,            -- admin user id (в registry), только для аудита
  created_at             TEXT NOT NULL,
  updated_at             TEXT NOT NULL,
  CHECK (ends_at > starts_at),
  CHECK (status <> 'open' OR (public_key IS NOT NULL AND eligibility_root IS NOT NULL))
);

CREATE TRIGGER poll_immutable_after_start
BEFORE UPDATE ON poll
WHEN OLD.status IN ('open','closed','published')
 AND (NEW.title                 IS NOT OLD.title
   OR NEW.summary               IS NOT OLD.summary
   OR NEW.description_md        IS NOT OLD.description_md
   OR NEW.system                IS NOT OLD.system
   OR NEW.starts_at             IS NOT OLD.starts_at
   OR NEW.ends_at               IS NOT OLD.ends_at
   OR NEW.k_threshold           IS NOT OLD.k_threshold
   OR NEW.revote_policy         IS NOT OLD.revote_policy
   OR NEW.key_publish_after     IS NOT OLD.key_publish_after
   OR NEW.public_key            IS NOT OLD.public_key
   OR NEW.ballot_plaintext_bytes IS NOT OLD.ballot_plaintext_bytes)
BEGIN SELECT RAISE(ABORT, 'poll content is immutable after start'); END;

CREATE TABLE contest (
  id               TEXT PRIMARY KEY,
  poll_id          TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  scope            TEXT NOT NULL CHECK (scope IN ('nationwide','district')),
  district_code    TEXT,                     -- NULL для nationwide
  kind             TEXT NOT NULL CHECK (kind IN ('party_list','candidate','referendum')),
  title            TEXT NOT NULL,
  description_html TEXT NOT NULL DEFAULT '',
  allow_against_all INTEGER NOT NULL DEFAULT 1,
  display_order    INTEGER NOT NULL,
  CHECK ((scope = 'nationwide' AND district_code IS NULL)
      OR (scope = 'district'   AND district_code IS NOT NULL))
);
CREATE INDEX ix_contest_poll ON contest(poll_id, display_order);

CREATE TABLE option (
  id            TEXT PRIMARY KEY,
  contest_id    TEXT NOT NULL REFERENCES contest(id) ON DELETE CASCADE,
  kind          TEXT NOT NULL CHECK (kind IN ('candidate','party','against_all')),
  name          TEXT NOT NULL,
  bio_html      TEXT,
  link_url      TEXT CHECK (link_url IS NULL OR link_url LIKE 'https://%'
                                                 OR link_url LIKE 'http://%'),
  display_order INTEGER NOT NULL
);
CREATE INDEX ix_option_contest ON option(contest_id, display_order);

CREATE TABLE poll_district (
  poll_id       TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  district_code TEXT NOT NULL,               -- копия кода из registry (без FK между файлами)
  display_name  TEXT NOT NULL,
  PRIMARY KEY (poll_id, district_code)
);

CREATE TABLE eligibility_commitment (
  poll_id       TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  district_code TEXT NOT NULL,
  eligible_count INTEGER NOT NULL,
  subtree_root  BLOB NOT NULL,
  PRIMARY KEY (poll_id, district_code)
);

CREATE TABLE poll_revision (                 -- публичная история правок до старта
  poll_id       TEXT NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
  revision      INTEGER NOT NULL,
  snapshot_json TEXT NOT NULL,
  content_hash  BLOB NOT NULL,
  created_at    TEXT NOT NULL,
  PRIMARY KEY (poll_id, revision)
);

CREATE TABLE admin_action (                  -- зеркало для быстрого UI; истина — audit_log
  id         INTEGER PRIMARY KEY,
  ts         TEXT NOT NULL,
  admin_id   INTEGER NOT NULL,
  action     TEXT NOT NULL,
  poll_id    TEXT,
  audit_seq  INTEGER NOT NULL
);
```

### 2.3.3. ballot_box.sqlite

```sql
CREATE TABLE ballot_queue (                  -- staging: принято, но ещё не опубликовано
  id            INTEGER PRIMARY KEY,
  poll_id       TEXT NOT NULL,
  ballot_id     TEXT NOT NULL,               -- публичный псевдоним, 64 hex
  district_code TEXT NOT NULL,               -- server-authoritative (из реестра, не из клиента)
  client_nonce  BLOB NOT NULL,               -- 16 байт из браузера (идемпотентность)
  ciphertext    BLOB NOT NULL,
  received_slot TEXT NOT NULL,               -- 'YYYY-MM-DDTHH:00Z'
  confirmed     INTEGER NOT NULL DEFAULT 0,
  created_at    TEXT NOT NULL,
  UNIQUE (poll_id, client_nonce),
  UNIQUE (poll_id, ballot_id)                -- один бюллетень на псевдоним (docs/05 D-2)
);
CREATE INDEX ix_queue_pending ON ballot_queue(confirmed, created_at);

CREATE TABLE ballot (                        -- публикуемый ящик
  seq           INTEGER PRIMARY KEY AUTOINCREMENT,
  poll_id       TEXT NOT NULL,
  ballot_id     TEXT NOT NULL,
  district_code TEXT NOT NULL,
  ciphertext    BLOB NOT NULL,
  slot          TEXT NOT NULL,               -- час, не минута
  batch_id      INTEGER NOT NULL,
  UNIQUE (poll_id, ballot_id)
);
CREATE INDEX ix_ballot_poll_seq ON ballot(poll_id, seq);

CREATE TABLE ballot_batch (
  id          INTEGER PRIMARY KEY,
  poll_id     TEXT NOT NULL,
  size        INTEGER NOT NULL,
  merkle_root BLOB NOT NULL,                 -- корень над ciphertext'ами пачки
  slot        TEXT NOT NULL,
  audit_seq   INTEGER NOT NULL,
  created_at  TEXT NOT NULL
);

CREATE TABLE published_key (
  poll_id      TEXT PRIMARY KEY,
  public_key   BLOB NOT NULL,
  private_key  BLOB,                         -- заполняется ТОЛЬКО после закрытия
  fingerprint  TEXT NOT NULL,
  published_at TEXT NOT NULL
);

CREATE TRIGGER ballot_no_update BEFORE UPDATE ON ballot
BEGIN SELECT RAISE(ABORT, 'ballot box is append-only'); END;
CREATE TRIGGER ballot_no_delete BEFORE DELETE ON ballot
BEGIN SELECT RAISE(ABORT, 'ballot box is append-only'); END;
```

* Нет `user_id`, `ip`, `session_id`, `user_agent` — это проверяется тестом схемы.
* `ballot.seq` — внутренний порядок публикации, не связан с временем прихода.

### 2.3.4. audit_log.sqlite

```sql
CREATE TABLE entry (
  seq       INTEGER PRIMARY KEY AUTOINCREMENT,
  ts        TEXT NOT NULL,                   -- UTC ISO-8601
  kind      TEXT NOT NULL,
  poll_id   TEXT,
  payload   TEXT NOT NULL,                   -- canonical_json
  prev_hash BLOB NOT NULL,                   -- 32 байта
  hash      BLOB NOT NULL UNIQUE,            -- SHA-256(prev_hash || canonical_json(rec))
  sig       BLOB                             -- Ed25519 (опционально, для checkpoint)
);
CREATE INDEX ix_entry_poll ON entry(poll_id, seq);
CREATE INDEX ix_entry_kind ON entry(kind, seq);

CREATE TABLE checkpoint (
  seq          INTEGER PRIMARY KEY,          -- последний seq, накрытый точкой
  hash         BLOB NOT NULL,
  signature    BLOB NOT NULL,                -- Ed25519 сервера
  anchor_note  TEXT,                         -- где опубликовано (URL/канал), вручную
  created_at   TEXT NOT NULL
);

CREATE TRIGGER entry_no_update BEFORE UPDATE ON entry
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER entry_no_delete BEFORE DELETE ON entry
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
```

Виды записей (`kind`): `poll.create`, `poll.update` (diff + content_hash), `poll.key_commit`,
`poll.schedule`, `poll.start`, `ballot.batch`, `poll.close`, `poll.key_publish`,
`poll.results`, `admin.action`, `registry.purge` (только счётчик), `checkpoint`,
`asset.manifest`.

## 2.4. Криптосхема

### 2.4.1. Ключи и их происхождение

| Имя | Тип | Где | Назначение |
|-----|-----|-----|------------|
| `FV_SECRET_KEY` | 32 B | env | подпись CSRF-токенов (itsdangerous) |
| `FV_MASTER_KEY` | 32 B | env | HKDF → подключам |
| `k_totp_enc` | HKDF(master, "fairvote/totp/v1") | память | AES-256-GCM секрета TOTP |
| `k_ip_hash` | HKDF(master, "fairvote/ip/v1") | память | HMAC(IP) для счётчиков |
| `FV_VOTER_PEPPER_V1` | 32 B | env | Argon2id-salt для voter_key |
| `FV_ED25519_SIGN` | 64 B | env/файл вне web-root | подпись checkpoints |
| `FV_ED25519_ANCHOR` | 64 B | офлайн | ручные публичные «якоря» |
| ключ опроса (X25519) | — | **офлайн** | расшифровка бюллетеней |

Секреты читаются в `config.load_secrets()` из env, а на PA — из WSGI-файла
(вне web-root, `chmod 600`). В репозитории нет ни одного секрета; тест
`test_no_secrets_in_repo` ищет 32-байтовые base64-подобные строки в файлах.

### 2.4.2. voter_key (детерминированный, «один человек — один аккаунт»)

```
input:  fio (как в документе), dob='YYYY-MM-DD', doc_type, doc_series, doc_number
norm:   NFKC → casefold → ё→е, й не трогаем → удалить всё, кроме букв/цифр/пробела →
        сжать пробелы в один → trim; для doc_*: только [0-9A-Z], кириллические
        гомоглифы (АВЕКМНОРСТУХ) → латинские
string: f"{fio}\x1f{dob}\x1f{doc_type}\x1f{doc_series}\x1f{doc_number}"  (UTF-8)
key:    Argon2id(string, salt=FV_VOTER_PEPPER_V1, t=3, m=65536 KiB, p=1, len=32)
```

* Перед отправкой сервер показывает пользователю **нормализованный вид** и требует
  подтверждения — иначе «Ивановъ» и «Иванов» создают два аккаунта.
* UNIQUE-индекс `ux_user_voter_key` решает гонку.
* Исходные ФИО/ДР/документ **не сохраняются** — только `voter_key` и `district_id`.
* Ротация `FV_VOTER_PEPPER_V1` невозможна без потери свойства (детерминизм);
  версия хранится в `voter_key_version` для будущей миграции «старые ключи + новый pepper».
* `voter_key` удаляется: при удалении аккаунта и через `RETENTION_DAYS` после закрытия
  последнего опроса, где человек участвовал (`kinds=registry.purge` в журнале, только счётчик).

### 2.4.3. Меркл-дерево допущенных

```
leaf_i          = SHA-256(b"fairvote/elig/v1" || voter_key_i)
node            = SHA-256(b"\x01" || left || right)
odd node        = поднимается без изменений (RFC 6962-style, без дублирования)
листья в поддереве округа сортируются лексикографически (детерминизм)
district_root_d = merkle(leaf_i, i ∈ district d)
dleaf_d         = SHA-256(b"fairvote/dist/v1" || code_d || be64(count_d) || district_root_d)
root            = merkle(dleaf_d по возрастанию code_d)
```

Публикуется: `root`, `(code_d, count_d, district_root_d)` для каждого округа.
**Листья и пути включения не публикуются** (docs/01 T15). Персональный путь
выдаётся владельцу аккаунта после старта: `leaf_index + siblings + district_root + siblings_d`.

### 2.4.4. Секрет избирателя и ballot_id

* По умолчанию: 32 байта `crypto.getRandomValues` **в браузере**; отображается как
  Crockford Base32 (52 символа, группы по 4). Сервер секрет не видит никогда.
* По выбору: `Argon2id(passphrase, salt="fairvote/secret/v1"||poll_id, t=3, m=65536, len=32)`
  с проверкой стойкости (≥ 4 слов ≥ 20 символов, не из списка частых).
* `ballot_id = hex(HMAC-SHA256(secret, "fairvote/ballot/v1\x00" || poll_id))` — считается
  в браузере. Сервер получает `ballot_id` (он нужен как публичный псевдоним в ящике),
  но **связь с аккаунтом нигде не сохраняется** (docs/05 D-2).
  Связь `ballot_id ↔ secret` сервер проверить не может и, значит, не может проверить
  «правильность» секрета, предъявленного при принуждении.
* `client_nonce` — 16 случайных байт, идемпотентность повторной отправки.

### 2.4.5. Бюллетень

Открытый текст — канонический JSON фиксированной длины `ballot_plaintext_bytes`:

```json
{"v":1,"poll":"<uuid>","district":"RU-MOW-77-012",
 "contests":{"<contest_id>":"<option_id>", "...":"..."},
 "spoil":false,"pad":"<hex, добивает до точного размера>"}
```

* `sealed = crypto_box_seal(plaintext, poll_public_key)`; длина = `size + 48` — **одинакова
  у всех бюллетеней опроса** (утечки длины нет).
* Что сервер проверяет: размер, `size == ballot_plaintext_bytes`, `poll_id` опроса открыт,
  пользователь verified+допущен, не превышен лимит отправок. Содержимое — нет.
* Что проверяет публика: `district` внутри расшифрованного бюллетеня совпадает с
  `district_code`, который сервер записал в ящик при приёме (взят из реестра, а не из
  клиента) — иначе бюллетень помечается `DISTRICT_MISMATCH` и публикуется аномалия.
  Так подмена округа клиентом не проходит (docs/04 C5).

### 2.4.6. Счёт: один бюллетень на псевдоним, без переголосования

* Сервер не хранит `ballot_id` в реестре и не знает, кому он принадлежит. «Один человек —
  один голос» обеспечивается `participation(poll_id, user_id)` — PK не даёт вставить
  вторую запись, поэтому второй `POST /vote` получает `409`.
* `UNIQUE(poll_id, ballot_id)` в очереди и в ящике: чужой/продублированный псевдоним
  отвергается явной ошибкой, а не молчаливой подменой голоса (docs/05 D-2).
* Правило подсчёта тривиально: каждый `ballot_id` даёт ровно один голос; любой дубликат —
  аномалия `DUPLICATE_BALLOT` (в корректной БД невозможен, но `verify.py` проверяет).
* Переголосования нет: это осознанное отклонение от п. 5.3 ТЗ ради полного отсутствия
  связи «человек ↔ ballot_id» (цена — ослабленная защита от принуждения, docs/05 D-2).

### 2.4.7. Журнал

```
rec  = {"seq":n,"ts":"...","kind":"...","poll":"...","payload":{...}}
h_n  = SHA-256(h_{n-1} || canonical_json(rec)),  h_0 = 0x00 * 32
```

`canonical_json` — подмножество RFC 8785: ключи сортируются по code point, без пробелов,
`ensure_ascii=False`, UTF-8, числа только целые в пределах ±2^53, `true/false/null`,
никаких float и не-строковых ключей. Функция обязана совпадать в `fairvote.security.canonical`
и в `scripts/verify.py` (общий тест-вектор в `tests/vectors/canonical.json`).

Checkpoint: раз в сутки подписывается голова цепочки. Точное подписываемое сообщение
(важно для сторонних проверяющих):

```
message = canonical_json({"hash": "<head hex>", "seq": <seq>, "v": 1})
signature = Ed25519_sign(FV_ED25519_SIGN_KEY, message)
```

`seq` в сообщении не даёт перенести старую подпись на укороченную цепочку. Подпись и
хэш попадают в таблицу `checkpoint` и на страницу прозрачности; публикацию во внешнем
канале рекомендуется дублировать вручную (поле `anchor_note`). Если тот же `seq` позже
указывает на другой хэш, `create_checkpoint` падает (`AuditError`) — это и есть
обнаружение перезаписи истории.

Отсоединённая подпись файла (`.sig`, JSON `{"alg":"ed25519","public_key":"…","signature":"…"}`)
покрывает `SHA-256(файла)`, а не сам файл: так подпись проверяется потоково и совпадает
с формулировкой в docs/03 §3.10.

### 2.4.8. Публикация ключа и результат

1. Админ офлайн: `python scripts/poll_keygen.py --poll <uuid>` → `pub.json`, `priv.json`
   (при желании — `shares/*.json` по схеме Шамира).
2. До старта: `POST /admin/polls/<id>/key` с публичным ключом → журнал `poll.key_commit`
   с `fingerprint` (commitment).
3. После `ends_at`: `flask poll close <id>` → журнал `poll.close` (итоговый head ящика,
   агрегаты по округам). Если `key_publish_after IS NULL` — ключ можно публиковать сразу;
   если дата в будущем, сервер отказывает (`409`) до её наступления; затем админ вставляет
   приватный ключ → `poll.key_publish`; fingerprint сверяется с commitment, расхождение →
   `409` + публичный инцидент.
4. `flask poll tally <id>` → сервер расшифровывает (ключ уже публичен), считает итоги,
   проверяет `district_code`, публикует `poll.results` с хэшем и **версией/хэшем
   `verify.py`**, чтобы любой мог пересчитать независимо.

### 2.4.9. Почему связи «человек ↔ ballot_id» нет вообще

Решением D-2 `live_vote`/`superseded` из схемы удалены. Что это даёт и чего стоит:

* **Даёт:** даже полный дамп registry + env **во время** опроса не позволяет связать
  аккаунт с бюллетенем — такой связи не существует ни в одной таблице. Остаются только
  метаданные хостинга (IP/время, docs/01 T10) и порядок приёма (T11).
* **Стоит:** переголосование невозможно; принуждённый голос неизменяем (T7 без смягчения).
  Единственные смягчения — предупреждение перед отправкой, `k`-порог и отложенная
  публикация ключа (D-4).
* **Обратимость:** вернуть переголосование можно только вместе с возвратом `live_vote`
  (или со слепыми подписями). Это записано в docs/05 D-2/D-2-b, чтобы решение не
  «растворилось» в коде.

### 2.4.10. Интерфейс этапа 2 (только контракт, не реализация)

`fairvote/ballots/tokens.py`:

```python
class TokenIssuer(Protocol):
    def issue(self, *, poll_id: str, blinded: bytes) -> bytes: ...
class EligibilityOracle(Protocol):
    def is_eligible(self, token: bytes) -> bool: ...
```

MVP использует `NullTokenIssuer` (голос публикуется без токена). Если в конфиге выставлен
`VOTING_MODE='blind_token'`, приложение **отказывается стартовать** (`ImproperlyConfigured`),
пока не подключён настоящий issuer — никакой «полу-безопасной» имитации.

## 2.5. Жизненные циклы

### 2.5.1. Регистрация и верификация

```
registered ──request──▶ proof_submitted ──provider──▶ verified
      │                      │                    └─▶ rejected (можно подать заново, ≤3 раз)
      └──────────────────────┴──▶ suspended (по решению провайдера/оператора)
```

* Шаг 1: логин, пароль (Argon2id), округ (из списка), согласие на обработку ПДн, чекбокс
  «мне ≥ 18» (если требуется), метод верификации.
* Шаг 2: `DemoProvider` (только `DEMO_MODE`) — мгновенно; `ManualProvider` — платформа
  выдаёт одноразовый 8-символьный код, документ передаётся провайдеру **вне платформы**,
  оператор провайдера вносит решение CLI-командой по коду (docs/05 D-3). Файлы в FairVote
  не загружаются вообще.
* Шаг 3: TOTP-настройка (обязательна для admin, рекомендована для voter), 10 recovery-кодов.
* Повторная регистрация с тем же `voter_key` → UNIQUE violation → **тот же** ответ
  «регистрация принята, проверьте статус» (без oracle «этот человек уже есть»).

### 2.5.2. Старт опроса (ленивый и детерминированный)

Опрос становится `open` при первом обращении после `starts_at` (или scheduled task):

1. `write_tx(polls)`: если `status='scheduled' and now >= starts_at` → вычислить снапшот.
2. Снапшот: `SELECT ... FROM app_user WHERE status='verified' AND verify_decided_at <= starts_at
   AND district_id IN (округа опроса)` — **отсечка по `starts_at`**, а не по «сейчас»;
   поэтому ленивый запуск даёт тот же корень, что и пунктуальный.
3. `audit.append('poll.start', {root, counts, k, schedule, manifest_hash, ballot_bytes})`.
4. `UPDATE poll SET status='open', eligibility_root=..., started_committed_at=...`.
5. Если упало между 3 и 4 — повтор идемпотентен: запись `poll.start` уже есть → пропуск
   (проверка по `(poll_id, kind)`).
6. После старта: любые изменения контента невозможны (триггер + сервис), новые
   верификации на состав не влияют (отсечка по времени).

### 2.5.3. Голосование

```
браузер: GET /vote/<poll>            → HTML + конфиг опроса (JSON в <script type="application/json">)
         JS: сгенерировать секрет, ballot_id, plaintext, pad, sealed box
         POST /vote/<poll>  {ballot_id, nonce, ciphertext}
сервер:  1) write_tx(ballot_box): INSERT ballot_queue(confirmed=0, district из реестра)
         2) write_tx(registry):  INSERT participation(poll_id, user_id, voted_on)
         3) UPDATE ballot_queue SET confirmed=1
         4) ответ: 200 {ballot_id, status:'accepted'} — без подтверждения выбора
```

Порядок «сначала ящик, потом реестр» гарантирует, что принятый голос есть в ящике;
неподтверждённые строки очереди (`confirmed=0`, старше 24 ч) вычищаются.
Если шаг 2 упал (гонка за `participation`), клиент получает `409`, а строка очереди
остаётся `confirmed=0` и удаляется: голос не засчитывается, потому что избиратель не
получил подтверждения.

### 2.5.4. Пачки и задержки

Очередь сбрасывается **лениво** (нет фонового воркера на free-tier PA):

* триггеры: (а) накопилось ≥ `BATCH_MIN` (по умолчанию 8) неподтверждённых, или
  (б) самая старая ждёт ≥ `BATCH_MAX_DELAY` (по умолчанию 45 мин), или
  (в) наступил `ends_at` (финальный сброс всех);
* `commit_batch`: под `BEGIN IMMEDIATE` забрать пачку, **перемешать** (`secrets.SystemRandom`),
  вставить в `ballot` с `slot` = час приёма, посчитать Меркл-корень пачки по шифртекстам,
  `audit.append('ballot.batch', {size, root, slot})`, затем пометить очередь.
* Идемпотентность: `ballot_batch.audit_seq` + проверка, что пачка ещё не закоммичена.
* Ленивый сброс вызывается из middleware `after_request` с вероятностью 1/8 (дешёвая
  проверка «есть ли что сбрасывать» — один индексированный `SELECT`), плюс ежедневный
  scheduled task как страховка.

### 2.5.5. Закрытие и публикация

```
flask poll close <id>  (идемпотентно, только при now >= ends_at):
  1) commit_batch(final=True)
  2) audit.append('poll.close', {box_head, box_count, counts_by_district, key_publish_after})
  3) UPDATE poll SET status='closed', closed_at=now
  4) экспорт ballot_box.jsonl + audit.jsonl + .sig (публично)
```

Никаких `live_vote`/`superseded` при закрытии нет (их нет в схеме): ящик уже содержит
`ballot_id`, `district_code`, `slot`, `ct`, и публикуется целиком. Подмена округа
клиентом проверяется по `district_code` из ящика (§2.4.5).

### 2.5.6. Проверка избирателем

* До публикации ключа: `ballot_id` — единственный «чек». Форма `/verify` **считает
  хэш локально в браузере** и ищет `ballot_id` в скачанном JSONL (сервер не отвечает
  на вопрос «есть ли такой id» — иначе это oracle для принуждения).
* После закрытия: тот же поиск + сверка `district_code` из ящика с расшифрованным payload.

## 2.6. Ограничения PythonAnywhere и как они учтены

| Ограничение | Решение |
|-------------|---------|
| Несколько воркеров, нет общего state | Сессии, rate limit, lockout, очередь, «старт опроса», идемпотентность — в БД |
| Нельзя отключить access-логи | Нет секретов/логинов/`ballot_id` в URL; всё чувствительное — POST; предупреждение в UI; удаление PII из БД |
| Нет фоновых задач/always-on | Ленивый сброс пачек в `after_request`, ежедневный scheduled task, ленивый старт/закрытие |
| Лимит CPU | Argon2id m=46 MiB только на логине/регистрации; статика без JS; страницы прозрачности — статические HTML + пагинация по индексу; никакой тяжёлой криптографии на сервере (только при подсчёте итогов, офлайн-команда) |
| Исходящий трафик ограничен | Никаких внешних запросов; OpenTimestamps/зеркала — вручную, вне платформы |
| Free-tier scheduled task ≤ 1/сутки (уточнить) | Все ежедневные операции объединены в одну команду `flask daily` |
| Диск 512 MB | Ротация экспортов, TTL доказательств, JSONL сжаты gzip, старые пачки не дублируются |

### 2.6.1. Сессии

`DBSessionInterface(flask.sessions.SessionInterface)`:

* cookie `fv_sid` = base64url(32 случайных байта), `Secure; HttpOnly; SameSite=Strict; Path=/`;
* в БД — `SHA-256(token)`, так что дамп БД не даёт валидных cookie;
* idle TTL 20 мин (voter) / 10 мин (admin), абсолютный 8 ч / 4 ч; продление — не чаще
  одного `UPDATE` раз в 60 с (экономия записи), при простое — удаление;
* ротация id при входе, при переходе `password→full` (после TOTP), при смене пароля;
* смена пароля/восстановление → `DELETE FROM session WHERE user_id=?`;
* очистка просроченных — в `daily` + вероятностно в `before_request`.

### 2.6.2. CSRF

`Flask-WTF` `CSRFProtect` использует Flask-сессию (у нас серверную) → токен живёт в
`session.csrf_token`; дополнительно `before_request`-guard: для методов POST/PUT/PATCH/DELETE
требуется `Origin` (или `Referer`) с нашим хостом, либо `Sec-Fetch-Site: same-origin`;
иное → 403. Тест: POST без токена, с чужим Origin, с `Sec-Fetch-Site: cross-site`.

### 2.6.3. Rate limiting и lockout

`limits` не имеет SQLite-бэкенда (только memory/redis/memcached/mongodb), поэтому:

```python
class DBStorage(limits.storage.Storage):   # fairvote/security/ratelimit.py
    STORAGE_SCHEME = "fairvote-db"
    def incr(self, key, expiry, elastic_expiry=False, amount=1) -> int: ...
    def get(self, key) -> int: ...
    def get_expiry(self, key) -> float: ...
    def clear(self, key) -> None: ...
    def reset(self) -> int: ...
```

реализация — UPSERT в `rate_counter` под `BEGIN IMMEDIATE` (портируемо), ключи —
`HMAC(k_ip_hash, value)` (открытый IP не хранится), TTL окна ≤ 24 ч. Класс
регистрируется в публичном реестре схем `limits` (`SCHEMES["fairvote-db"] = DBStorage`),
а хранилище передаётся через `storage_options`, так что Flask-Limiter создаётся со
`storage_uri="fairvote-db://"` штатным путём. `key_func` берёт `REMOTE_ADDR`
(не `X-Forwarded-For`!) — доверять заголовку клиента нельзя.
Lockout аккаунта (независимо от IP) — `app_user.failed_login_count` + `locked_until`
с экспоненциальной задержкой (1, 2, 4, 8, 15 мин после 5 неудач).

Важно: лимит вешается на **POST**-обработчик, а не на страницу с формой, иначе
просмотры съедают бюджет попыток (так и случилось на первом прогоне: шестой GET
получал 429 раньше, чем заканчивались попытки).

### 2.6.4. Транзакции, гонки, идемпотентность

* Между файлами нет атомарности → паттерн «сначала запись, которую можно перепроверить,
  потом подтверждение» (см. §2.5.3) + детерминизм (старт опроса) + дедупликация по
  `(poll_id, kind, unique_key)` в журнале.
* Все пишущие транзакции — `BEGIN IMMEDIATE` (SQLite) через `db.write_tx()`, чтобы
  избежать `SQLITE_BUSY` при апгрейде блокировки.
* Уникальные индексы — последняя линия защиты от гонок (`participation` PK,
  `ux_user_voter_key`, `login`, `(poll, client_nonce)`, `(poll, ballot_id_hmac)`).
* Повторный POST голоса с тем же `nonce` → 200 идемпотентно.

### 2.6.5. Логирование

* Наш лог: только коды событий (`vote.accepted`, `login.fail`), `poll_id`, счётчики,
  `request_id`. Никогда: логин, `ballot_id`, секрет, IP, `voter_key`, содержимое форм.
* `redact.py` — logging.Filter, который режет сообщения по regex (IP, 32+ hex/base64,
  e-mail) и заменяет на `[redacted]`; тест `test_logs_have_no_pii` прогоняет сценарии
  и сканирует `caplog`.
* Ошибки: 500-страница без трейсбека, `request_id` для корреляции; трейсбек пишется
  в stderr PA (там нет PII из форм, потому что формы не логируются).

## 2.7. Безопасность приложения (конкретика)

| Тема | Решение |
|------|---------|
| Пароли | Argon2id `m=47104, t=1, p=1` (OWASP), `argon2-cffi`, `needs_rehash` при входе, длина 12..128, проверка на частые (встроенный список 2000 строк) |
| voter_key | Argon2id `m=65536, t=3, p=1` (однократно при регистрации) |
| Пароль-политика | минимум 12 символов, максимум 128, никаких «сложностных» правил (NIST SP 800-63B) |
| TOTP | `pyotp`, 6 цифр/30 с, окно ±1 шаг для дрейфа часов, одноразовость — по `totp_last_step` (шаг кода), ≤5 попыток/15 мин, после 5 неудач pending-сессия уничтожается |
| Recovery | 10 кодов, Argon2id-хэши, одноразовые, показ один раз, регенерация сбрасывает старые |
| CSP | `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'; object-src 'none'` |
| Заголовки | `Strict-Transport-Security: max-age=63072000; includeSubDomains`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `Cross-Origin-Opener-Policy: same-origin`, `Permissions-Policy` (пусто), `Cache-Control: no-store` для аутентифицированных |
| Cookies | `Secure, HttpOnly, SameSite=Strict`; префикс `__Host-` |
| Формы | `Flask-WTF` + серверная валидация, лимит длины полей, `max_content_length=6 MiB` |
| Контент админа | **Markdown-подмножество** (`fairvote/polls/content.py`): заголовки, абзацы, списки, `**bold**`, `*italic*`, `` `code` ``, ссылки, цитаты; сначала экранирование, потом ограниченный набор тегов, затем `nh3` с `ALLOWED_TAGS` (без `script/style/iframe/form/object`) и схемами `http/https/mailto`. `rel` ставит сам nh3. Полноценный Markdown не поддерживается осознанно (нет парсера в утверждённом стеке) |
| SQL | SQLAlchemy 2.x, только параметризованные выражения; никакой f-string-склейки (проверка ревью + тест на grep) |
| Загрузки | **Файлы не принимаются вообще** (docs/05 D-3): верификация — одноразовый код + решение провайдера. Нет парсеров недоверенных файлов, нет хранения сканов |
| Ошибки | одинаковая страница/сообщение для «нет такого логина» и «неверный пароль»; выравнивание времени dummy-hash |
| Заголовки кэша | публичные страницы — `public, max-age=60`; экспорт — `immutable` + ETag по хэшу |
| Админ | отдельный blueprint, `session.auth_level == 'admin'`, TOTP обязателен, все действия → журнал, нет доступа к registry/ballots |

## 2.8. Статика, JS и «доказуемость клиента»

* Всё отдаётся с нашего домена; сторонних запросов нет. CSP запрещает inline.
* `static/js/` — ES-модули без сборщика: `vote.js`, `sodium-loader.js`, `verify.js`,
  `receipt.js`. Это упрощает воспроизводимую сборку (файлы = то, что отдаётся).
* `vendor/libsodium-wrappers.min.js` — **вендорится** (D-1): версия пиннится, SHA-256 в
  `vendor.lock`, лицензия ISC рядом, хэш входит в `manifest.json`. Без неё в браузере нет
  `crypto_box_seal` (WebCrypto не умеет XSalsa20-Poly1305).
* `tools/build_assets.py`: читает все файлы статики, пишет `static/manifest.json`
  (`путь → sha256`), копирует в `static/dist/<hash>/...`; `manifest_hash` =
  SHA-256(canonical_json(manifest)). На старте опроса `manifest_hash` попадает в журнал
  (`poll.start`), на странице прозрачности публикуются хэши. Любой может скачать
  `view-source`-файлы и сверить.
* `verify`-страница работает **без JS** (поиск по JSONL через grep/`verify.py`), но
  удобный поиск — на JS.

## 2.9. Что публикуется и когда

| Объект | Когда | Где |
|--------|-------|-----|
| Опрос, кандидаты, расписание | после сохранения (черновик — только админу) | `/polls/<slug>` |
| `content_hash` + каждое изменение | при правке | журнал `poll.update` |
| `key_fingerprint` | до старта | журнал `poll.key_commit`, страница опроса |
| `eligibility_root`, счётчики по округам | при старте | журнал `poll.start`, `/transparency` |
| Число проголосовавших по округам | в реальном времени (с порогом k) | `/polls/<slug>` |
| Шифртексты (`ballot_box.jsonl`) | **только после закрытия** | `/transparency/export` |
| Приватный ключ | после `max(closed_at, key_publish_after)` | `/transparency/keys/<poll>` |
| Итоги | после публикации ключа | `/polls/<slug>/results` |
| Голова журнала | в реальном времени | `/transparency` |
| Checkpoint + подпись | ежедневно | `/transparency/checkpoints` |

## 2.10. CLI-команды (`flask ...`)

```
init-db                 создать схемы (DDL + триггеры), PRAGMA
admin-create            интерактивно создать админа (TOTP обязателен)
district-seed           засеять иерархию округов (демо: РФ + N округов)
demo-seed               синтетические избиратели/опросы (только DEMO_MODE)
verification-decide     решение провайдера по одноразовому коду (approve/reject)
poll-start-all          ленивый старт всех опросов, у которых наступило starts_at
poll-close-all          ленивый старт закрытия (после ends_at)
poll-close <id>         закрытие + публикация
poll-tally <id>         расшифровка (после публикации ключа) + итоги
verify-chain            проверка цепочки и подписей на сервере
export-public           JSONL + Ed25519-подпись (ежедневно)
backup-registry         AES-GCM-шифрованный дамп реестра (ключ вне платформы)
purge-retention         удаление voter_key и просроченных доказательств
daily                   poll-start-all + poll-close-all + export + backup + purge + cleanup
```

Scheduled task на PA: `daily` (одна задача, раз в сутки). Всё остальное — лениво из
запросов, чтобы не зависеть от частоты задач.

## 2.11. Деплой на PythonAnywhere

1. Код в `/home/<user>/fairvote` (не в `/var/www`), venv, `pip install -r requirements.txt`
   (пиннинг версий + hashes через `pip-compile --generate-hashes`).
2. WSGI-файл `/var/www/<user>_pythonanywhere_com_wsgi.py`:
   `os.environ[...] = '...'` для секретов **или** `open('/home/<user>/.fairvote/secrets.env')`
   с `chmod 600`; затем `from fairvote import create_app; application = create_app()`.
3. `instance/` (db, proofs, backups) — вне web-root, `chmod 700`.
4. TLS — сертификат PA, force HTTPS, HSTS.
5. Static — через PA «static files mapping» (`/static/` → `fairvote/web/static`), не через
   Flask (экономия CPU).
6. Один web app, несколько воркеров — допустимо (state в БД).
7. Бэкапы: `daily` пишет в `instance/backups/`, скачивание вручную; **ключ шифрования
   реестра хранится только офлайн** — иначе бэкап на PA бесполезен против PA.

## 2.12. Стратегия тестов (по модулям)

| Модуль | Ключевые тесты |
|--------|----------------|
| `security.canonical` | вектор-файл, стабильность, отказ на float/не-ASCII-ключах |
| `audit.chain` | цепочка, подмена записи, удаление, вставка в середину, конкурентная запись из 4 потоков, checkpoint-подпись |
| `registry.identity` | нормализация (регистр, ё/е, пробелы, гомоглифы), детерминизм, «один человек — один аккаунт» (UNIQUE), разные люди — разные ключи |
| `registry.provider` | статусы, переходы, одноразовый код, отказ демо-провайдера в проде, решение по коду нельзя повторить |
| `polls.service` | неизменяемость после старта (ORM + триггер), расписание, снапшот по `starts_at`, идемпотентный старт, `key_publish_after` |
| `polls.content` | XSS-векторы в Markdown (`<script>`, `onerror=`, `javascript:`, `data:`), сохранение безопасного HTML |
| `ballots.service` | приём, идемпотентность nonce, **второй POST → 409**, чужой/дублированный `ballot_id` → 409, `district_code` берётся из реестра, а не из запроса |
| `ballots.queue` | перемешивание, слот-час, фиксированная длина, корень пачки, ленивый сброс, гонка двух воркеров |
| `ballots.tally` | k-порог, mismatch округа, недействительные, дубликат `ballot_id` = аномалия |
| `web.auth` | вход, TOTP replay, lockout, enumeration (одинаковые ответы/время), recovery-код одноразовый, смена пароля отзывает сессии |
| `web.vote` | только verified+свой округ+открытый опрос; CSRF; rate limit; размер; фиксированная длина шифртекста |
| `web.admin` | доступа к registry нет (import-graph + поведение), правка после старта → 409, действия в журнале |
| `web.public` | прозрачность, `k`-скрытие, отсутствие утечек в HTML |
| `security.headers` | CSP/HSTS/nosniff на всех маршрутах, включая 404/500 |
| `security.ratelimit` | DBStorage incr/expiry, два «воркера» (два engine) видят один счётчик |
| `db.schema` | **нет связи ballot ↔ user**: в `ballot`/`ballot_queue` нет user/ip/session; в registry нет `live_vote`/`superseded` и нет колонок, указывающих на бюллетень (тест-обход схемы); `ballot` append-only; в registry нет ФИО/паспорта/адреса/файлов |
| `verify.py` | e2e: сгенерировать опрос, 50 голосов, закрыть, расшифровать, сверить итоги, подделать цепочку → падение |
| `logs` | нет PII/IP в логах по сценариям |

## 2.13. Порядок реализации (решения зафиксированы, docs/05)

| Этап | Модули | Результат |
|------|--------|-----------|
| M0 | скелет, конфиг, `db.py`, DDL, `canonical`, `crypto` | `flask init-db` работает, тесты крипто-примитивов |
| M1 | `audit.chain` + checkpoint + `verify.py` (только цепочка) | проверяемая цепочка |
| M2 | `registry` (идентичность, аккаунты, сессии, lockout) | регистрация/вход без UI-красоты |
| M3 | `polls` (контент, nh3, расписание, старт, eligibility/Меркл) | публичные страницы опросов |
| M4 | `ballots` (очередь, пачки, приём) + JS с libsodium (sealed box) | сквозной голос в демо |
| M5 | `web.auth`, `web.account`, `web.verify` (demo provider) | полный сценарий избирателя |
| M6 | `web.vote` (предупреждение о необратимости, чек), `tally`, страница проверки | проверяемый бюллетень |
| M7 | `web.admin` (без registry) + журнал действий | админ-флоу |
| M8 | `web.public` (прозрачность, «чему нельзя доверять», политика), i18n | публичная часть |
| M9 | экспорт, подписи, бэкапы, `daily`, retention, удаление аккаунта | эксплуатация |
| M10 | демо-сидер федеральной кампании, баннер, сквозные тесты, `verify.py` e2e | демо-стенд |
| M11 | документация: как развернуть, как провести опрос, шаблон политики ПДн | передача |

К каждому модулю: docstring-контракт, тесты (в т.ч. негативные), краткое обоснование
решений в `docs/decisions/NN-*.md`.
