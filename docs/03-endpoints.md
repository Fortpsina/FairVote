# FairVote — 3. Эндпоинты

Статус: проектное решение. Все пути ниже — под префиксом домена.
Нотация: `A` — требуется вход; `V` — требуется статус `verified`; `ADM` — требуется
`auth_level=admin` + TOTP; `—` — публично. CSRF обязателен для всех POST.
`RL` — примерные лимиты (значения в конфиге, хранилище — БД).

## 3.1. Общие правила

* Только `GET`/`HEAD` — идемпотентны, без побочных эффектов. Любая мутация — `POST`.
* Все ответы JSON — с `Cache-Control: no-store`; публичные HTML — `max-age=60`.
* Ошибки: `400` неверный запрос, `401` нет аутентификации, `403` нет прав/CSRF,
  `404` нет объекта, `409` конфликт состояния (переголосование, старт уже был),
  `413` слишком большой запрос, `429` лимит, `503` опрос не открыт/временно недоступен.
* Идентификаторы опросов — `uuid4 hex` (не последовательные), чтобы нельзя было
  перебором узнать количество/порядок.
* Никаких секретов в URL: `ballot_id`, логин, коды — только в теле POST.

## 3.2. Публичные страницы (без JS, кэшируемые)

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/` | — | 60/мин | Лендинг: что это, баннер DEMO_MODE, ближайшие опросы |
| GET | `/polls` | — | 60/мин | Список опросов (статус, расписание) |
| GET | `/polls/<slug>` | — | 60/мин | Карточка: описание (HTML), кандидаты, расписание, k, число допущенных по округам (после старта), счётчик проголосовавших (с порогом k), отпечаток ключа |
| GET | `/polls/<slug>/results` | — | 60/мин | Итоги; `404`/заглушка до публикации ключа (`max(closed_at, key_publish_after)`) |
| GET | `/transparency` | — | 60/мин | Голова журнала (`head_hash`, `seq`), последние записи, ссылки на экспорт/ключи/чекпоинты |
| GET | `/transparency/log` | — | 60/мин | Журнал, пагинация `?after=<seq>&limit=100` |
| GET | `/transparency/log/<seq>` | — | 120/мин | Запись + `prev_hash` + `hash` (для ручной проверки) |
| GET | `/transparency/polls/<poll_id>` | — | 60/мин | Commitments: root, счётчики, ключ, superseded, binding, итоги |
| GET | `/transparency/checkpoints` | — | 60/мин | Контрольные точки: seq, hash, подпись, `anchor_note` |
| GET | `/transparency/export` | — | 30/мин | Индекс экспортов (файлы + `.sig`) |
| GET | `/transparency/export/<poll_id>/ballots.jsonl` | — | 30/мин | Шифртексты (только после закрытия), `ETag`=sha256 |
| GET | `/transparency/export/<poll_id>/ballots.jsonl.sig` | — | 30/мин | Ed25519-подпись файла |
| GET | `/transparency/export/audit.jsonl` | — | 30/мин | Цепочка |
| GET | `/transparency/export/audit.jsonl.sig` | — | 30/мин | Подпись |
| GET | `/transparency/keys/<poll_id>` | — | 60/мин | Опубликованный приватный ключ (после закрытия), fingerprint |
| GET | `/transparency/verify.py` | — | 10/мин | Публичная копия скрипта проверки + sha256 (самопроверка по хэшу) |
| GET | `/how-it-works` | — | 60/мин | «Как устроено и чему нельзя доверять» (docs/01 §1.6) |
| GET | `/privacy` | — | 60/мин | Политика конфиденциальности (шаблон, спец. категория ПДн) |
| GET | `/terms` | — | 60/мин | Дисклеймер «неофициально, без юридической силы» |
| GET | `/accessibility` | — | 60/мин | Доступность (WCAG 2.1 AA-цель) |
| GET | `/healthz` | — | 120/мин | `{"ok":true}`; без версий/деталей |
| GET | `/robots.txt` | — | — | `Disallow: /admin/`, `/auth/`, `/vote/` |
| GET | `/manifest.json` | — | 60/мин | Хэши статики (из `static/manifest.json`) |

`/transparency/log` отдаётся с `Cache-Control: public, max-age=60` и `ETag`; пагинация
курсором (`seq`), без `OFFSET` — экономия CPU.

## 3.3. Аутентификация

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/auth/register` | — | 20/мин | Форма: логин, пароль, округ, чекбоксы; предпросмотр нормализации ФИО/ДР/документа |
| POST | `/auth/register` | — | 3/час (IP), 1/сутки (voter_key) | Создать аккаунт; ответ всегда «принято» (без oracle существования) |
| GET | `/auth/login` | — | 20/мин | Логин + пароль |
| POST | `/auth/login` | — | 10/15мин (IP), 5/15мин (аккаунт) | Проверка пароля → `auth_level=password`, редирект на TOTP |
| GET | `/auth/totp` | — | 20/мин | Ввод 6 цифр |
| POST | `/auth/totp` | — | 5/15мин | Проверка TOTP → `auth_level=full`, ротация sid |
| POST | `/auth/totp/recovery` | — | 5/15мин | Вход recovery-кодом (одноразовый) |
| POST | `/auth/logout` | A | 30/мин | Удалить серверную сессию |
| GET | `/auth/recover` | — | 10/мин | Форма восстановления |
| POST | `/auth/recover` | — | 5/15мин | recovery-код + новый пароль; отзыв всех сессий |
| GET | `/auth/totp/setup` | A | 10/мин | Показать секрет (один раз) + `otpauth://` URI + инструкции |
| POST | `/auth/totp/setup` | A | 5/15мин | Подтвердить код, включить TOTP |
| GET/POST | `/auth/recovery-codes` | A | 5/мин | Показать/перегенерировать 10 кодов (старые аннулируются) |

Особенности: `POST /auth/login` для несуществующего логина выполняет Argon2id над
dummy-hash и возвращает ту же страницу/тот же текст; время ответа выравнивается.
TOTP-секрет показывается один раз и не восстанавливается (только через recovery-коды).

## 3.4. Аккаунт избирателя

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/account` | A | 60/мин | Статус верификации, округ, список доступных опросов, отметки «голос принят» (без ballot_id на сервере) |
| GET/POST | `/account/password` | A | 5/мин | Смена пароля (текущий + новый, Argon2id); отзыв сессий |
| POST | `/account/delete` | A | 3/сутки | «Удалить аккаунт»: подтверждение паролем+TOTP, каскадное удаление, `registry.purge` в журнале |
| GET | `/account/sessions` | A | 30/мин | Активные сессии (создана, последняя активность), кнопка «завершить все» |
| POST | `/account/sessions/revoke` | A | 10/мин | Завершить все сессии |

## 3.5. Верификация

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/verification/` | A | 30/мин | Статус, история решений (метод/дата/код причины) |
| GET | `/verification/submit` | A | 20/мин | Выбор метода: DemoProvider (только DEMO_MODE) или ManualProvider |
| POST | `/verification/submit` | A | 5/сутки | Создать заявку: `district_code`, `method`, согласие. Ответ — одноразовый 8-символьный код (показывается один раз) |
| GET | `/verification/status` | A | 60/мин | JSON: статус + метка (используется для опроса без перезагрузки) |
| POST | `/verification/withdraw` | A | 3/сутки | Отозвать заявку до решения |

Файлы **не принимаются** (docs/05 D-3): нет загрузки, нет превью, нет обратных ссылок.
Пользователь передаёт документ провайдеру по каналу провайдера вместе с кодом; решение
вносится оператором провайдера через CLI (`flask verification-decide <код>`), а не админом
FairVote. Код одноразовый, TTL 14 дней, ≤ 5 попыток подбора на код.

## 3.6. Голосование

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/vote/<poll_id>` | A V | 60/мин | Бюллетень: конфиг опроса в `<script type="application/json">`, публичный ключ + fingerprint, инструкция про секрет, предупреждение о принуждении и о необратимости голоса |
| GET | `/vote/<poll_id>/config` | A V | 60/мин | JSON-конфиг для JS: `poll_id, ballot_plaintext_bytes, contests[{id,scope,options[]}], pubkey, fingerprint` |
| POST | `/vote/<poll_id>` | A V | 20/час | Приём шифртекста: `{ballot_id, nonce, ciphertext}` (base64) → `{status:"accepted", ballot_id}` |
| GET | `/vote/<poll_id>/receipt` | A V | 30/мин | Страница «сохраните секрет»; секрет приходит из JS (в localStorage/показан один раз), сервер его не знает |
| GET | `/vote/<poll_id>/status` | A V | 60/мин | «Голос принят» (без ballot_id: сервер его не связывает с аккаунтом) |

Правила `POST /vote`:
1. `status=open`/`starts_at <= now < ends_at`; иначе `503`.
2. `session.user_id` verified, `district_id ∈ poll_district`; иначе `403` (без деталей).
3. `len(ciphertext) == ballot_plaintext_bytes + 48`; `nonce` 16 байт; `ballot_id` — 64 hex.
4. `BEGIN IMMEDIATE` в ballot_box: `INSERT ballot_queue(ballot_id, district_code из реестра,
   confirmed=0)`; на `UNIQUE(poll,nonce)` — `200` идемпотентно; на `UNIQUE(poll,ballot_id)`
   — `409` (псевдоним уже занят, в т.ч. своей же первой отправкой).
5. `write_tx(registry)`: `INSERT participation(poll_id,user_id,voted_on=date)`; на PK —
   `409` «уже голосовали» (строка очереди остаётся неподтверждённой и будет вычищена).
6. `UPDATE ballot_queue SET confirmed=1`; с вероятностью 1/8 — `after_request` дергает
   `commit_batch`, если пора.
7. Ответ не содержит выбора, не подтверждает, что именно записано, и не выдаёт `seq`.

Переголосования **нет** (docs/05 D-2): второй `POST` → `409`, голос не меняется.
Связи `ballot_id ↔ user` сервер не хранит; `district_code` берётся из реестра
по сессии, а не из запроса (защита от подмены округа, docs/04 C5).

## 3.7. Проверка бюллетеня избирателем

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/verify` | — | 60/мин | Инструкция + локальный поиск: вставьте секрет → JS считает `ballot_id` и ищет в скачанном JSONL |
| GET | `/verify/local.js` | — | — | Скрипт проверки (тот же, что в статике) |

Принципиально: **нет серверного эндпоинта «есть ли такой ballot_id»** — иначе он стал бы
оракулом для принуждения («покажи, что твой голос в ящике»). Клиент скачивает публичный
JSONL (только после закрытия) и ищет локально. До закрытия избирателю доступен только
факт «принято» из `/vote/<poll_id>/status`.

## 3.8. Админ (без доступа к реестру и к промежуточным результатам)

| Метод | Путь | Доступ | RL | Назначение |
|-------|------|--------|----|-----------|
| GET | `/admin/` | ADM | 60/мин | Список опросов (черновики/запланированные/закрытые) |
| GET/POST | `/admin/polls/new` | ADM | 20/мин | Создать опрос (title, system, расписание, k, revote_policy) → журнал `poll.create` |
| GET/POST | `/admin/polls/<id>/edit` | ADM | 30/мин | Правка **только до старта**; иначе `409`; журнал `poll.update` с diff+hash |
| GET/POST | `/admin/polls/<id>/contests` | ADM | 30/мин | Контесты (общий список / по округам), варианты, «против всех» |
| GET/POST | `/admin/contests/<id>/options` | ADM | 30/мин | Кандидаты/партии: имя, биография (Markdown→nh3), ссылка |
| GET/POST | `/admin/polls/<id>/schedule` | ADM | 20/мин | `starts_at`, `ends_at` (UTC), проверки; журнал `poll.schedule` |
| GET/POST | `/admin/polls/<id>/districts` | ADM | 20/мин | Набор округов опроса (из справочника, без списка избирателей) |
| POST | `/admin/polls/<id>/key` | ADM | 10/мин | Прикрепить публичный ключ (base64/hex); журнал `poll.key_commit` с fingerprint; до старта |
| POST | `/admin/polls/<id>/start` | ADM | 5/мин | Ручной старт (обычно — ленивый): снапшот + root + `poll.start` |
| POST | `/admin/polls/<id>/close` | ADM | 5/мин | Закрытие (только `now >= ends_at`); журнал `poll.close` |
| POST | `/admin/polls/<id>/publish-key` | ADM | 5/мин | Вставить приватный ключ после закрытия **и** после `key_publish_after` (иначе `409`); сверка fingerprint → `poll.key_publish` |
| POST | `/admin/polls/<id>/tally` | ADM | 5/мин | Пересчёт итогов сервером (для страницы); `poll.results` |
| GET | `/admin/polls/<id>/preview` | ADM | 60/мин | Как выглядит публичная страница |
| GET | `/admin/actions` | ADM | 60/мин | Свои действия + ссылки на журнал |

Ограничения, проверяемые кодом и тестами:
* blueprint `web/admin.py` не импортирует `registry.models/service` (импорт-граф-тест);
* ни один админский ответ не содержит имён/логинов избирателей, `voter_key`, файлов;
* агрегаты (число допущенных/проголосовавших) доступны только после старта — и они
  публичны, т.е. админ не получает ничего эксклюзивного;
* после `status=open` любые `POST` правки → `409` (сервис) и `ABORT` (триггер БД).

## 3.9. Служебные (только локально/CLI, не HTTP)

`flask init-db`, `admin-create`, `district-seed`, `demo-seed`, `poll-start-all`,
`poll-close-all`, `poll-close <id>`, `poll-tally <id>`, `verify-chain`, `export-public`,
`backup-registry`, `purge-retention`, `daily` — см. docs/02 §2.10.
Отдельный офлайн-скрипт `scripts/poll_keygen.py` (никогда не запускается на сервере
в рабочем режиме; при `--on-server` отказывается).

## 3.10. Форматы данных

### 3.10.1. `POST /vote/<poll_id>`

```json
{"ballot_id": "9f2c…(64 hex)", "nonce": "<base64 16B>", "ciphertext": "<base64>"}
```
Ответ `200`: `{"status":"accepted","ballot_id":"9f2c…"}`;
`409` — `{"error":"rejected"}` (уже голосовали / псевдоним занят — причина не раскрывается);
`403` — `{"error":"not_eligible"}` (без указания причины).

### 3.10.2. `ballots.jsonl` (одна строка на бюллетень)

```json
{"v":1,"poll":"<uuid>","seq":17,"ballot_id":"9f2c…","district":"RU-MOW-77-012",
 "slot":"2026-03-14T09:00Z","batch":3,"ct":"<base64>","batch_root":"<hex>","audit_seq":142}
```

### 3.10.3. `audit.jsonl`

```json
{"seq":1,"ts":"2026-03-01T10:00:00Z","kind":"poll.create","poll":"<uuid>",
 "payload":{…},"prev_hash":"<hex>","hash":"<hex>"}
```

### 3.10.4. `keys/<poll_id>` (JSON)

```json
{"poll":"<uuid>","alg":"x25519-xsalsa20-poly1305","public_key":"<base64>",
 "fingerprint":"<hex>","private_key":"<base64>","published_at":"…",
 "commit_audit_seq":42,"publish_audit_seq":900,"verify_py_sha256":"<hex>"}
```

### 3.10.5. `scripts/verify.py` — что проверяет

```
$ python verify.py --audit audit.jsonl [--audit-sig audit.jsonl.sig] [--pubkey <hex>] \
                   [--ballots ballots.jsonl] [--ballots-sig ballots.jsonl.sig] \
                   [--poll poll.json] [--poll-key key.json] [--results results.json] [--json]
```

* `--audit` / `--audit-sig` — цепочка и её подпись;
* `--ballots` / `--ballots-sig` — выгрузка ящика и её подпись;
* `--poll` — опубликованный конфиг (округа, счётчики, контесты, опции, порог k);
* `--poll-key` — опубликованный ключ (JSON с `private_key` в hex);
* `--results` — ожидаемые итоги для сверки (код `TALLY_MISMATCH`);
* `--pubkey` — ключ Ed25519, полученный **независимо** (иначе `PUBKEY_MISMATCH`);
* `--json` — отчёт `{ok, audit:{records,head_hash,signature_checked}, ballots:{rows,batches,results}, problems[]}`;
* коды выхода: `0` — сходится, `1` — расхождения, `2` — ошибка использования/IO.

Проверки бюллетеней: баз64 → `crypto_box_seal_open` с опубликованным ключом; размер
открытого текста; `poll`/`district` внутри payload против строки ящика; допустимость
каждого пункта (контест применим к округу, опция из его списка); порог k; корни
Меркла батчей пересчитываются по шифртекстам.

Проверки цепочки: `hash_n == SHA256(prev_hash || canonical_json(rec))`, связность
`prev_hash`, непрерывность `seq`, полный набор полей (`EXTRA_FIELD`/`MISSING_FIELD`),
формат времени, словарь `kind`, подпись файла.

1. Цепочка: `hash_n == SHA256(hash_{n-1} || canonical_json(rec_without_hash))`, `prev_hash` связан.
2. Подписи: `.sig` над `SHA256(файла)` ключом `FV_ED25519_SIGN` (публичная часть публикуется).
3. `poll.start`: `root` и счётчики совпадают с `poll.json`; хэш конфигурации опроса = `content_hash`.
4. Ключ: `fingerprint == blake2b(pubkey)` и он равен commitment из `poll.key_commit`;
   `public_key` в `poll.json` совпадает.
5. Расшифровка: `crypto_box_seal_open` каждого `ct`; JSON валиден; `v==1`, `poll` совпадает;
   длина plaintext = `ballot_plaintext_bytes`; `district` ∈ округа опроса.
6. Округ: `district` внутри расшифрованного = `district` из строки ящика; иначе
   `DISTRICT_MISMATCH` (попытка записать голос в чужой округ).
7. Уникальность: каждый `ballot_id` встречается один раз; дубликат — `DUPLICATE_BALLOT`
   (переголосования нет, docs/05 D-2).
8. Порог: скрыть округа с `votes < k`; сверить с опубликованными итогами.
9. Счётчики: `sum(rows per district) == published counts` (в пределах `k`-маскировки).
10. Выход: `OK` либо список расхождений с кодами (`CHAIN_BREAK`, `SIG_INVALID`,
    `KEY_MISMATCH`, `DECRYPT_FAIL`, `DISTRICT_MISMATCH`, `DUPLICATE_BALLOT`, `TALLY_MISMATCH`, …), код 0/1.
    `--json` — машинный отчёт. Никакой сети, только stdlib + `PyNaCl`/`cryptography`.

## 3.11. Заголовки ответов

```
Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self';
  img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self';
  base-uri 'none'; frame-ancestors 'none'; object-src 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Permissions-Policy: accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()
Cache-Control: no-store        (аутентифицированные), public, max-age=60 (публичные)
```
