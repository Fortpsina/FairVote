# Первый тестовый запуск на PythonAnywhere

Этот порядок предназначен для демонстрации с вымышленными участниками.
Оставшиеся ограничения тайны голосования описаны в
[проверке безопасности](security-review-2026-10-26.md). Не собирайте реальные
паспортные данные или реальные политические голоса на этом стенде.

Команды ниже выполняются в **Bash-консоли PythonAnywhere**, не в Windows PowerShell.
Windows-папку с `.venv`, локальными БД и временными файлами загружать не нужно.

## 1. Код и окружение

```bash
git clone https://github.com/Fortpsina/FairVote.git /home/$USER/FairVote
cd /home/$USER/FairVote
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip check
python tools/vendor_libsodium.py --verify
```

Если репозиторий на хостинге уже существует, вместо повторного клонирования
используйте `git pull --ff-only` в его папке. Python 3.12 должен быть доступен в
аккаунте; версию веб-приложения далее выбирайте такую же, как у окружения.
Окружение создаётся на хостинге заново.

## 2. Новые секреты вне репозитория

Следующий блок создаёт `~/.fairvote-demo/config.json` с четырьмя независимыми
случайными ключами. Он не печатает значения и **откажется перезаписывать** файл,
если тот уже существует. Сохраните защищённую резервную копию этого файла.

```bash
python - <<'PY'
import base64
import json
import os
import secrets
from pathlib import Path

private = Path.home() / ".fairvote-demo"
private.mkdir(mode=0o700, exist_ok=True)
private.chmod(0o700)
instance = private / "instance"
instance.mkdir(mode=0o700, exist_ok=True)
config = {
    "FV_DEMO_MODE": "1",
    "FV_TRUST_X_REAL_IP": "1",
    "FV_INSTANCE_DIR": str(instance),
}
for name in ("FV_SECRET_KEY", "FV_MASTER_KEY", "FV_VOTER_PEPPER_V1", "FV_ED25519_SIGN_KEY"):
    config[name] = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
target = private / "config.json"
descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    json.dump(config, stream)
print("Создан защищённый файл конфигурации; значения не выводятся.")
PY
```

Не используйте ключ из старой истории Git. Не помещайте `config.json`, БД,
резервные копии или приватные ключи опросов внутрь `fairvote/web/static`.
Демонстрационные данные не переносятся в будущий реальный экземпляр: для него
понадобятся отдельные ключи, хранилища и проверенный протокол.

## 3. Базы и вымышленные участники

В этой же консоли, из папки проекта с активированным `.venv`, выполните блок.
Он запускает реальные команды приложения `init-db` и `demo-seed`, затем просит
новый пароль администратора без отображения ввода. Это нужно сделать **до**
открытия сайта посетителям: пароль demo-admin в исходниках общеизвестен.
Сохраните выбранный пароль; включите TOTP при первом входе администратора.

```bash
python - <<'PY'
import json
import os
from getpass import getpass
from pathlib import Path

os.environ.update(json.loads((Path.home() / ".fairvote-demo/config.json").read_text()))
from fairvote import create_app
from fairvote.registry import service
from fairvote.security.passwords import validate_password

app = create_app()
runner = app.test_cli_runner()
for args in (["init-db"], ["demo-seed", "--voters-per-district", "2", "--votes-per-district", "0"]):
    result = runner.invoke(args=args)
    if result.exit_code:
        print(result.output)
        raise SystemExit(result.exit_code)

registry = app.extensions["fairvote.stores"]["registry"]
admin = service.find_by_login(registry, "admin")
password = getpass("Новый пароль администратора: ")
if password != getpass("Повторите пароль: "):
    raise SystemExit("Пароли не совпали. Повторите настройку до публикации сайта.")
validate_password(password, login="admin")
service.set_password(registry, admin.id, password)
print("Готово. Администратор: admin, пароль — выбранный вами.")
print("Тестовый избиратель: demo-012-00, пароль: demo-parol-2026.")
for store in app.extensions["fairvote.stores"].values():
    store.dispose()
PY
```

Если блок завершился ошибкой до смены пароля, не публикуйте стенд до успешного
повторного запуска. Тестовые избиратели намеренно используют известный пароль и
вымышленные личности. Административный аккаунт должен иметь другой пароль.

## 4. Web → Manual configuration

В разделе **Web** нажмите **Add a new web app**, выберите **Manual configuration**
и Python **3.12**. В поле Virtualenv укажите:

```text
/home/ВАШ_ЛОГИН/FairVote/.venv
```

В WSGI-файле, ссылка на который находится на странице Web, замените пример
приложения следующим кодом. `ВАШ_ЛОГИН` замените на логин PythonAnywhere.

```python
import json
import os
import sys
from pathlib import Path

project = Path("/home/ВАШ_ЛОГИН/FairVote")
sys.path.insert(0, str(project))
private = Path("/home/ВАШ_ЛОГИН/.fairvote-demo")
os.environ.update(json.loads((private / "config.json").read_text(encoding="utf-8")))

from fairvote import create_app
application = create_app()
```

`app.run()` и `flask run` в WSGI-файле не нужны. Переменные, заданные в консоли,
сами по себе не переносятся в веб-воркеры: WSGI загружает тот же файл отдельно.

## 5. Только правильный каталог статики

В **Static files** добавьте ровно такое сопоставление:

| URL | Directory |
|---|---|
| `/static/` | `/home/ВАШ_ЛОГИН/FairVote/fairvote/web/static` |

Не добавляйте сопоставление `/` с папкой проекта или домашней папкой.
Не публикуйте `.git`, `.fairvote-demo`, `instance`, `db`, `backups` или
`demo-keys`. Наличие `.gitignore` не ограничивает доступ через веб-сервер.

Включите **Force HTTPS**, затем нажмите **Reload**. Для собственного домена
сначала должен быть настроен сертификат. Если тариф предоставляет парольную
защиту всего сайта, её можно дополнительно включить для закрытого тестирования.

## 6. Проверка снаружи

Откройте `https://ВАШ_ЛОГИН.pythonanywhere.com/healthz`:
должно появиться `{"ok":true}`. Затем проверьте страницу входа и отправку
вымышленного голоса. Администратор сначала настраивает TOTP.

Следующие адреса должны завершаться ответом 404, без содержимого файлов:

```text
/.git/HEAD
/.env
/secrets.env
/fairvote/config.py
/instance/db/registry.sqlite
/.fairvote-demo/config.json
/static/../../config.py
```

В Bash можно проверить статус, сохраняя буквальный путь:

```bash
curl --path-as-is -I https://ВАШ_ЛОГИН.pythonanywhere.com/.git/HEAD
curl --path-as-is -I https://ВАШ_ЛОГИН.pythonanywhere.com/static/../../config.py
```

Редирект HTTP → HTTPS сам по себе нормален; конечный ответ для закрытого файла
должен быть 404. Для проверки реальной выдачи используйте также GET без `-I`.
Серверные настройки PythonAnywhere не охватываются локальными тестами Flask.

## 7. Ежедневное обслуживание

У новых бесплатных аккаунтов PythonAnywhere может не быть Scheduled Tasks:
с 15.01.2026 задача сохранена только для старых бесплатных аккаунтов.
Проверьте вкладку **Tasks** своего аккаунта. Для автоматического выполнения
`daily` нужен тариф с задачами либо отдельный согласованный способ запуска.

Создайте через Files файл `/home/ВАШ_ЛОГИН/.fairvote-demo/daily.py`:

```python
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path.home() / "FairVote"))
os.environ.update(json.loads((Path.home() / ".fairvote-demo/config.json").read_text()))
from fairvote import create_app

result = create_app().test_cli_runner().invoke(args=["daily"])
print(result.output)
raise SystemExit(result.exit_code)
```

Команда задания Tasks, если оно доступно:

```text
/home/ВАШ_ЛОГИН/FairVote/.venv/bin/python /home/ВАШ_ЛОГИН/.fairvote-demo/daily.py
```

Для первого теста можно запустить её вручную в Bash и проверить отчёт.
Без автоматического `daily` опросы не будут автоматически открываться/закрываться,
а очистка состояния и экспорт не будут выполняться по расписанию.
Бэкап в приведённой демо-конфигурации пропускается: `FV_BACKUP_KEY` намеренно не задан.
Готовый план резервного копирования реального сервиса требует отдельной настройки.

## Источники

- <https://help.pythonanywhere.com/pages/Flask/>
- <https://help.pythonanywhere.com/pages/EnvironmentVariables/>
- <https://help.pythonanywhere.com/pages/StaticFiles/>
- <https://help.pythonanywhere.com/pages/ForcingHTTPS>
- <https://blog.pythonanywhere.com/129/>
