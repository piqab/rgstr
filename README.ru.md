[English](README.md) | **Русский**

# rgstr

Минималистичный OCI/Docker container registry, написанный на Go.

Совместим с `docker push` / `docker pull`, `crane`, `skopeo`, `containerd` и любым другим клиентом, поддерживающим [OCI Distribution Specification v1.1](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

---

## Возможности

- **Полная OCI/Docker совместимость** — поддержка Docker Registry HTTP API v2 и OCI Distribution Spec v1.1
- **Chunked uploads** — возобновляемые загрузки с проверкой `Content-Range`
- **Дедупликация blob'ов** — одни и те же слои хранятся на диске один раз вне зависимости от количества репозиториев
- **Cross-repo mount** — мгновенное монтирование blob'а из другого репозитория без передачи данных (при наличии права pull на исходный репозиторий)
- **Garbage collection** — периодическая очистка образов без тегов, их blob'ов и зависших сессий загрузки; не мешает идущему push
- **Bearer token auth** — JWT (HS256) по Docker auth specification, Basic auth на токен-эндпоинте
- **Кластер (HA)** — несколько процессов на S3 и PostgreSQL принимают push и pull; падение любого не останавливает реестр
- **Бэкапы в S3 или директорию** — по расписанию, на работающем реестре, с ротацией и восстановлением одной командой
- **LDAP, Active Directory и единый вход (OIDC)** — вход по паролю из каталога или через Keycloak, Authentik, Entra ID, Google; роли по группам
- **Публичные и приватные репозитории** — гибкий контроль доступа через glob-паттерны, анонимный pull без авторизации
- **Range downloads** — поддержка HTTP `Range` заголовка при скачивании слоёв
- **Kubernetes** — [оператор rgstroperator](https://github.com/piqab/rgstroperator): реестр, том, Ingress с TLS, метрики, бэкапы и кластер одним ресурсом
- **Без внешних зависимостей рантайма** — один статический бинарь; базы данных и сторонние сервисы нужны только для кластера (PostgreSQL и S3)
- **Безопасность от гонок** — `sync.RWMutex` + per-digest и per-upload локи; в кластере — общая блокировка в PostgreSQL

### Ограничения

- **Отказоустойчивость — в [режиме кластера](#кластер-ha)** (S3 и PostgreSQL).
  Без него rgstr — один процесс на каталоге данных (второй не запустится, см.
  [блокировку](#конфигурация)): перезапуск даёт короткий простой.
- **Внешние пользователи** — LDAP / Active Directory и OpenID Connect; SAML нет.
  Пользователи SSO выполняют `docker login` с CLI-секретом из админки.

---

## Быстрый старт

Готовые сборки публикуются автоматически через GitHub Actions:

- **бинарники** (linux/amd64, linux/arm64) — на странице [Releases](https://github.com/piqab/rgstr/releases): отдельными файлами `rgstr-linux-<arch>` и `mkpasswd-linux-<arch>` и архивом `rgstr-<версия>-linux-<arch>.tar.gz` с файлами для установки;
- **Docker-образ** (amd64 + arm64) — `ghcr.io/piqab/rgstr`.

| Тег образа | Что внутри |
|---|---|
| `latest` | последний релиз |
| `1.2.3`, `1.2` | конкретная версия |
| `main` | текущая ветка `main` (может быть нестабильной) |

### Вариант 1: бинарник

```bash
VERSION=v1.0.0          # нужная версия со страницы Releases
ARCH=amd64              # или arm64

curl -LO https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-${VERSION}-linux-${ARCH}.tar.gz
curl -LO https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-${VERSION}-linux-${ARCH}.tar.gz.sha256
sha256sum -c rgstr-${VERSION}-linux-${ARCH}.tar.gz.sha256

tar xzf rgstr-${VERSION}-linux-${ARCH}.tar.gz
cd rgstr-${VERSION}-linux-${ARCH}
```

В архиве: бинарники `rgstr` и `mkpasswd`, `.env.example`, `docker-compose.yml`, `deploy/` (systemd unit и скрипт установки) и этот README.

Если нужен только бинарник, без архива:

```bash
curl -L -o rgstr https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-linux-${ARCH}
chmod +x rgstr
```

**Быстрый запуск в текущей директории:**

```bash
RGSTR_STORAGE=./data ./rgstr
```

Конфигурация задаётся только переменными окружения (см. [Конфигурация](#конфигурация)); сам бинарник `.env` не читает. Чтобы взять настройки из файла:

```bash
cp .env.example .env
# отредактируйте .env
set -a; . ./.env; set +a
./rgstr
```

**Установка как systemd-сервис (production):**

```bash
sudo ./deploy/install.sh ./rgstr
sudo nano /etc/rgstr/env        # auth, пользователи, публичные репозитории
sudo systemctl restart rgstr
```

Подробнее — в разделе [Развёртывание на Linux](#развёртывание-на-linux).

### Вариант 2: Docker Compose

Нужны только два файла — `docker-compose.yml` и `.env`. Исходники клонировать и собирать не нужно:

```bash
mkdir rgstr && cd rgstr
curl -LO https://raw.githubusercontent.com/piqab/rgstr/main/docker-compose.yml
curl -L -o .env https://raw.githubusercontent.com/piqab/rgstr/main/.env.example
# (или возьмите оба файла из архива релиза)

# В .env задайте:
#   RGSTR_AUTH_ENABLED=true
#   RGSTR_AUTH_SECRET=<openssl rand -hex 32>
#   RGSTR_AUTH_REALM=http://<адрес сервера>:5000/v2/auth
#   RGSTR_ADMIN_PASSWORD=<временный пароль>

docker compose pull
docker compose up -d
docker compose logs -f
```

Откройте `http://<адрес сервера>:5000/ui`, войдите как `admin` с временным паролем и задайте постоянный — до этого `docker login` под `admin` не пройдёт. Остальных пользователей можно добавить в `RGSTR_USERS` (см. [Формат RGSTR_USERS](#формат-rgstr_users)).

Если пакет `ghcr.io/piqab/rgstr` приватный, перед `pull` войдите в GHCR с GitHub-токеном, у которого есть право `read:packages`:

```bash
echo <TOKEN> | docker login ghcr.io -u <github-user> --password-stdin
```

По умолчанию берётся образ `ghcr.io/piqab/rgstr:latest`. Зафиксировать версию — переменной `RGSTR_VERSION` (в `.env` или в окружении):

```bash
echo "RGSTR_VERSION=1.2.0" >> .env
docker compose pull && docker compose up -d
```

Обновление: `docker compose pull && docker compose up -d`.
Собрать образ локально из исходников (в клоне репозитория), не скачивая из GHCR:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

Веб-интерфейс поднимается вместе с реестром: `http://<адрес>:5000/ui`.

**Если `docker compose pull` / `up` пишет `unauthorized`** — Docker не может скачать образ: пакет в GHCR приватный (войдите через `docker login ghcr.io`, см. выше, или сделайте пакет публичным) либо образ этой версии ещё не опубликован (проверьте, что релизная сборка в GitHub Actions прошла, а тег `RGSTR_VERSION` существует).

`docker compose` передаёт все переменные из `.env` в контейнер. `RGSTR_STORAGE` всегда переопределяется на `/data` (Docker volume).

> **Внимание:** данные хранятся в named volume `rgstr-data` (управляется Docker), а не в локальной папке `./data`. Найти volume на хосте: `docker volume inspect rgstr-data`. Если нужна локальная папка — замените в `docker-compose.yml` `rgstr-data:/data` на `./data:/data` и удалите секцию `volumes: rgstr-data:`.

### Вариант 3: docker run

```bash
docker run -d \
  --name rgstr \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /srv/registry:/data \
  ghcr.io/piqab/rgstr:latest
```

### Вариант 4: Kubernetes

[rgstroperator](https://github.com/piqab/rgstroperator) разворачивает rgstr ресурсом `Registry`: том, секрет с временным паролем администратора, Ingress с TLS, метрики, бэкапы, LDAP/OIDC и кластер из нескольких реплик.

```bash
helm install rgstroperator oci://ghcr.io/piqab/charts/rgstroperator -n rgstroperator-system --create-namespace
```

### Проверка

Реестр слушает `http://localhost:5000`:

```bash
curl http://localhost:5000/v2/

docker pull alpine
docker tag alpine localhost:5000/myrepo/alpine:latest
docker push localhost:5000/myrepo/alpine:latest
docker pull localhost:5000/myrepo/alpine:latest
```

Один каталог данных — один процесс rgstr: пока rgstr работает, он держит блокировку `<RGSTR_STORAGE>/.rgstr.lock`, и второй процесс на тех же данных (второй контейнер на общем томе, NFS) не запустится. После падения процесса блокировку снимает ядро, перезапуск не блокируется.

Для доступа с других машин по HTTP см. [Настройка Docker daemon для HTTP реестра](#настройка-docker-daemon-для-http-реестра) или настройте [TLS](#tls).

### Из исходников

```bash
git clone https://github.com/piqab/rgstr
cd rgstr
make build
./rgstr
```

---

## Конфигурация

Все параметры задаются переменными окружения. Скопируйте `.env.example` в `.env` и отредактируйте:

```bash
cp .env.example .env
```

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RGSTR_ADDR` | `:5000` | Адрес и порт для прослушивания |
| `RGSTR_STORAGE` | `./data` | Путь к директории хранилища |
| `RGSTR_TLS_CERT` | — | Путь к TLS-сертификату (PEM) |
| `RGSTR_TLS_KEY` | — | Путь к TLS-ключу (PEM) |
| `RGSTR_AUTH_ENABLED` | `false` | Включить аутентификацию |
| `RGSTR_AUTH_SECRET` | `change-me-in-production` | Секрет для подписи JWT |
| `RGSTR_AUTH_REALM` | `http://localhost:5000/v2/auth` | URL токен-эндпоинта (возвращается в WWW-Authenticate) |
| `RGSTR_AUTH_SERVICE` | `rgstr` | Имя сервиса в токенах |
| `RGSTR_AUTH_ISSUER` | `rgstr` | Издатель токенов (поле `iss`) |
| `RGSTR_TOKEN_TTL` | `1h` | Время жизни токена `docker login` |
| `RGSTR_SESSION_TTL` | `12h` | Сколько живёт сессия веб-админки без активности; пока админка открыта, сессия продлевается |
| `RGSTR_USERS` | — | Список пользователей (см. ниже) |
| `RGSTR_ADMIN_USER` | `admin` | Имя первого администратора |
| `RGSTR_ADMIN_PASSWORD` | — | Временный пароль первого администратора, без хеша. Требует смены при первом входе в `/ui` (см. [Первый администратор](#первый-администратор)) |
| `RGSTR_ADMINS` | — | Пользователи, которым разрешено удаление (см. [Роли](#роли-пользователей)). Пусто — удалять могут все, кроме read-only |
| `RGSTR_READONLY_USERS` | — | Пользователи только с правом pull |
| `RGSTR_TRUSTED_PROXIES` | loopback и частные сети | Прокси, чьему `X-Forwarded-For` верить при записи IP клиента; `none` — не верить никому (см. [fail2ban](#fail2ban)) |
| `RGSTR_PUBLIC_REPOS` | — | Паттерны публичных репозиториев (см. ниже) |
| `RGSTR_METRICS_ENABLED` | `false` | Метрики Prometheus на `/metrics` (см. [Метрики](#метрики)) |
| `RGSTR_STORAGE_DRIVER` | `filesystem` | `filesystem` или `s3` (см. [Кластер](#кластер-ha)) |
| `RGSTR_STORAGE_S3_*` | — | Бакет для данных при `RGSTR_STORAGE_DRIVER=s3` |
| `RGSTR_DATABASE_URL` | — | PostgreSQL: включает режим кластера |
| `RGSTR_BACKUP_*` | — | Бэкапы по расписанию в S3 или директорию (см. [Бэкапы](#бэкапы)) |
| `RGSTR_LDAP_*` | — | Вход по паролю LDAP / Active Directory (см. [LDAP](#ldap-и-active-directory)) |
| `RGSTR_OIDC_*` | — | Вход в веб-админку через OpenID Connect (см. [Единый вход](#единый-вход-oidc)) |
| `RGSTR_GC_INTERVAL` | `1h` | Интервал запуска сборщика мусора |
| `RGSTR_UPLOAD_TTL` | `24h` | Через сколько удалять незавершённые загрузки. Это же льготный период GC: загруженное недавно не удаляется, даже если на него ещё не указывает тег |

### Формат RGSTR_USERS

```
RGSTR_USERS='alice:$2a$10$...,bob:$2a$10$...'
```

Каждая запись — `имя:bcrypt-хеш`. Для генерации хеша:

```bash
# Без Go — утилита есть в Docker-образе
docker run --rm --entrypoint /mkpasswd ghcr.io/piqab/rgstr alice mypassword
# Из архива релиза
./mkpasswd alice mypassword
# Из исходников
go run ./cmd/mkpasswd alice mypassword

# RGSTR_USERS='alice:$2a$10$...'
```

Значение должно быть в **одинарных** кавычках — так `$` в хеше остаётся как есть и в `.env` для docker compose, и в shell, и в `/etc/rgstr/env` для systemd. Без кавычек или в двойных кавычках docker compose подставит вместо `$2a`, `$10` переменные окружения, хеш обрежется и вход перестанет работать. Подходят и хеши `htpasswd -B` (`$2y$`).

---

## Публичные и приватные репозитории

По умолчанию при включённой аутентификации все репозитории приватные. Переменная `RGSTR_PUBLIC_REPOS` задаёт список паттернов, для которых анонимный `pull` разрешён без авторизации.

### Матрица доступа

|  | pull | push | delete |
|---|---|---|---|
| Аноним, публичный репо | ✓ | ✗ | ✗ |
| Аноним, приватный репо | ✗ | ✗ | ✗ |
| Пользователь из `RGSTR_READONLY_USERS` | ✓ | ✗ | ✗ |
| Обычный пользователь | ✓ | ✓ | ✗ (✓ если `RGSTR_ADMINS` пуст) |
| Пользователь из `RGSTR_ADMINS` | ✓ | ✓ | ✓ |
| Кто угодно при `AUTH_ENABLED=false` | ✓ | ✓ | ✓ |

### Паттерны

| Паттерн | Совпадает | Не совпадает |
|---|---|---|
| `alpine` | `alpine` | `myns/alpine` |
| `library/*` | `library/ubuntu`, `library/alpine` | `library/ns/ubuntu` |
| `public/**` | `public/myimage`, `public/ns/myimage` | `other/myimage` |
| `**/public/**` | `alex/public/alpine`, `public/alpine`, `a/b/public/img` | `alex/private/alpine` |
| `**` | любой репозиторий | — |

- `*` — любой одиночный сегмент пути (без слешей)
- `**` — ноль или более сегментов пути, включая слеши (может стоять в любом месте паттерна)
- `?` — любой одиночный символ

### Примеры

```bash
# Всё в namespace "public/" доступно без логина, остальное приватное
RGSTR_PUBLIC_REPOS=public/**

# Репозитории с сегментом "public" в любом месте пути
RGSTR_PUBLIC_REPOS=**/public/**

# Несколько паттернов через запятую
RGSTR_PUBLIC_REPOS=library/*,public/**,alpine

# Все репозитории публичные для pull (зеркало без ограничений)
RGSTR_PUBLIC_REPOS=**

# Все репозитории приватные (оставить пустым)
RGSTR_PUBLIC_REPOS=
```

### Поведение клиентов

```bash
# Публичный репо — pull без docker login
docker pull registry.example.com/public/myimage:latest

# Публичный репо — push требует авторизации
docker push registry.example.com/public/myimage:latest
# → unauthorized: authentication required

# Приватный репо — pull требует авторизации
docker pull registry.example.com/private/myimage:latest
# → unauthorized: authentication required

# После docker login — доступ по роли пользователя
docker login registry.example.com
docker pull registry.example.com/private/myimage:latest
docker push registry.example.com/public/myimage:latest
```

### Роли пользователей

| Роль | Как задать | Права |
|---|---|---|
| read-only | `RGSTR_READONLY_USERS=viewer,ci-reader` | pull |
| пользователь | есть в `RGSTR_USERS` | pull, push |
| администратор | `RGSTR_ADMINS=alice` | pull, push, удаление тегов и blob'ов, управление пользователями, политиками и GC в админке |

Пользователей с любой из этих ролей можно также создать в админке (страница «Users»), см. [Пользователи в админке](#пользователи-в-админке).

Первый администратор из `RGSTR_ADMIN_USER` всегда имеет права администратора, даже если его нет в `RGSTR_ADMINS`.

Если `RGSTR_ADMINS` не задан, удалять могут все пользователи из `RGSTR_USERS`, кроме read-only (как в версиях до 1.1.0). Права проверяются на каждый запрос: токен даёт ровно те действия, которые были запрошены в scope и разрешены ролью. Запрещённое действие возвращает `403 DENIED` при Basic-авторизации и `401` при Bearer-токене. Роль фиксируется в токене при выдаче, поэтому изменение ролей вступает в силу после перезапуска сервера и истечения ранее выданных токенов (`RGSTR_TOKEN_TTL`).

### Первый администратор

Чтобы не генерировать хеш для первого входа, задайте временный пароль прямо в env:

```
RGSTR_ADMIN_USER=admin          # по умолчанию admin
RGSTR_ADMIN_PASSWORD=changeme
```

- С временным паролем можно только войти в `/ui`: интерфейс сразу попросит задать новый пароль (не короче 8 символов). `docker login` с временным паролем отклоняется с сообщением `password change required: sign in to the web UI at /ui`.
- Новый пароль хранится в виде bcrypt-хеша в `<RGSTR_STORAGE>/users.json` (права `0600`) и переживает перезапуски. В Docker это том `/data`.
- После смены пароля учётная запись живёт в `users.json` и больше не зависит от env: `RGSTR_ADMIN_PASSWORD` можно убрать или оставить пустым — вход своим паролем продолжит работать. (До 1.5.0 удаление переменной удаляло учётную запись вместе с паролем.)
- **Сброс забытого пароля:** задайте в env другое значение `RGSTR_ADMIN_PASSWORD` и перезапустите. Сохранённый пароль удаляется, новый временный снова требует смены при входе.
- Если имя из `RGSTR_ADMIN_USER` есть и в `RGSTR_USERS`, действует временный пароль, а хеш из `RGSTR_USERS` для него игнорируется.

Сменить пароль через `/ui` может любой пользователь, не только администратор. Для пользователей из `RGSTR_USERS` действует то же правило сброса: если поменять хеш пользователя в `RGSTR_USERS`, сохранённый пароль сбрасывается. Если удалить пользователя из `RGSTR_USERS`, его сохранённый пароль тоже удаляется. Смена пароля завершает сессии веб-админки пользователя; токены `docker login` действуют до истечения `RGSTR_TOKEN_TTL`.

### Проекты

Проект объединяет репозитории с общим первым сегментом имени: проект `team` — это `team/app`, `team/db/postgres` и т. д. Проекты создаёт администратор реестра на странице «Projects».

- **Участники и роли в проекте:**

  | Роль | pull | push | delete | участники и webhooks проекта |
  |---|---|---|---|---|
  | Project admin | ✓ | ✓ | ✓ | ✓ |
  | Maintainer | ✓ | ✓ | ✓ | |
  | Developer | ✓ | ✓ | | |
  | Guest | ✓ | | | |

- Внутри проекта доступ есть только у участников и администраторов реестра; глобальная роль пользователя («User», «Read-only») здесь не действует. Посторонние не видят репозитории проекта ни в `/v2/_catalog`, ни в админке.
- **Публичный проект** — pull без входа для всех (как `RGSTR_PUBLIC_REPOS`, но настраивается в админке).
- Репозитории вне проектов работают по глобальным ролям, как раньше.
- **Квота** на хранение (задаёт администратор реестра): считается по уникальным слоям всех образов проекта, на которые указывают теги. Push манифеста, который вывел бы проект за квоту, отклоняется (`denied: quota exceeded: project team would use 3.3 MiB of 2.0 MiB`); push без новых данных (новый тег на уже загруженный образ) проходит всегда. Занятое место и квота видны в списке проектов. Слои, загруженные без манифеста, в квоту не входят — их удаляет GC.
- Удалить можно только пустой проект — сначала удалите его репозитории.
- Проекты хранятся в `<RGSTR_STORAGE>/meta.json`.

### Robot-аккаунты

Для CI и автоматизации администратор создаёт robot-аккаунты на странице «Robots»:

- имя вида `robot$ci`, вместо пароля — сгенерированный секрет. Секрет показывается один раз, хранится только его хеш; при утечке его можно перевыпустить (старый сразу перестаёт работать);
- права перечисляются явно: проект (или «все репозитории») и действия pull/push/delete. Робот с правом на конкретный проект не имеет доступа к репозиториям вне проектов;
- срок действия (30/90/180/365 дней или бессрочно), отключение. Отключённый, истёкший или удалённый робот теряет доступ сразу;
- робот работает только через `docker login`, в веб-админку войти не может.

```bash
# имя в одинарных кавычках — в нём есть «$»
echo "$ROBOT_SECRET" | docker login registry.example.com -u 'robot$ci' --password-stdin
```

Роботы хранятся в `<RGSTR_STORAGE>/meta.json`.

### Webhooks

На странице «Webhooks» настраиваются HTTP-уведомления о событиях: push, pull, удаление, превышение квоты проекта.

- **Область:** все репозитории (только администратор реестра) или один проект (администратор реестра или админ проекта).
- **Формат:** JSON в стиле Harbor (`{"type":"PUSH_ARTIFACT","operator":…,"event_data":{"resources":[{"digest","tag","resource_url"}],"repository":{…}}}`) или Slack-совместимый `{"text": "alice pushed …"}` — его принимают входящие webhooks Slack и Mattermost.
- Необязательный заголовок `Authorization` (в админке не показывается после сохранения), отключение проверки TLS-сертификата.
- Отправка в фоне, до 3 попыток при ошибке; последние 20 отправок каждого webhook видны в админке (хранятся в памяти до перезапуска). Кнопка «Send test» отправляет тестовое событие.
- Адрес реестра в ссылках на образы берётся из `RGSTR_AUTH_REALM`.

Учтите: webhook заставляет сервер реестра отправлять запросы на указанный URL, в том числе во внутреннюю сеть. Права на создание webhooks есть только у администраторов реестра и админов проектов.

### Пользователи в админке

На странице «Users» администратор может:

- создать пользователя с ролью «Administrator», «User» или «Read-only» и паролем (кнопка «Generate» придумывает случайный). По умолчанию пароль временный: при первом входе в `/ui` пользователь задаёт свой, а до этого `docker login` с временным паролем не работает. Логин и пароль показываются один раз — передайте их пользователю;
- изменить роль и удалить созданного в админке пользователя. Удалённый пользователь теряет доступ сразу, даже с ещё действующим токеном;
- сбросить пароль любому пользователю, в том числе из `RGSTR_USERS`.

Такие пользователи хранятся в `<RGSTR_STORAGE>/users.json`. Пользователи из `RGSTR_USERS` и первый администратор показываются в списке, но их роль и наличие задаются в env. Если в env появится пользователь с тем же именем, что и созданный в админке, действует env. Нельзя удалить себя или изменить свою роль — чтобы случайно не остаться без администратора.

Для пользователей, созданных в админке, правило «если `RGSTR_ADMINS` пуст, удалять могут все» не действует: их права определяет только роль.

### Сброс пароля администратора

Способ зависит от того, где задан администратор. Колонка «Source» на странице «Users» показывает это: `first admin`, `env` или `created here`.

**Если есть другой администратор** — проще всего: «Users» → «Reset password» у нужного пользователя. Можно сразу отметить «Require a password change at the first sign-in».

**Первый администратор (`RGSTR_ADMIN_USER` / `RGSTR_ADMIN_PASSWORD`).** Задайте новый временный пароль в env и перезапустите — сохранённый пароль удалится:

```bash
# Docker Compose: отредактируйте .env
RGSTR_ADMIN_PASSWORD=new-temporary-password
docker compose up -d          # именно up -d: restart не перечитывает .env

# systemd: отредактируйте /etc/rgstr/env
sudo systemctl restart rgstr
```

Войдите в `/ui` как `admin` с этим паролем — админка попросит задать постоянный. Если потом снова вернуть в env старое значение, забытый пароль не восстановится.

**Администратор из `RGSTR_USERS`.** Сгенерируйте новый хеш и замените его в `RGSTR_USERS` — пароль, сохранённый в админке, сбросится, и снова будет действовать хеш из env:

```bash
docker run --rm --entrypoint /mkpasswd ghcr.io/piqab/rgstr alice new-password
# RGSTR_USERS='alice:$2a$10$...'  → заменить запись alice, затем docker compose up -d / systemctl restart rgstr
```

**Администратор, созданный в админке, и других администраторов нет.** Временно включите первого администратора с отдельным именем, войдите им и сбросьте пароль на странице «Users»:

```bash
# .env или /etc/rgstr/env
RGSTR_ADMIN_USER=recovery
RGSTR_ADMIN_PASSWORD=temporary-recovery-password
docker compose up -d   # или sudo systemctl restart rgstr
```

1. Войдите в `/ui` как `recovery`, задайте ему постоянный пароль (админка попросит).
2. «Users» → «Reset password» у забывшего пароль администратора, с галочкой «Require a password change at the first sign-in».
3. Уберите `RGSTR_ADMIN_USER` и `RGSTR_ADMIN_PASSWORD` из env, выполните `docker compose up -d` / `systemctl restart rgstr`, войдите восстановленным администратором и удалите `recovery` на странице «Users».

Используйте для восстановления имя, которого нет среди пользователей: если имя совпадёт с пользователем, созданным в админке, env «перекроет» его, и этот пользователь будет удалён из `users.json`.

**Если доступа к env нет, но есть к данным.** Пароли пользователей хранятся в `<RGSTR_STORAGE>/users.json` (bcrypt). Удаление записи пользователя из этого файла при остановленном реестре: для пользователя из env вернёт пароль из env, пользователя, созданного в админке, удалит целиком.

**Если после обновления «слетела» сессия и не подходит пароль.** Проверьте, не заменили ли вы `.env` (например, свежим `.env.example`):
- изменился `RGSTR_AUTH_SECRET` — все сессии и `docker login` выходят, пароли при этом не меняются;
- изменилось значение `RGSTR_ADMIN_PASSWORD` — пароль первого администратора сбрасывается на это значение (так задумано, это способ сброса): войдите им, админка попросит задать новый;
- в rgstr до 1.5.0 пустой или удалённый `RGSTR_ADMIN_PASSWORD` удалял первого администратора — задайте временный пароль, как описано выше;
- изменился том или путь данных (`RGSTR_STORAGE`, имя volume, имя проекта compose) — реестр запустился с пустыми данными: исчезнут и образы, и пароли.

После сброса или смены пароля сессии веб-админки этого пользователя завершаются сразу; `docker login`, выполненные со старым паролем, действуют, пока не истечёт их токен (`RGSTR_TOKEN_TTL`, по умолчанию 1 час). Каждый сброс записывается в журнал действий.

---

## Аутентификация

По умолчанию реестр открытый (`RGSTR_AUTH_ENABLED=false`). Для включения auth:

```bash
# 1. Сгенерировать хеши паролей
./mkpasswd alice secret1
./mkpasswd bob   secret2

# 2. Запустить с auth (хеши — в одинарных кавычках)
RGSTR_AUTH_ENABLED=true \
RGSTR_AUTH_SECRET=my-signing-secret \
RGSTR_USERS='alice:$2a$10$...,bob:$2a$10$...' \
./rgstr
```

Docker-клиент автоматически обнаружит токен-эндпоинт через `WWW-Authenticate` заголовок и запросит токен при `docker login`:

```bash
docker login localhost:5000
# Username: alice
# Password: secret1
```

### Настройка Docker daemon для HTTP реестра

Если реестр работает без TLS, добавьте в `/etc/docker/daemon.json`:

```json
{
  "insecure-registries": ["myserver:5000"]
}
```

И перезапустите Docker: `sudo systemctl restart docker`.

---

## LDAP, Active Directory и единый вход

Помимо локальных пользователей rgstr принимает пользователей каталога. Они
появляются в списке пользователей при первом входе (источник «LDAP» или «SSO»),
могут быть участниками проектов, а их роль берётся из групп каталога.

Правила для обоих способов:

- **Локальные пользователи главнее.** Пользователь из env или созданный в админке
  входит только со своим паролем; пользователь каталога с тем же именем не
  войдёт. Первый администратор поэтому работает, даже если каталог недоступен.
- **Имена хранятся в нижнем регистре**: `Alice` и `alice` — один пользователь.
- **Роли по группам.** Если заданы `*_ADMIN_GROUPS` или `*_READONLY_GROUPS`,
  роль при каждом входе берётся из групп: администратор, только чтение, иначе
  `*_DEFAULT_ROLE`. Если не заданы — роль меняется в админке и сохраняется.
- **Ограничение доступа.** `*_ALLOWED_GROUPS` пускает только участников этих
  групп (и групп ролей).
- Группа сравнивается без учёта регистра по полному имени/DN или по `CN` из DN:
  `registry-admins` совпадает с `CN=registry-admins,OU=Groups,DC=corp`.
- Пароль такого пользователя хранится в каталоге: сменить или сбросить его в
  rgstr нельзя. Удаление в админке убирает пользователя и его сессии; при
  следующем входе он появится снова — закрывайте доступ в каталоге или группами.

### LDAP и Active Directory

docker login и вход в веб-админку принимают пароль из каталога. rgstr ищет
запись пользователя (от имени служебной учётной записи или анонимно), затем
проверяет пароль, подключаясь от имени найденной записи. Удачная проверка
кешируется на минуту.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RGSTR_LDAP_URL` | — | `ldap://host:389` или `ldaps://host:636`. Пусто — LDAP выключен |
| `RGSTR_LDAP_STARTTLS` | `false` | StartTLS поверх `ldap://` |
| `RGSTR_LDAP_CA_FILE` | системные | CA-сертификат сервера (PEM) |
| `RGSTR_LDAP_INSECURE_SKIP_VERIFY` | `false` | Не проверять сертификат (только для тестов) |
| `RGSTR_LDAP_BIND_DN`, `RGSTR_LDAP_BIND_PASSWORD` | анонимно | Служебная учётная запись для поиска |
| `RGSTR_LDAP_BASE_DN` | — | Где искать пользователей |
| `RGSTR_LDAP_USER_FILTER` | `(&(objectClass=person)(uid=%s))` | Фильтр поиска; `%s` — имя (экранируется) |
| `RGSTR_LDAP_GROUP_ATTR` | `memberOf` | Атрибут записи пользователя со списком групп |
| `RGSTR_LDAP_GROUP_FILTER` | — | Поиск групп для каталогов без `memberOf`; `%s` — DN пользователя |
| `RGSTR_LDAP_GROUP_BASE_DN` | `RGSTR_LDAP_BASE_DN` | Где искать группы |
| `RGSTR_LDAP_ADMIN_GROUPS`, `RGSTR_LDAP_READONLY_GROUPS` | — | Группы ролей (через запятую) |
| `RGSTR_LDAP_ALLOWED_GROUPS` | — | Кого вообще пускать |
| `RGSTR_LDAP_DEFAULT_ROLE` | `user` | Роль без групп ролей: `user`, `readonly`, `admin` |

Active Directory:

```bash
RGSTR_LDAP_URL=ldaps://dc1.corp.example:636
RGSTR_LDAP_BIND_DN='CN=svc-rgstr,OU=Service,DC=corp,DC=example'
RGSTR_LDAP_BIND_PASSWORD=...
RGSTR_LDAP_BASE_DN='DC=corp,DC=example'
RGSTR_LDAP_USER_FILTER='(&(objectClass=user)(sAMAccountName=%s))'
RGSTR_LDAP_ADMIN_GROUPS=Registry-Admins
RGSTR_LDAP_ALLOWED_GROUPS=Developers
```

OpenLDAP без оверлея `memberOf`:

```bash
RGSTR_LDAP_URL=ldap://ldap.example:389
RGSTR_LDAP_STARTTLS=true
RGSTR_LDAP_BASE_DN='ou=people,dc=example,dc=org'
RGSTR_LDAP_GROUP_BASE_DN='ou=groups,dc=example,dc=org'
RGSTR_LDAP_GROUP_FILTER='(&(objectClass=groupOfNames)(member=%s))'
RGSTR_LDAP_ADMIN_GROUPS=registry-admins
```

### Единый вход (OIDC)

На странице входа появляется кнопка «Войти через …», которая ведёт к
провайдеру OpenID Connect (Keycloak, Authentik, Dex, Entra ID, Google, GitLab).
Поток — authorization code с PKCE; подпись ID-токена проверяется по ключам
провайдера.

Docker не умеет входить через браузер, поэтому пользователь SSO создаёт в
админке **CLI-секрет** (кнопка в шапке) и использует его как пароль:

```bash
echo "$CLI_SECRET" | docker login registry.example.com -u dave --password-stdin
```

Новый секрет отменяет предыдущий. Пользователи LDAP тоже могут сделать
CLI-секрет, чтобы не хранить пароль каталога в CI.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RGSTR_OIDC_ISSUER` | — | URL провайдера (issuer). Пусто — OIDC выключен |
| `RGSTR_OIDC_CLIENT_ID`, `RGSTR_OIDC_CLIENT_SECRET` | — | Клиент у провайдера; без секрета — публичный клиент с PKCE |
| `RGSTR_OIDC_REDIRECT_URL` | из `RGSTR_AUTH_REALM` | Адрес возврата: `https://<реестр>/ui/oidc/callback` |
| `RGSTR_OIDC_SCOPES` | `openid profile email` | Запрашиваемые scope (добавьте `groups`, если провайдер так отдаёт группы) |
| `RGSTR_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim с именем (без него — `email`) |
| `RGSTR_OIDC_GROUPS_CLAIM` | `groups` | Claim с группами; если его нет в ID-токене, берётся из userinfo |
| `RGSTR_OIDC_NAME` | `SSO` | Название на кнопке входа |
| `RGSTR_OIDC_ADMIN_GROUPS`, `RGSTR_OIDC_READONLY_GROUPS`, `RGSTR_OIDC_ALLOWED_GROUPS`, `RGSTR_OIDC_DEFAULT_ROLE` | | Как у LDAP |

Имя пользователя берётся из claim и связывает вход с его проектами, поэтому
выбирайте claim, который пользователь не может поменять сам: в Keycloak
запретите редактирование имени (*Edit username* выключен), у Google и Entra ID
используйте `email` (неподтверждённый e-mail rgstr не примет) или
`RGSTR_OIDC_USERNAME_CLAIM=sub`.

Keycloak: создайте клиента с типом *OpenID Connect*, включите *Client
authentication*, в *Valid redirect URIs* укажите
`https://registry.example.com/ui/oidc/callback`, добавьте маппер *Group
Membership* с именем claim `groups` (выключите *Full group path*).

```bash
RGSTR_OIDC_ISSUER=https://sso.example.com/realms/main
RGSTR_OIDC_CLIENT_ID=rgstr
RGSTR_OIDC_CLIENT_SECRET=...
RGSTR_OIDC_NAME=Keycloak
RGSTR_OIDC_ADMIN_GROUPS=registry-admins
```

## Кластер (HA)

Несколько процессов rgstr работают как один реестр: любой принимает push и
pull, падение или обновление одного не останавливает ни push, ни pull.

```
          балансировщик / Kubernetes Service
        ┌──────────┼──────────┐
     rgstr-1    rgstr-2    rgstr-N
        └─────┬────┴─────┬────┘
        PostgreSQL       S3
```

- **S3** хранит данные: blob'ы, манифесты, теги, незавершённые загрузки.
  Загрузку частями (PATCH) может продолжить любой процесс: каждая часть и
  состояние sha256 сохраняются сразу.
- **PostgreSQL** хранит общее состояние: пользователей, проекты, роботов,
  политики, webhooks, настройки, сессии веб-админки, журнал аудита, счётчики
  pull. Изменения сразу видны всем процессам (`LISTEN/NOTIFY`).
- **Сборка мусора** запускается в одном процессе на интервал и держит общую
  блокировку: push, который делает данные достижимыми, её ждёт, так что GC
  никогда не удалит слой образа, который сейчас пушат.
- **Без состояния на диске:** процессы можно добавлять, убирать и
  перезапускать в любой момент.

Проверено нагрузочным тестом (`test/ha`): три процесса под постоянными push и
pull, каждые 1,5–3 с один из них убивается `kill -9` и перезапускается; все
образы остаются целыми, ни один pull не отдаёт неверных данных.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RGSTR_DATABASE_URL` | — | `postgres://user:pass@host:5432/rgstr?sslmode=require`; таблицы создаются сами |
| `RGSTR_STORAGE_DRIVER` | `filesystem` (`s3`, если задан бакет) | Где хранить данные |
| `RGSTR_STORAGE_S3_BUCKET` | — | Бакет (создайте заранее) |
| `RGSTR_STORAGE_S3_PREFIX` | — | Префикс ключей, например `prod/` |
| `RGSTR_STORAGE_S3_ENDPOINT` | AWS для региона | `https://storage.yandexcloud.net`, `http://minio:9000` … |
| `RGSTR_STORAGE_S3_REGION` | `us-east-1` | Регион |
| `RGSTR_STORAGE_S3_ACCESS_KEY`, `RGSTR_STORAGE_S3_SECRET_KEY` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Ключи |
| `RGSTR_STORAGE_S3_PATH_STYLE` | `true` с endpoint | Адресация `host/бакет/ключ` |
| `RGSTR_STORAGE_S3_REDIRECT` | `false` | Отдавать слои редиректом на presigned URL: клиенты качают прямо из S3, мимо rgstr. Endpoint должен быть доступен клиентам |

Все процессы получают одинаковое окружение, включая `RGSTR_AUTH_SECRET`:
токены, выданные одним, принимаются всеми. `/healthz` — живость процесса,
`/readyz` — готовность (доступны база и хранилище); балансировщику нужен
`/readyz`.

Каталог данных на общем томе (NFS, CephFS) вместо S3 тоже работает:
`RGSTR_STORAGE_DRIVER=filesystem` с `RGSTR_DATABASE_URL`.

**Переход с одиночного режима.** Остановите rgstr и перенесите данные:

```bash
RGSTR_DATABASE_URL=postgres://… RGSTR_STORAGE_S3_BUCKET=registry RGSTR_STORAGE_S3_ENDPOINT=… \
RGSTR_STORAGE_S3_ACCESS_KEY=… RGSTR_STORAGE_S3_SECRET_KEY=… \
  rgstr migrate -from /data
```

Копируются blob'ы, манифесты, теги, пользователи, проекты, настройки, счётчики
и журнал; повторный запуск докопирует недостающее. Время пуша тегов после
переноса — время переноса (S3 не хранит исходное), это влияет на политики
хранения по возрасту.

**Бэкапы кластера** — средствами хранилищ: версионирование или репликация
бакета и бэкапы PostgreSQL (pg_dump, pgBackRest, CloudNativePG). Встроенные
бэкапы `RGSTR_BACKUP_*` работают только в одиночном режиме.

## Бэкапы

rgstr сам делает бэкапы по расписанию: в S3-совместимое хранилище (AWS S3,
MinIO, Ceph, SeaweedFS, Yandex Object Storage, Cloudflare R2 …) или в
директорию (смонтированная NFS-шара, второй диск).

- **Что входит:** всё содержимое `RGSTR_STORAGE` — образы, пользователи,
  проекты, роботы, политики, настройки и журнал. Незавершённые загрузки не входят.
- **Без остановки.** Бэкап делается на работающем реестре и получается
  целостным: файлы заменяются атомарно, а архив пишет сначала метаданные и
  манифесты, потом blob'ы; сборка мусора на время бэкапа ждёт.
- **Формат:** обычный tar `rgstr-backup-<UTC дата-время>.tar` (слои образов
  уже сжаты, сжимать ещё раз нет смысла). В S3 он уходит multipart-загрузкой по
  частям, ни память, ни диск не держат бэкап целиком.
- **Ротация:** после удачного бэкапа старые сверх `RGSTR_BACKUP_KEEP` удаляются.
- Бэкап, пропущенный, пока rgstr был остановлен, делается сразу после запуска.
- Состояние — в админке на странице «Бэкапы» (там же «Сделать бэкап сейчас»),
  время последнего удачного — в `/healthz` (`last_backup`) и в метрике
  `rgstr_backup_last_success_timestamp_seconds`. Удобно для алерта.

| Переменная | По умолчанию | Описание |
|---|---|---|
| `RGSTR_BACKUP_TARGET` | — | `s3://бакет/префикс` или директория (`/backups`, `file:///backups`). Пусто — бэкапы выключены |
| `RGSTR_BACKUP_SCHEDULE` | `0 3 * * *` | Расписание cron (минута час день месяц день-недели), UTC |
| `RGSTR_BACKUP_KEEP` | `7` | Сколько бэкапов хранить |
| `RGSTR_BACKUP_S3_ENDPOINT` | AWS для региона | Адрес хранилища, например `https://storage.yandexcloud.net`, `http://minio:9000` |
| `RGSTR_BACKUP_S3_REGION` | `us-east-1` | Регион (`AWS_REGION`) |
| `RGSTR_BACKUP_S3_ACCESS_KEY`, `RGSTR_BACKUP_S3_SECRET_KEY` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Ключи доступа; `AWS_SESSION_TOKEN` тоже учитывается |
| `RGSTR_BACKUP_S3_PATH_STYLE` | `true` с `RGSTR_BACKUP_S3_ENDPOINT` | Адресация `https://host/бакет/ключ` (MinIO, Ceph); иначе `https://бакет.host/ключ` |

Ключам нужны права на чтение, запись, удаление и список объектов в префиксе.
Бакет создайте заранее. Если нужна неизменяемость копий, включите в хранилище
версионирование или object lock: rgstr удаляет только старые копии своего
префикса.

```bash
RGSTR_BACKUP_TARGET=s3://my-backups/rgstr
RGSTR_BACKUP_S3_ENDPOINT=https://storage.yandexcloud.net
RGSTR_BACKUP_S3_REGION=ru-central1
RGSTR_BACKUP_S3_ACCESS_KEY=...
RGSTR_BACKUP_S3_SECRET_KEY=...
```

### Восстановление

Остановите rgstr и запустите `rgstr restore` с тем же окружением:

```bash
rgstr backups                      # список
rgstr restore latest               # самый свежий — в пустой RGSTR_STORAGE
rgstr restore rgstr-backup-20261027-030000.tar
rgstr restore -force latest        # поверх данных: текущие уйдут в .before-restore-<время>/

# Docker Compose
docker compose stop rgstr
docker compose run --rm rgstr restore -force latest
docker compose start rgstr
```

Пока rgstr работает, `restore` откажется (данные заблокированы). При распаковке
содержимое каждого blob'а сверяется с его digest: повреждённый архив не
затронет текущие данные. После проверки удалите `.before-restore-*`.

Для разового бэкапа остановленного реестра есть `rgstr backup`; у работающего —
кнопка в админке или `POST /ui/api/backup/run` с токеном администратора.

## TLS

Передайте пути к сертификату и ключу — сервер автоматически переключится на HTTPS:

```bash
RGSTR_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem \
RGSTR_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem \
./rgstr
```

Или используйте nginx/Caddy/HAProxy как TLS-терминатор перед реестром.

---

## Метрики

С `RGSTR_METRICS_ENABLED=true` реестр отдаёт метрики в формате Prometheus на `GET /metrics` (без авторизации — открывайте только внутри сети мониторинга или закройте путь на reverse proxy):

| Метрика | Тип | Что это |
|---|---|---|
| `rgstr_build_info{version}` | gauge | версия |
| `rgstr_http_requests_total{method,code}` | counter | HTTP-запросы |
| `rgstr_events_total{action}` | counter | события журнала: `push`, `pull`, `delete_tag`, `login`, `login_failed`, `gc_run`, … |
| `rgstr_gc_runs_total{result}`, `rgstr_gc_freed_bytes_total` | counter | запуски GC и освобождённое место |
| `rgstr_gc_last_run_timestamp_seconds` | gauge | время последнего GC |
| `rgstr_repositories`, `rgstr_storage_bytes`, `rgstr_uploads_in_progress` | gauge | репозитории, данные на диске (пересчёт раз в минуту), незавершённые загрузки |
| `rgstr_disk_total_bytes`, `rgstr_disk_free_bytes` | gauge | размер и свободное место тома с данными |

Пример алерта: `rgstr_disk_free_bytes / rgstr_disk_total_bytes < 0.1`, всплеск `rate(rgstr_events_total{action="login_failed"}[5m])`.

## fail2ban

Неудачные входы (`docker login`, веб-админка, неверный текущий пароль при смене) пишутся в `<RGSTR_STORAGE>/audit.log` с IP клиента. В `deploy/fail2ban/` лежат фильтр и jail: 5 неудачных попыток за 10 минут — бан на час.

Фильтр `/etc/fail2ban/filter.d/rgstr.conf`:

```ini
[Definition]
# fail2ban вырезает найденную дату ({"time":"2026-10-08T10:44:00) из строки
# до проверки failregex, поэтому выражение начинается с долей секунды.
failregex = ^(?:\.\d+)?Z","user":"(?:[^"\\]|\\.)*","ip":"<HOST>","action":"login_failed"
ignoreregex =
datepattern = ^\{"time":"%%Y-%%m-%%dT%%H:%%M:%%S
```

Jail `/etc/fail2ban/jail.d/rgstr.local`:

```ini
[rgstr]
enabled     = true
filter      = rgstr
logpath     = /var/lib/rgstr/audit.log
# Docker Compose с volume rgstr-data:
# logpath   = /var/lib/docker/volumes/rgstr-data/_data/audit.log
logtimezone = UTC
backend     = polling
maxretry    = 5
findtime    = 10m
bantime     = 1h
port        = 5000,http,https
# rgstr в Docker с опубликованным портом:
# banaction = iptables-multiport[chain="DOCKER-USER"]
```

Установка из репозитория (или из архива релиза):

```bash
sudo cp deploy/fail2ban/filter.d/rgstr.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/rgstr.local  /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/rgstr.local   # logpath, порты, banaction для Docker
sudo fail2ban-regex /var/lib/rgstr/audit.log /etc/fail2ban/filter.d/rgstr.conf   # проверка
sudo systemctl reload fail2ban
sudo fail2ban-client status rgstr
```

- **`logpath`:** `/var/lib/rgstr/audit.log` при установке через `deploy/install.sh`; для Docker Compose с volume `rgstr-data` — `/var/lib/docker/volumes/rgstr-data/_data/audit.log` (или путь bind-mount, если вы смонтировали `./data`).
- **Docker с опубликованным портом:** трафик к контейнеру идёт через NAT Docker мимо цепочки `INPUT`, поэтому баните в `DOCKER-USER`: раскомментируйте в jail строку `banaction = iptables-multiport[chain="DOCKER-USER"]`. Если перед реестром стоит nginx на хосте, обычный `banaction` подходит.
- **Реальный IP за прокси.** rgstr берёт IP из `X-Forwarded-For`, только если запрос пришёл от доверенного прокси (`RGSTR_TRUSTED_PROXIES`, по умолчанию loopback и частные сети), и берёт в цепочке крайний правый недоверенный адрес — клиент не может подставить чужой IP, отправив заголовок сам. nginx из `nginx.conf` передаёт заголовок правильно. Если реестр доступен напрямую из сети, где есть недоверенные клиенты с частными адресами, задайте `RGSTR_TRUSTED_PROXIES=none` или конкретный адрес прокси.
- Имя пользователя в журнале задаёт клиент, но оно экранировано в JSON, и фильтр не даёт подставить через него поддельный IP.

## Reverse proxy

### nginx — системный (порты 80/443 уже заняты)

Если на хосте уже работает nginx, не нужно поднимать контейнерный. Скопируйте шаблон из репозитория и подключите его:

```bash
sudo cp nginx.conf /etc/nginx/conf.d/rgstr.conf
# Замените registry.example.com на свой домен
sudo nano /etc/nginx/conf.d/rgstr.conf
sudo nginx -t && sudo systemctl reload nginx
```

В docker-compose.yml оставьте секцию nginx закомментированной, rgstr слушает на `localhost:5000`.

### nginx — контейнерный (docker compose)

Раскомментируйте секцию `nginx` в `docker-compose.yml`. Подходит когда на хосте нет другого веб-сервера и порты 80/443 свободны.

### HAProxy

Альтернатива nginx — подходит если HAProxy уже используется как единая точка входа для нескольких сервисов.

Пример конфигурации (`/etc/haproxy/haproxy.cfg`):

```
frontend https_in
    bind *:443 ssl crt /etc/letsencrypt/live/registry.example.com/fullchain.pem
    default_backend rgstr

    # HTTP → HTTPS редирект
    bind *:80
    redirect scheme https if !{ ssl_fc }

backend rgstr
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    # Отключить буферизацию для больших образов
    option http-server-close
    server rgstr 127.0.0.1:5000 check
```

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
```

> HAProxy передаёт TLS-трафик напрямую бэкенду без буферизации, что удобно для больших образов.

---

## Развёртывание на Linux

### Systemd (production)

```bash
# Бинарник из релиза (см. «Быстрый старт → бинарник») или собранный локально:
#   make build-linux   → ./rgstr-linux-amd64
sudo ./deploy/install.sh ./rgstr
```

Скрипт создаёт:
- системного пользователя `rgstr`
- директорию `/var/lib/rgstr` для хранилища
- конфигурационный файл `/etc/rgstr/env` для секретов (переменные из него переопределяют значения в unit-файле)
- systemd unit с hardening-настройками

Управление сервисом:
```bash
sudo systemctl status  rgstr
sudo systemctl restart rgstr
sudo journalctl -u rgstr -f
```

### Кросс-компиляция

```bash
make build-linux        # Linux amd64
make build-linux-arm64  # Linux arm64 (Graviton, Raspberry Pi)
make build-windows      # Windows amd64
make release            # Все платформы сразу
```

---

## API

Все эндпоинты соответствуют [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/v2/` | Проверка версии API |
| `GET` | `/healthz` | Health check и версия (без аутентификации) |
| `GET` | `/readyz` | Готовность: доступны хранилище и (в кластере) база; `503`, если нет. Для балансировщика (без аутентификации) |
| `GET` | `/ui` | Веб-интерфейс |
| `GET` | `/stats` | Статистика репозиториев и pulls |
| `GET`, `POST` | `/v2/auth` | Получение Bearer токена (GET с query или POST-форма OAuth2, как у containerd) |
| `GET` | `/v2/_catalog` | Список репозиториев |
| `GET` | `/v2/<name>/tags/list` | Список тегов |
| `HEAD` | `/v2/<name>/manifests/<ref>` | Проверка существования манифеста |
| `GET` | `/v2/<name>/manifests/<ref>` | Получение манифеста |
| `PUT` | `/v2/<name>/manifests/<ref>` | Загрузка манифеста |
| `DELETE` | `/v2/<name>/manifests/<ref>` | Удаление: по тегу — только этот тег, по digest — манифест и все теги на него |
| `HEAD` | `/v2/<name>/blobs/<digest>` | Проверка существования blob'а |
| `GET` | `/v2/<name>/blobs/<digest>` | Скачивание blob'а (с поддержкой Range) |
| `DELETE` | `/v2/<name>/blobs/<digest>` | Отвязка blob'а от репозитория; данные удаляет GC, когда они не нужны ни одному образу с тегом |
| `POST` | `/v2/<name>/blobs/uploads/` | Начало загрузки |
| `GET` | `/v2/<name>/blobs/uploads/<uuid>` | Статус загрузки |
| `PATCH` | `/v2/<name>/blobs/uploads/<uuid>` | Загрузка чанка |
| `PUT` | `/v2/<name>/blobs/uploads/<uuid>` | Завершение загрузки |
| `DELETE` | `/v2/<name>/blobs/uploads/<uuid>` | Отмена загрузки |

Параметры `?n=<int>&last=<string>` поддерживаются для пагинации в `/v2/_catalog` и `/v2/<name>/tags/list`.

### GET /ui

Веб-интерфейс реестра. Открывается в браузере:

```
https://registry.example.com/ui
```

Возможности:
- Версия реестра — внизу каждой страницы и на форме входа (а также в ответе `/healthz`: `{"status":"ok","version":"v1.9.1"}`)
- Русский и английский интерфейс: язык берётся из браузера, переключается в шапке и на форме входа и запоминается
- Смена пароля (кнопка «Change password» в шапке) для любого пользователя. Новый пароль хранится в виде bcrypt-хеша в `<RGSTR_STORAGE>/users.json` и действует и для `docker login`
- Вход теми же пользователями, что и для `docker login`. Форма входа отправляется обычным образом (`POST /ui/login`), поэтому браузер предлагает сохранить логин и пароль, а после смены пароля — обновить его. В браузере хранится только токен сессии, пароль — нет
- Сессия общая для всех вкладок и переживает перезапуск браузера; живёт `RGSTR_SESSION_TTL` (12 часов) и продлевается, пока админка открыта. Выход завершает сессию на сервере (её токен больше не действует) и во всех вкладках. Смена или сброс пароля завершает остальные сессии пользователя
- При `RGSTR_AUTH_ENABLED=false` форма входа не показывается
- Статистика: количество репозиториев и pulls
- Список репозиториев с тегами: digest, размер, платформы. Для мультиархитектурных образов показываются все платформы с размером каждой, attestation-манифесты пропускаются
- Поиск репозиториев (без учёта регистра)
- Удаление (кнопки видны только пользователям с правом удаления):
  - **тега** — удаляется только этот тег, другие теги того же образа остаются;
  - **нескольких тегов** — флажки у тегов и «Delete selected»;
  - **образа** — образ и все теги, указывающие на него;
  - **репозитория** — все теги репозитория; для подтверждения нужно ввести его имя. Вложенные репозитории (`team/app` при удалении `team`) не затрагиваются.

  Удаление сразу убирает теги и манифесты — образ больше нельзя скачать, — а место на диске освобождает сборка мусора (GC). Администратор может отметить в подтверждении «Сразу освободить место»: тогда GC запускается сразу только для удаляемых данных (льготный период снимается только с них, загрузки, идущие в этот момент, не затрагиваются), и в уведомлении видно, сколько освобождено. Без этой галочки место освободит следующий плановый GC; данные, запушенные в пределах льготного периода (`RGSTR_UPLOAD_TTL`), — после его окончания
- Имя репозитория можно выделить и скопировать; кнопка «Copy» копирует полный путь `host/repo`. Копирование работает и без HTTPS
- Диск (для администраторов): на странице репозиториев — свободно из всего и сколько занимают данные реестра; на странице сборки мусора — ещё сколько освободит следующий GC, сколько освободится после льготного периода, и список удалённого, что ждёт GC (репозиторий / тег / образ, кто и когда удалил, размер). При свободном месте меньше 10% у администраторов на всех страницах показывается предупреждение
- Сборка мусора (страница «Garbage collection», только для администраторов):
  - расписание: выключено, раз в 1/6/12/24 часа, раз в неделю или своё значение. Сохраняется в `/data/meta.json`, действует сразу, без перезапуска, и имеет приоритет над `RGSTR_GC_INTERVAL`; кнопка возвращает значение из env;
  - запуск вручную, в том числе пробный (dry run) — показывает, что и сколько места будет освобождено, ничего не удаляя;
  - режим «без льготного периода» — сразу освобождает место от только что удалённого, но может сломать push, идущий в этот момент;
  - история последних 30 запусков: кто запустил, сколько освобождено, место каких удалённых репозиториев, тегов и образов освобождено, какие образы без тегов удалены
- Политики (страница «Policies», только для администраторов):
  - **хранение тегов** — правило задаёт шаблон репозиториев (`team/**`), шаблон тегов (`*`, `dev-*`) и что оставить: N последних по времени push и/или запушенные за последние N дней. Тег удаляется, только если его не оставляет ни одно подходящее правило. Правила применяются перед каждым плановым GC, вручную или пробным запуском, история запусков сохраняется. Если плановый GC выключен, правила применяются только вручную;
  - **неизменяемые теги** — подходящий тег нельзя перезаписать другим образом и нельзя удалить: ни `docker push` (ошибка `tag is immutable`), ни через админку, ни политикой хранения. Новый тег по шаблону запушить можно. Такие теги помечены 🔒 в списке репозиториев
- Карточка образа — клик по тегу: команды `docker pull` по тегу и по digest с кнопкой копирования, все теги образа, размер; для мультиархитектурных образов — переключение платформ; конфигурация (entrypoint, cmd, рабочая папка, пользователь, порты, тома, переменные окружения, labels); шаги сборки с командами `RUN`/`COPY`/… и размером каждого слоя; исходный манифест
- Журнал действий (страница «Audit log», только для администраторов): кто, когда и с какого IP сделал push, pull (скачал манифест), удалил тег, образ или репозиторий, вошёл в админку, ошибся паролем (в админке или при `docker login`), сменил пароль, изменил пользователей, политики или расписание GC, запустил GC или политики хранения (плановые запуски — от имени `system`). Фильтры по пользователю, действию и тексту. Хранится в `<RGSTR_STORAGE>/audit.log` (JSON по строке на событие); при 10 МБ файл переименовывается в `audit.log.1`, поэтому на диске не больше ~20 МБ журнала

Без TLS логин и пароль при входе передаются открытым текстом — для доступа извне настройте [TLS](#tls) или reverse proxy.

Данные интерфейс получает одним запросом:

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/ui/api/me` | Включена ли авторизация, текущий пользователь и его права |
| `POST` | `/ui/api/login` | `{"username","password"}` → `{"token","user","admin"}` (для скриптов) |
| `POST` | `/ui/login`, `/ui/password` | Формы входа и смены пароля веб-админки (перенаправляют обратно на `/ui`) |
| `GET` | `/ui/api/repos` | Репозитории с тегами, digest, размерами, платформами и временем push |
| `POST` | `/ui/api/tags/delete` | `{"repo","tags":[…],"free_space"}` — удалить теги, результат по каждому |
| `POST` | `/ui/api/images/delete` | `{"repo","digest","free_space"}` — удалить образ со всеми тегами |
| `POST` | `/ui/api/repos/delete` | `{"repo","free_space"}` — удалить репозиторий |
| `GET` | `/ui/api/disk` | Место на диске (администратор); `?data=1` — и размер данных реестра; `?details=1` — и оценка GC и список ожидающего |
| `GET` | `/ui/api/gc` | Расписание GC и история запусков (администратор) |
| `POST` | `/ui/api/gc/run` | `{"dry_run","ignore_grace"}` — запустить GC (администратор) |
| `GET` | `/ui/api/backup` | Настройки, состояние и список бэкапов (администратор) |
| `POST` | `/ui/api/backup/run` | Запустить бэкап сейчас, ответ `202` (администратор) |
| `POST` | `/ui/api/cli-secret` | Новый CLI-секрет для docker login (пользователи LDAP и SSO) |
| `GET` | `/ui/api/policies` | Правила хранения и неизменяемости, история применения (администратор) |
| `POST` | `/ui/api/policies/retention` | `{"rules":[{"repos","tags","keep_last","keep_days","disabled"}]}` — заменить правила хранения |
| `POST` | `/ui/api/policies/retention/run` | `{"dry_run"}` — применить правила хранения сейчас |
| `POST` | `/ui/api/policies/immutable` | `{"rules":[{"repos","tags","disabled"}]}` — заменить правила неизменяемости |
| `GET` | `/ui/api/users` | Пользователи (администратор) |
| `POST` | `/ui/api/users/create` | `{"name","role","password","must_change"}` |
| `POST` | `/ui/api/users/role` | `{"name","role"}` — для созданных в админке |
| `POST` | `/ui/api/users/password` | `{"name","password","must_change"}` — сброс пароля |
| `POST` | `/ui/api/users/delete` | `{"name"}` — для созданных в админке |
| `GET` | `/ui/api/image` | `?repo=&ref=` — подробности образа: платформы, конфигурация, слои |
| `GET` | `/ui/api/projects` | Видимые пользователю проекты |
| `GET` | `/ui/api/project` | `?name=` — проект: настройки, участники, репозитории |
| `POST` | `/ui/api/projects/create` | `{"name","description","public","quota_bytes"}` (администратор) |
| `POST` | `/ui/api/projects/update` | `{"name","description","public","quota_bytes"}` (админ проекта; квота — администратор) |
| `POST` | `/ui/api/projects/member` | `{"name","user","role"}`; пустая роль — убрать участника (админ проекта) |
| `POST` | `/ui/api/projects/delete` | `{"name"}` — только пустой проект (администратор) |
| `GET` | `/ui/api/robots` | Robot-аккаунты (администратор) |
| `POST` | `/ui/api/robots/create` | `{"name","description","permissions":[{"project","actions"}],"expires_days"}` → `{"name","secret"}` |
| `POST` | `/ui/api/robots/update` | `{"name","description","permissions","expires_days","disabled"}` |
| `POST` | `/ui/api/robots/secret` | `{"name"}` → новый `{"secret"}` |
| `POST` | `/ui/api/robots/delete` | `{"name"}` |
| `GET` | `/ui/api/webhooks` | Webhooks, которыми может управлять пользователь, и их последние отправки |
| `POST` | `/ui/api/webhooks/save` | `{"id","name","url","project","events","format","auth_header","skip_verify","disabled"}`; без `id` — создать |
| `POST` | `/ui/api/webhooks/delete` | `{"id"}` |
| `POST` | `/ui/api/webhooks/test` | `{"id"}` — отправить тестовое событие |
| `GET` | `/ui/api/audit` | Журнал: `?user=&action=&q=&before=&limit=` (администратор) |
| `POST` | `/ui/api/gc/settings` | `{"interval":"6h"}` — расписание; `"0"` — выключить, `""` — значение из env (администратор) |

---

### GET /stats

Возвращает список репозиториев, их теги и количество pulls.

При `RGSTR_AUTH_ENABLED=true` требует Basic auth (те же пользователи, что и для реестра) или Bearer-токен с доступом к каталогу.

```bash
curl https://registry.example.com/stats
# С авторизацией:
curl -u alice:secret https://registry.example.com/stats
```

```json
{
  "repositories": [
    {"name": "myrepo/alpine", "tags": ["latest", "3.18"], "pulls": 42},
    {"name": "myrepo/nginx",  "tags": ["latest"],          "pulls": 7}
  ],
  "total_repos": 2,
  "total_pulls": 49
}
```

Счётчики pulls персистируются в `stats.json` в директории хранилища и сохраняются между перезапусками.

---

## Структура хранилища

```
<RGSTR_STORAGE>/                    # или бакет S3 (RGSTR_STORAGE_S3_*): те же пути — ключи объектов
├── blobs/
│   └── sha256/
│       └── <2 hex>/<62 hex>        # содержимое blob'а (адресация по digest)
├── uploads/
│   └── <uuid>/
│       ├── chunk-<смещение>        # части незавершённой загрузки, по одной на PATCH
│       └── info.json               # uuid, repo, offset, started_at, состояние sha256
├── repositories/
│   └── <namespace>/<repo>/
│       ├── manifests/
│       │   ├── by-digest/<hex>     # содержимое манифеста + content-type
│       │   └── tags/<tag>          # hex-digest тега (указатель)
│       └── layers/
│           └── <hex>               # пустой маркер: blob принадлежит репозиторию
├── users.json                      # пользователи из админки и сменённые пароли (bcrypt)
├── meta.json                       # проекты, роботы, политики, webhooks, настройки, сессии, история GC
├── audit.log, audit.log.1          # журнал (JSON по строке), ротация по 10 МБ
├── stats.json                      # счётчики pull
└── .rgstr.lock                     # блокировка: один процесс на каталог
```

В [режиме кластера](#кластер-ha) `users.json`, `meta.json`, журнал и счётчики
хранятся в PostgreSQL (таблицы `rgstr_docs`, `rgstr_audit`, `rgstr_pulls`,
`rgstr_jobs`), а не в файлах; блокировки каталога нет.

Загрузка, начатая на одном процессе, продолжается на любом: каждая часть
сохраняется отдельно вместе с состоянием sha256, а при завершении части
склеиваются в blob (в S3 — копированием на стороне хранилища).

Дедупликация работает автоматически: если два репозитория содержат одинаковый слой, на диске он хранится один раз.

Несмотря на общее хранилище, каждый репозиторий отдаёт только «свои» blob'ы — те, что в него загружены, смонтированы или на которые ссылаются его манифесты (маркеры в `layers/`). Запрос чужого blob'а по digest возвращает `404`, поэтому через публичный репозиторий нельзя скачать слой приватного.

---

## Сборка и тесты

Нужен Go 1.26+.

```bash
make build      # сборка
make test       # unit- и интеграционные тесты
make cover      # с покрытием
make clean
```

Тесты кластера идут на настоящих PostgreSQL и S3 и запускаются, только когда
заданы адреса (так их запускает CI):

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=rgstr postgres:16-alpine
# S3: SeaweedFS (или MinIO) с бакетом rgstr-test и ключами
RGSTR_TEST_DATABASE_URL='postgres://postgres:pw@localhost:5432/rgstr?sslmode=disable' \
RGSTR_TEST_S3=http://localhost:9000 RGSTR_TEST_S3_KEY=… RGSTR_TEST_S3_SECRET=… \
  go test ./internal/db ./internal/storage ./internal/backup ./test/ha
```

`test/ha` запускает три процесса rgstr под нагрузкой push и pull и убивает их
`kill -9` по одному (`RGSTR_TEST_HA_DURATION`, по умолчанию 40 с); образы
проверяются по digest.

---

## Релизы (CI/CD)

Сборка настроена в `.github/workflows/`:

- `ci.yml` — на каждый push в `main` и pull request: `go vet`, govulncheck (уязвимости в вызываемом коде), тесты; задача `cluster` — тесты кластера на PostgreSQL и SeaweedFS (S3), включая нагрузочный `test/ha`;
- `release.yml` — сборка и публикация:
  - push в `main` → образ `ghcr.io/piqab/rgstr:main`;
  - тег `v*` → GitHub Release с бинарниками `rgstr-linux-{amd64,arm64}`, `mkpasswd-linux-{amd64,arm64}` и архивами `rgstr-<версия>-linux-{amd64,arm64}.tar.gz` (у каждого файла есть `.sha256`) и образ `:<версия>`, `:<major>.<minor>`, `:latest`.

Версия хранится в файле `VERSION` (например, `1.0.0`). Она же вшивается в бинарник при `make build`. Выпустить релиз:

```bash
# 1. повысить версию в VERSION и закоммитить
# 2. запушить main и поставить тег из файла
git push origin main
git tag v$(cat VERSION) && git push origin v$(cat VERSION)
```

Если тег не совпадает с `v$(cat VERSION)`, релизная сборка падает с ошибкой.

Образ публикуется через встроенный `GITHUB_TOKEN`, дополнительные секреты не нужны. После первой публикации пакет в GHCR по умолчанию приватный — чтобы `docker pull` работал без логина, откройте **Packages → rgstr → Package settings → Change visibility → Public**.

---

## Архитектура

```
main.go, cli.go     — запуск сервера; команды backup, backups, restore, migrate, version
internal/
├── config/    — конфигурация из переменных окружения
├── registry/  — HTTP API реестра (/v2), роутинг, /healthz, /readyz, /stats
├── storage/   — content-addressable хранилище: blob'ы, загрузки, манифесты, GC
│                поверх драйвера: файловая система или S3
├── s3/        — клиент S3 (подпись SigV4, multipart, копирование, presigned URL)
├── db/        — PostgreSQL кластера: общие документы, журнал, счётчики,
│                блокировка GC, захват плановых задач
├── auth/      — токены (JWT), пользователи и роли, сессии, LDAP, OIDC, роботы
├── meta/      — метаданные админки: проекты, политики, webhooks, настройки
├── ops/       — операции админки (удаление, retention) с журналом и webhooks
├── maint/     — расписание GC и retention
├── policy/    — правила хранения тегов и неизменяемые теги
├── backup/    — бэкапы по расписанию и восстановление (одиночный режим)
├── audit/     — журнал действий
├── stats/     — счётчики pull
├── metrics/   — метрики Prometheus
├── webhook/   — уведомления о событиях
├── glob/      — паттерны репозиториев
└── ui/        — веб-админка (встроенный SPA на JS) и её API
```

### Модель блокировок

| Блокировка | Тип | Защищает |
|---|---|---|
| `gcMu` | `sync.RWMutex` | Операции процесса держат RLock; GC держит Lock — исключает гонку GC с записью |
| Блокировка GC в PostgreSQL | advisory lock | В кластере: запись, которая делает данные достижимыми (манифест, связь blob'а с репозиторием, завершение загрузки), держит её разделяемо, GC — эксклюзивно, во всех процессах сразу |
| `blobMu[digest]` | `sync.Map[*sync.Mutex]` | Параллельная запись одного blob'а — только первый горутин пишет, остальные видят готовый файл |
| `uploadMu[uuid]` | `sync.Map[*sync.Mutex]` | Параллельные PATCH-чанки одной сессии — сериализует запись смещения |
| Строка документа в PostgreSQL | `SELECT … FOR UPDATE` | В кластере: изменение пользователей и метаданных применяется к последней версии, ничего не теряется |
| `.rgstr.lock` | `flock` | Одиночный режим: второй процесс на том же каталоге не запустится |

Все записи атомарны: на диске — запись во временный файл и `os.Rename`, в S3 —
объект появляется только целиком. Читатели никогда не видят частично
записанный файл.

---

## Лицензия

[MIT](LICENSE)
