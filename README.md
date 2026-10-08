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
- **Публичные и приватные репозитории** — гибкий контроль доступа через glob-паттерны, анонимный pull без авторизации
- **Range downloads** — поддержка HTTP `Range` заголовка при скачивании слоёв
- **Без внешних зависимостей рантайма** — один статический бинарь, нет баз данных, нет сторонних сервисов
- **Безопасность от гонок** — `sync.RWMutex` + per-digest и per-upload локи

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

### Проверка

Реестр слушает `http://localhost:5000`:

```bash
curl http://localhost:5000/v2/

docker pull alpine
docker tag alpine localhost:5000/myrepo/alpine:latest
docker push localhost:5000/myrepo/alpine:latest
docker pull localhost:5000/myrepo/alpine:latest
```

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
| `RGSTR_TOKEN_TTL` | `1h` | Время жизни токена |
| `RGSTR_USERS` | — | Список пользователей (см. ниже) |
| `RGSTR_ADMIN_USER` | `admin` | Имя первого администратора |
| `RGSTR_ADMIN_PASSWORD` | — | Временный пароль первого администратора, без хеша. Требует смены при первом входе в `/ui` (см. [Первый администратор](#первый-администратор)) |
| `RGSTR_ADMINS` | — | Пользователи, которым разрешено удаление (см. [Роли](#роли-пользователей)). Пусто — удалять могут все, кроме read-only |
| `RGSTR_READONLY_USERS` | — | Пользователи только с правом pull |
| `RGSTR_PUBLIC_REPOS` | — | Паттерны публичных репозиториев (см. ниже) |
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
| администратор | `RGSTR_ADMINS=alice` | pull, push, удаление тегов и blob'ов |

Первый администратор из `RGSTR_ADMIN_USER` всегда имеет права администратора, даже если его нет в `RGSTR_ADMINS`.

Если `RGSTR_ADMINS` не задан, удалять могут все пользователи, кроме read-only (как в версиях до 1.1.0). Права проверяются на каждый запрос: токен даёт ровно те действия, которые были запрошены в scope и разрешены ролью. Запрещённое действие возвращает `403 DENIED` при Basic-авторизации и `401` при Bearer-токене. Роль фиксируется в токене при выдаче, поэтому изменение ролей вступает в силу после перезапуска сервера и истечения ранее выданных токенов (`RGSTR_TOKEN_TTL`).

### Первый администратор

Чтобы не генерировать хеш для первого входа, задайте временный пароль прямо в env:

```
RGSTR_ADMIN_USER=admin          # по умолчанию admin
RGSTR_ADMIN_PASSWORD=changeme
```

- С временным паролем можно только войти в `/ui`: интерфейс сразу попросит задать новый пароль (не короче 8 символов). `docker login` с временным паролем отклоняется с сообщением `password change required: sign in to the web UI at /ui`.
- Новый пароль хранится в виде bcrypt-хеша в `<RGSTR_STORAGE>/users.json` (права `0600`) и переживает перезапуски. В Docker это том `/data`.
- **Сброс забытого пароля:** задайте в env другое значение `RGSTR_ADMIN_PASSWORD` и перезапустите. Сохранённый пароль удаляется, новый временный снова требует смены при входе.
- Если имя из `RGSTR_ADMIN_USER` есть и в `RGSTR_USERS`, действует временный пароль, а хеш из `RGSTR_USERS` для него игнорируется.

Сменить пароль через `/ui` может любой пользователь, не только администратор. Для пользователей из `RGSTR_USERS` действует то же правило сброса: если поменять хеш пользователя в `RGSTR_USERS`, сохранённый пароль сбрасывается. Если удалить пользователя из `RGSTR_USERS`, его сохранённый пароль тоже удаляется. Уже выданные токены остаются действительными до истечения `RGSTR_TOKEN_TTL`.

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

## TLS

Передайте пути к сертификату и ключу — сервер автоматически переключится на HTTPS:

```bash
RGSTR_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem \
RGSTR_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem \
./rgstr
```

Или используйте nginx/Caddy/HAProxy как TLS-терминатор перед реестром.

---

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
| `GET` | `/healthz` | Health check (без аутентификации) |
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
- Смена пароля (кнопка «Change password» в шапке) для любого пользователя. Новый пароль хранится в виде bcrypt-хеша в `<RGSTR_STORAGE>/users.json` и действует и для `docker login`
- Вход теми же пользователями, что и для `docker login`. Пароль обменивается на токен (`POST /ui/api/login`), в браузере хранится только токен — до закрытия вкладки и не дольше `RGSTR_TOKEN_TTL`, после чего интерфейс снова попросит войти
- При `RGSTR_AUTH_ENABLED=false` форма входа не показывается
- Статистика: количество репозиториев и pulls
- Список репозиториев с тегами: digest, размер, платформы. Для мультиархитектурных образов показываются все платформы с размером каждой, attestation-манифесты пропускаются
- Поиск репозиториев (без учёта регистра)
- Удаление (кнопки видны только пользователям с правом удаления):
  - **тега** — удаляется только этот тег, другие теги того же образа остаются;
  - **нескольких тегов** — флажки у тегов и «Delete selected»;
  - **образа** — образ и все теги, указывающие на него;
  - **репозитория** — все теги репозитория; для подтверждения нужно ввести его имя. Вложенные репозитории (`team/app` при удалении `team`) не затрагиваются.

  Данные удалённого удаляет GC, когда на них не ссылается ни один тег

Без TLS логин и пароль при входе передаются открытым текстом — для доступа извне настройте [TLS](#tls) или reverse proxy.

Данные интерфейс получает одним запросом:

| Метод | Путь | Описание |
|---|---|---|
| `GET` | `/ui/api/me` | Включена ли авторизация, текущий пользователь и его права |
| `POST` | `/ui/api/login` | `{"username","password"}` → `{"token","user","actions"}` |
| `GET` | `/ui/api/repos` | Репозитории с тегами, digest, размерами, платформами и временем push |
| `POST` | `/ui/api/tags/delete` | `{"repo","tags":[…]}` — удалить теги, результат по каждому |
| `POST` | `/ui/api/images/delete` | `{"repo","digest"}` — удалить образ со всеми тегами |
| `POST` | `/ui/api/repos/delete` | `{"repo"}` — удалить репозиторий |

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
<RGSTR_STORAGE>/
├── blobs/
│   └── sha256/
│       └── <2 hex>/<62 hex>        # содержимое blob'а (адресация по digest)
├── uploads/
│   └── <uuid>/
│       ├── data                    # накопленные байты незавершённой загрузки
│       └── info.json               # uuid, repo, offset, started_at
└── repositories/
    └── <namespace>/<repo>/
        ├── manifests/
        │   ├── by-digest/<hex>     # содержимое манифеста + content-type
        │   └── tags/<tag>          # hex-digest тега (указатель)
        └── layers/
            └── <hex>               # пустой маркер: blob принадлежит репозиторию
```

Дедупликация работает автоматически: если два репозитория содержат одинаковый слой, на диске он хранится один раз.

Несмотря на общее хранилище, каждый репозиторий отдаёт только «свои» blob'ы — те, что в него загружены, смонтированы или на которые ссылаются его манифесты (маркеры в `layers/`). Запрос чужого blob'а по digest возвращает `404`, поэтому через публичный репозиторий нельзя скачать слой приватного.

---

## Сборка и тесты

```bash
# Зависимости
go mod tidy

# Сборка
make build

# Все тесты (unit + интеграционные)
make test

# С покрытием
make cover

# Очистка
make clean
```

---

## Релизы (CI/CD)

Сборка настроена в `.github/workflows/`:

- `ci.yml` — `go vet` и тесты на каждый push в `main` и pull request;
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
main.go
└── internal/
    ├── config/      — конфигурация из env vars
    ├── auth/
    │   ├── token.go      — JWT (HS256): выдача и верификация
    │   └── middleware.go — HTTP middleware: Bearer/Basic, /v2/auth эндпоинт
    ├── storage/
    │   ├── storage.go    — content-addressable хранилище, upload-сессии, манифесты
    │   └── gc.go         — mark-and-sweep GC: всё, что достижимо от тегов, плюс недавние загрузки
    └── registry/
        ├── registry.go   — HTTP handlers, роутинг
        └── errors.go     — OCI error codes
```

### Модель блокировок

| Блокировка | Тип | Защищает |
|---|---|---|
| `gcMu` | `sync.RWMutex` | Все операции держат RLock; GC держит Lock — исключает гонку GC с записью |
| `blobMu[digest]` | `sync.Map[*sync.Mutex]` | Параллельная запись одного blob'а — только первый горутин пишет, остальные видят готовый файл |
| `uploadMu[uuid]` | `sync.Map[*sync.Mutex]` | Параллельные PATCH-чанки одной сессии — сериализует запись смещения |

Все записи используют `atomicWrite` (write to temp → `os.Rename`) — читатели никогда не видят частично записанный файл.

---

## Лицензия

MIT
