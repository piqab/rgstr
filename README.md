# rgstr

Минималистичный OCI/Docker container registry, написанный на Go.

Совместим с `docker push` / `docker pull`, `crane`, `skopeo`, `containerd` и любым другим клиентом, поддерживающим [OCI Distribution Specification v1.1](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

---

## Возможности

- **Полная OCI/Docker совместимость** — поддержка Docker Registry HTTP API v2 и OCI Distribution Spec v1.1
- **Chunked uploads** — возобновляемые загрузки с проверкой `Content-Range`
- **Дедупликация blob'ов** — одни и те же слои хранятся на диске один раз вне зависимости от количества репозиториев
- **Cross-repo mount** — мгновенное монтирование blob'а из другого репозитория без передачи данных
- **Garbage collection** — периодическая очистка недостижимых blob'ов и зависших сессий загрузки
- **Bearer token auth** — JWT (HS256) по Docker auth specification, Basic auth на токен-эндпоинте
- **Публичные и приватные репозитории** — гибкий контроль доступа через glob-паттерны, анонимный pull без авторизации
- **Range downloads** — поддержка HTTP `Range` заголовка при скачивании слоёв
- **Без внешних зависимостей рантайма** — один статический бинарь, нет баз данных, нет сторонних сервисов
- **Безопасность от гонок** — `sync.RWMutex` + per-digest и per-upload локи

---

## Быстрый старт

### Локально

```bash
git clone https://github.com/piqab/rgstr
cd rgstr

go mod tidy
go build -o rgstr .
./rgstr
```

Реестр запустится на `http://localhost:5000`.

```bash
docker pull alpine
docker tag alpine localhost:5000/myrepo/alpine:latest
docker push localhost:5000/myrepo/alpine:latest
docker pull localhost:5000/myrepo/alpine:latest
```

### Docker

```bash
docker build -t rgstr .
docker run -d \
  --name rgstr \
  -p 5000:5000 \
  -v /srv/registry:/data \
  rgstr
```

### Docker Compose

```bash
docker compose up -d
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
| `RGSTR_PUBLIC_REPOS` | — | Паттерны публичных репозиториев (см. ниже) |
| `RGSTR_GC_INTERVAL` | `1h` | Интервал запуска сборщика мусора |
| `RGSTR_UPLOAD_TTL` | `24h` | Через сколько удалять незавершённые загрузки |

### Формат RGSTR_USERS

```
RGSTR_USERS="alice:$2a$10$...,bob:$2a$10$..."
```

Каждая запись — `имя:bcrypt-хеш`. Для генерации хеша:

```bash
go run ./cmd/mkpasswd alice mypassword
# RGSTR_USERS=alice:$2a$10$...
```

---

## Публичные и приватные репозитории

По умолчанию при включённой аутентификации все репозитории приватные. Переменная `RGSTR_PUBLIC_REPOS` задаёт список паттернов, для которых анонимный `pull` разрешён без авторизации.

### Матрица доступа

|  | pull | push |
|---|---|---|
| Публичный репо | без авторизации ✓ | требуется токен ✗ |
| Приватный репо | требуется токен ✗ | требуется токен ✗ |
| Любой репо при `AUTH_ENABLED=false` | без авторизации ✓ | без авторизации ✓ |

### Паттерны

| Паттерн | Совпадает | Не совпадает |
|---|---|---|
| `alpine` | `alpine` | `myns/alpine` |
| `library/*` | `library/ubuntu`, `library/alpine` | `library/ns/ubuntu` |
| `public/**` | `public/myimage`, `public/ns/myimage` | `other/myimage` |
| `**` | любой репозиторий | — |

- `*` — любой одиночный сегмент пути (без слешей)
- `**` — любой путь, включая слеши
- `?` — любой одиночный символ

### Примеры

```bash
# Всё в namespace "public/" доступно без логина, остальное приватное
RGSTR_PUBLIC_REPOS=public/**

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

# После docker login — доступ ко всему
docker login registry.example.com
docker pull registry.example.com/private/myimage:latest
docker push registry.example.com/public/myimage:latest
```

---

## Аутентификация

По умолчанию реестр открытый (`RGSTR_AUTH_ENABLED=false`). Для включения auth:

```bash
# 1. Сгенерировать хеши паролей
go run ./cmd/mkpasswd alice secret1
go run ./cmd/mkpasswd bob   secret2

# 2. Запустить с auth
RGSTR_AUTH_ENABLED=true \
RGSTR_AUTH_SECRET=my-signing-secret \
RGSTR_USERS="alice:$2a$10$...,bob:$2a$10$..." \
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

Или используйте nginx/Caddy как TLS-терминатор перед реестром.

---

## Развёртывание на Linux

### Systemd (production)

```bash
# Собрать Linux-бинарь
make build-linux          # → rgstr-linux-amd64

# Установить и запустить как systemd-сервис
sudo ./deploy/install.sh ./rgstr-linux-amd64
```

Скрипт создаёт:
- системного пользователя `rgstr`
- директорию `/var/lib/rgstr` для хранилища
- конфигурационный файл `/etc/rgstr/env` для секретов
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
| `GET` | `/v2/auth` | Получение Bearer токена |
| `GET` | `/v2/_catalog` | Список репозиториев |
| `GET` | `/v2/<name>/tags/list` | Список тегов |
| `HEAD` | `/v2/<name>/manifests/<ref>` | Проверка существования манифеста |
| `GET` | `/v2/<name>/manifests/<ref>` | Получение манифеста |
| `PUT` | `/v2/<name>/manifests/<ref>` | Загрузка манифеста |
| `DELETE` | `/v2/<name>/manifests/<ref>` | Удаление манифеста |
| `HEAD` | `/v2/<name>/blobs/<digest>` | Проверка существования blob'а |
| `GET` | `/v2/<name>/blobs/<digest>` | Скачивание blob'а (с поддержкой Range) |
| `DELETE` | `/v2/<name>/blobs/<digest>` | Удаление blob'а |
| `POST` | `/v2/<name>/blobs/uploads/` | Начало загрузки |
| `GET` | `/v2/<name>/blobs/uploads/<uuid>` | Статус загрузки |
| `PATCH` | `/v2/<name>/blobs/uploads/<uuid>` | Загрузка чанка |
| `PUT` | `/v2/<name>/blobs/uploads/<uuid>` | Завершение загрузки |
| `DELETE` | `/v2/<name>/blobs/uploads/<uuid>` | Отмена загрузки |

Параметры `?n=<int>&last=<string>` поддерживаются для пагинации в `/v2/_catalog` и `/v2/<name>/tags/list`.

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
            └── <hex>               # маркеры для GC (пустые файлы)
```

Дедупликация работает автоматически: если два репозитория содержат одинаковый слой, на диске он хранится один раз.

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
    │   └── gc.go         — mark-and-sweep GC
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
