**English** | [Русский](README.ru.md)

# rgstr

A minimalist OCI/Docker container registry written in Go.

Compatible with `docker push` / `docker pull`, `crane`, `skopeo`, `containerd` and any other client that supports the [OCI Distribution Specification v1.1](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

---

## Features

- **Full OCI/Docker compatibility** — supports the Docker Registry HTTP API v2 and the OCI Distribution Spec v1.1
- **Chunked uploads** — resumable uploads with `Content-Range` validation
- **Blob deduplication** — identical layers are stored on disk once, regardless of how many repositories use them
- **Cross-repo mount** — instantly mount a blob from another repository without transferring data (requires pull permission on the source repository)
- **Garbage collection** — periodic cleanup of untagged images, their blobs and stale upload sessions; does not interfere with a push in progress
- **Bearer token auth** — JWT (HS256) per the Docker auth specification, Basic auth on the token endpoint
- **Pull-through cache** — projects that cache Docker Hub, GHCR or any registry: no pull limits, faster CI, images available when the upstream is down
- **Vulnerability scanning** — Trivy built in: reports in the web admin, pulls of vulnerable images refused per project
- **Cluster (HA)** — several processes on S3 and PostgreSQL accept push and pull; the failure of any one of them does not stop the registry
- **Backups to S3 or a directory** — on a schedule, on a running registry, with rotation and one-command restore
- **LDAP, Active Directory and single sign-on (OIDC)** — sign in with a directory password or through Keycloak, Authentik, Entra ID, Google; roles from groups
- **Public and private repositories** — flexible access control with glob patterns, anonymous pull without authentication
- **Range downloads** — support for the HTTP `Range` header when downloading layers
- **Kubernetes** — [the rgstroperator operator](https://github.com/piqab/rgstroperator): registry, volume, Ingress with TLS, metrics, backups and cluster in a single resource
- **No external runtime dependencies** — a single static binary; databases and third-party services are needed only for the cluster (PostgreSQL and S3)
- **Race safety** — `sync.RWMutex` + per-digest and per-upload locks; in the cluster, a shared lock in PostgreSQL

### Limitations

- **High availability requires [cluster mode](#cluster-ha)** (S3 and PostgreSQL).
  Without it, rgstr is a single process on a data directory (a second one will not start, see
  [the lock](#configuration)): a restart means a short downtime.
- **Roles** — four project roles and three global ones; custom roles cannot be defined. Access can be given per project or per repository pattern within a project.
- **External users** — LDAP / Active Directory and OpenID Connect; no SAML.
  SSO users run `docker login` with a CLI secret from the web admin.

---

## Quick start

Prebuilt artifacts are published automatically by GitHub Actions:

- **binaries** (linux/amd64, linux/arm64) — on the [Releases](https://github.com/piqab/rgstr/releases) page: as standalone files `rgstr-linux-<arch>` and `mkpasswd-linux-<arch>` and as an archive `rgstr-<version>-linux-<arch>.tar.gz` with the installation files;
- **Docker image** (amd64 + arm64) — `ghcr.io/piqab/rgstr`.

| Image tag | Contents |
|---|---|
| `latest` | latest release |
| `1.2.3`, `1.2` | specific version |
| `main` | current `main` branch (may be unstable) |

### Option 1: binary

```bash
VERSION=v1.0.0          # the version you need from the Releases page
ARCH=amd64              # or arm64

curl -LO https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-${VERSION}-linux-${ARCH}.tar.gz
curl -LO https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-${VERSION}-linux-${ARCH}.tar.gz.sha256
sha256sum -c rgstr-${VERSION}-linux-${ARCH}.tar.gz.sha256

tar xzf rgstr-${VERSION}-linux-${ARCH}.tar.gz
cd rgstr-${VERSION}-linux-${ARCH}
```

The archive contains: the `rgstr` and `mkpasswd` binaries, `.env.example`, `docker-compose.yml`, `deploy/` (systemd unit and install script) and this README.

If you only need the binary, without the archive:

```bash
curl -L -o rgstr https://github.com/piqab/rgstr/releases/download/${VERSION}/rgstr-linux-${ARCH}
chmod +x rgstr
```

**Quick run in the current directory:**

```bash
RGSTR_STORAGE=./data ./rgstr
```

Configuration is set only through environment variables (see [Configuration](#configuration)); the binary itself does not read `.env`. To load settings from a file:

```bash
cp .env.example .env
# edit .env
set -a; . ./.env; set +a
./rgstr
```

**Install as a systemd service (production):**

```bash
sudo ./deploy/install.sh ./rgstr
sudo nano /etc/rgstr/env        # auth, users, public repositories
sudo systemctl restart rgstr
```

See [Deploying on Linux](#deploying-on-linux) for details.

### Option 2: Docker Compose

You only need two files — `docker-compose.yml` and `.env`. There is no need to clone or build the sources:

```bash
mkdir rgstr && cd rgstr
curl -LO https://raw.githubusercontent.com/piqab/rgstr/main/docker-compose.yml
curl -L -o .env https://raw.githubusercontent.com/piqab/rgstr/main/.env.example
# (or take both files from the release archive)

# In .env set:
#   RGSTR_AUTH_ENABLED=true
#   RGSTR_AUTH_SECRET=<openssl rand -hex 32>
#   RGSTR_AUTH_REALM=http://<server address>:5000/v2/auth
#   RGSTR_ADMIN_PASSWORD=<temporary password>

docker compose pull
docker compose up -d
docker compose logs -f
```

Open `http://<server address>:5000/ui`, sign in as `admin` with the temporary password and set a permanent one — until then, `docker login` as `admin` will not succeed. Other users can be added to `RGSTR_USERS` (see [RGSTR_USERS format](#rgstr_users-format)).

If the `ghcr.io/piqab/rgstr` package is private, sign in to GHCR before `pull` with a GitHub token that has the `read:packages` scope:

```bash
echo <TOKEN> | docker login ghcr.io -u <github-user> --password-stdin
```

The `ghcr.io/piqab/rgstr:latest` image is used by default. To pin a version, use the `RGSTR_VERSION` variable (in `.env` or in the environment):

```bash
echo "RGSTR_VERSION=1.2.0" >> .env
docker compose pull && docker compose up -d
```

Upgrade: `docker compose pull && docker compose up -d`.
To build the image locally from source (in a clone of the repository) instead of pulling it from GHCR:

```bash
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

The web UI starts together with the registry: `http://<address>:5000/ui`.

**If `docker compose pull` / `up` reports `unauthorized`** — Docker cannot pull the image: either the GHCR package is private (sign in with `docker login ghcr.io`, see above, or make the package public), or the image for this version has not been published yet (check that the release build in GitHub Actions succeeded and that the `RGSTR_VERSION` tag exists).

`docker compose` passes all variables from `.env` into the container. `RGSTR_STORAGE` is always overridden to `/data` (Docker volume).

> **Note:** data is stored in the named volume `rgstr-data` (managed by Docker), not in a local `./data` folder. To locate the volume on the host: `docker volume inspect rgstr-data`. If you need a local folder, replace `rgstr-data:/data` with `./data:/data` in `docker-compose.yml` and remove the `volumes: rgstr-data:` section.

### Option 3: docker run

```bash
docker run -d \
  --name rgstr \
  --restart unless-stopped \
  -p 5000:5000 \
  -v /srv/registry:/data \
  ghcr.io/piqab/rgstr:latest
```

### Option 4: Kubernetes

[rgstroperator](https://github.com/piqab/rgstroperator) deploys rgstr as a `Registry` resource: volume, a secret with the administrator's temporary password, Ingress with TLS, metrics, backups, LDAP/OIDC and a cluster of several replicas.

```bash
helm install rgstroperator oci://ghcr.io/piqab/charts/rgstroperator -n rgstroperator-system --create-namespace
```

### Verify

The registry listens on `http://localhost:5000`:

```bash
curl http://localhost:5000/v2/

docker pull alpine
docker tag alpine localhost:5000/myrepo/alpine:latest
docker push localhost:5000/myrepo/alpine:latest
docker pull localhost:5000/myrepo/alpine:latest
```

One data directory, one rgstr process: while rgstr is running it holds the lock `<RGSTR_STORAGE>/.rgstr.lock`, and a second process on the same data (a second container on a shared volume, NFS) will not start. If the process crashes, the kernel releases the lock, so a restart is not blocked.

For access from other machines over HTTP, see [Configuring the Docker daemon for an HTTP registry](#configuring-the-docker-daemon-for-an-http-registry) or set up [TLS](#tls).

### From source

```bash
git clone https://github.com/piqab/rgstr
cd rgstr
make build
./rgstr
```

---

## Configuration

All settings are set through environment variables. Copy `.env.example` to `.env` and edit it:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|---|---|---|
| `RGSTR_ADDR` | `:5000` | Listen address and port |
| `RGSTR_STORAGE` | `./data` | Path to the storage directory |
| `RGSTR_TLS_CERT` | — | Path to the TLS certificate (PEM) |
| `RGSTR_TLS_KEY` | — | Path to the TLS key (PEM) |
| `RGSTR_AUTH_ENABLED` | `false` | Enable authentication |
| `RGSTR_AUTH_SECRET` | `change-me-in-production` | Secret for signing JWTs |
| `RGSTR_AUTH_REALM` | `http://localhost:5000/v2/auth` | Token endpoint URL (returned in WWW-Authenticate) |
| `RGSTR_AUTH_SERVICE` | `rgstr` | Service name in tokens |
| `RGSTR_AUTH_ISSUER` | `rgstr` | Token issuer (the `iss` field) |
| `RGSTR_TOKEN_TTL` | `1h` | Lifetime of a `docker login` token |
| `RGSTR_SESSION_TTL` | `12h` | How long an idle web admin session lives; while the web admin is open, the session is extended |
| `RGSTR_USERS` | — | List of users (see below) |
| `RGSTR_ADMIN_USER` | `admin` | Name of the first administrator |
| `RGSTR_ADMIN_PASSWORD` | — | Temporary password of the first administrator, unhashed. Must be changed at the first sign-in to `/ui` (see [First administrator](#first-administrator)) |
| `RGSTR_ADMINS` | — | Users allowed to delete (see [Roles](#user-roles)). If empty, everyone except read-only users can delete |
| `RGSTR_READONLY_USERS` | — | Users with pull permission only |
| `RGSTR_TRUSTED_PROXIES` | loopback and private networks | Proxies whose `X-Forwarded-For` is trusted when recording the client IP; `none` — trust no one (see [fail2ban](#fail2ban)) |
| `RGSTR_PUBLIC_REPOS` | — | Public repository patterns (see below) |
| `RGSTR_METRICS_ENABLED` | `false` | Prometheus metrics on `/metrics` (see [Metrics](#metrics)) |
| `RGSTR_STORAGE_DRIVER` | `filesystem` | `filesystem` or `s3` (see [Cluster](#cluster-ha)) |
| `RGSTR_STORAGE_S3_*` | — | Data bucket when `RGSTR_STORAGE_DRIVER=s3` |
| `RGSTR_DATABASE_URL` | — | PostgreSQL: enables cluster mode |
| `RGSTR_PROXIES`, `RGSTR_PROXY_*` | — | Pull-through cache projects (see [Pull-through cache](#pull-through-cache)) |
| `RGSTR_SCAN_*` | — | Vulnerability scanning (see [Vulnerability scanning](#vulnerability-scanning)) |
| `RGSTR_BACKUP_*` | — | Scheduled backups to S3 or a directory (see [Backups](#backups)) |
| `RGSTR_LDAP_*` | — | Password sign-in via LDAP / Active Directory (see [LDAP](#ldap-and-active-directory)) |
| `RGSTR_OIDC_*` | — | Web admin sign-in via OpenID Connect (see [Single sign-on](#single-sign-on-oidc)) |
| `RGSTR_GC_INTERVAL` | `1h` | Garbage collector run interval |
| `RGSTR_UPLOAD_TTL` | `24h` | When to remove unfinished uploads. This is also the GC grace period: recently uploaded data is not removed even if no tag points to it yet |

### RGSTR_USERS format

```
RGSTR_USERS='alice:$2a$10$...,bob:$2a$10$...'
```

Each entry is `name:bcrypt-hash`. To generate a hash:

```bash
# Without Go — the tool is included in the Docker image
docker run --rm --entrypoint /mkpasswd ghcr.io/piqab/rgstr alice mypassword
# From the release archive
./mkpasswd alice mypassword
# From source
go run ./cmd/mkpasswd alice mypassword

# RGSTR_USERS='alice:$2a$10$...'
```

The value must be in **single** quotes — this keeps the `$` in the hash as is in `.env` for docker compose, in the shell, and in `/etc/rgstr/env` for systemd. Without quotes or in double quotes, docker compose substitutes environment variables for `$2a`, `$10`, the hash gets truncated and sign-in stops working. `htpasswd -B` hashes (`$2y$`) also work.

---

## Public and private repositories

By default, with authentication enabled, all repositories are private. The `RGSTR_PUBLIC_REPOS` variable sets a list of patterns for which anonymous `pull` is allowed without authentication.

### Access matrix

|  | pull | push | delete |
|---|---|---|---|
| Anonymous, public repo | ✓ | ✗ | ✗ |
| Anonymous, private repo | ✗ | ✗ | ✗ |
| User in `RGSTR_READONLY_USERS` | ✓ | ✗ | ✗ |
| Regular user | ✓ | ✓ | ✗ (✓ if `RGSTR_ADMINS` is empty) |
| User in `RGSTR_ADMINS` | ✓ | ✓ | ✓ |
| Anyone with `AUTH_ENABLED=false` | ✓ | ✓ | ✓ |

### Patterns

| Pattern | Matches | Does not match |
|---|---|---|
| `alpine` | `alpine` | `myns/alpine` |
| `library/*` | `library/ubuntu`, `library/alpine` | `library/ns/ubuntu` |
| `public/**` | `public/myimage`, `public/ns/myimage` | `other/myimage` |
| `**/public/**` | `alex/public/alpine`, `public/alpine`, `a/b/public/img` | `alex/private/alpine` |
| `**` | any repository | — |

- `*` — any single path segment (no slashes)
- `**` — zero or more path segments, including slashes (can appear anywhere in the pattern)
- `?` — any single character

### Examples

```bash
# Everything in the "public/" namespace is available without login, the rest is private
RGSTR_PUBLIC_REPOS=public/**

# Repositories with a "public" segment anywhere in the path
RGSTR_PUBLIC_REPOS=**/public/**

# Several comma-separated patterns
RGSTR_PUBLIC_REPOS=library/*,public/**,alpine

# All repositories public for pull (unrestricted mirror)
RGSTR_PUBLIC_REPOS=**

# All repositories private (leave empty)
RGSTR_PUBLIC_REPOS=
```

### Client behavior

```bash
# Public repo — pull without docker login
docker pull registry.example.com/public/myimage:latest

# Public repo — push requires authentication
docker push registry.example.com/public/myimage:latest
# → unauthorized: authentication required

# Private repo — pull requires authentication
docker pull registry.example.com/private/myimage:latest
# → unauthorized: authentication required

# After docker login — access according to the user's role
docker login registry.example.com
docker pull registry.example.com/private/myimage:latest
docker push registry.example.com/public/myimage:latest
```

### User roles

| Role | How to set | Permissions |
|---|---|---|
| read-only | `RGSTR_READONLY_USERS=viewer,ci-reader` | pull |
| user | listed in `RGSTR_USERS` | pull, push |
| administrator | `RGSTR_ADMINS=alice` | pull, push, deleting tags and blobs, managing users, policies and GC in the web admin |

Users with any of these roles can also be created in the web admin (the "Users" page), see [Users in the web admin](#users-in-the-web-admin).

The first administrator from `RGSTR_ADMIN_USER` always has administrator rights, even if not listed in `RGSTR_ADMINS`.

If `RGSTR_ADMINS` is not set, all users from `RGSTR_USERS` except read-only ones can delete (as in versions before 1.1.0). Permissions are checked on every request: a token grants exactly the actions that were requested in the scope and allowed by the role. A forbidden action returns `403 DENIED` with Basic auth and `401` with a Bearer token. The role is fixed in the token when it is issued, so role changes take effect after a server restart and once previously issued tokens expire (`RGSTR_TOKEN_TTL`).

### First administrator

To avoid generating a hash for the first sign-in, set a temporary password directly in env:

```
RGSTR_ADMIN_USER=admin          # admin by default
RGSTR_ADMIN_PASSWORD=changeme
```

- The temporary password only lets you sign in to `/ui`: the UI immediately asks you to set a new password (at least 8 characters). `docker login` with the temporary password is rejected with the message `password change required: sign in to the web UI at /ui`.
- The new password is stored as a bcrypt hash in `<RGSTR_STORAGE>/users.json` (mode `0600`) and survives restarts. In Docker this is the `/data` volume.
- After the password change, the account lives in `users.json` and no longer depends on env: `RGSTR_ADMIN_PASSWORD` can be removed or left empty — signing in with your own password keeps working. (Before 1.5.0, removing the variable deleted the account together with the password.)
- **Resetting a forgotten password:** set a different `RGSTR_ADMIN_PASSWORD` value in env and restart. The saved password is deleted, and the new temporary one again must be changed at sign-in.
- If the name from `RGSTR_ADMIN_USER` is also in `RGSTR_USERS`, the temporary password applies and the hash from `RGSTR_USERS` is ignored for it.

Any user, not only an administrator, can change their password via `/ui`. The same reset rule applies to users from `RGSTR_USERS`: if you change a user's hash in `RGSTR_USERS`, the saved password is reset. If you remove a user from `RGSTR_USERS`, their saved password is deleted too. A password change ends the user's web admin sessions; `docker login` tokens stay valid until `RGSTR_TOKEN_TTL` expires.

### Projects

A project groups repositories sharing the same first name segment: the `team` project is `team/app`, `team/db/postgres`, and so on. Projects are created by a registry administrator on the "Projects" page.

- **Project members and roles:**

  | Role | pull | push | delete | project members and webhooks |
  |---|---|---|---|---|
  | Project admin | ✓ | ✓ | ✓ | ✓ |
  | Maintainer | ✓ | ✓ | ✓ | |
  | Developer | ✓ | ✓ | | |
  | Guest | ✓ | | | |

- Inside a project, only members and registry administrators have access; the user's global role ("User", "Read-only") does not apply here. Outsiders do not see the project's repositories either in `/v2/_catalog` or in the web admin.
- **Repository access** — roles on some repositories of a project, on top of a member's role on the whole project. A rule names a user, a pattern within the project (`app-*` — one level, `app/**` — everything under `app/`, `api` — one repository) and a role (maintainer, developer or guest). The user may do what any of their roles allows: guest on `team` plus developer on `app-*` means push only to `team/app-*` and pull from the rest. A user with only such rules sees the project too. Rules are managed by project admins on the project page ("Repository access").
- **Public project** — pull without sign-in for everyone (like `RGSTR_PUBLIC_REPOS`, but configured in the web admin).
- Repositories outside projects follow global roles, as before.
- **Storage quota** (set by a registry administrator): calculated over the unique layers of all the project's images that tags point to. A manifest push that would take the project over its quota is rejected (`denied: quota exceeded: project team would use 3.3 MiB of 2.0 MiB`); a push without new data (a new tag on an already uploaded image) always succeeds. Used space and the quota are shown in the project list. Layers uploaded without a manifest do not count toward the quota — GC removes them.
- Only an empty project can be deleted — delete its repositories first.
- Projects are stored in `<RGSTR_STORAGE>/meta.json`.

### Robot accounts

For CI and automation, an administrator creates robot accounts on the "Robots" page:

- a name like `robot$ci`, and a generated secret instead of a password. The secret is shown once and only its hash is stored; if it leaks, it can be regenerated (the old one stops working immediately);
- permissions are listed explicitly: a project (or "all repositories"), optionally a repository pattern (`web/**` within the project; with "all repositories" the full name, e.g. `team/base-*`), and the pull/push/delete actions. A robot with permissions on a specific project has no access to repositories outside projects;
- expiration (30/90/180/365 days or never), disabling. A disabled, expired or deleted robot loses access immediately;
- a robot works only through `docker login`; it cannot sign in to the web admin.

```bash
# the name in single quotes — it contains "$"
echo "$ROBOT_SECRET" | docker login registry.example.com -u 'robot$ci' --password-stdin
```

Robots are stored in `<RGSTR_STORAGE>/meta.json`.

### Webhooks

The "Webhooks" page configures HTTP notifications about events: push, pull, delete, project quota exceeded.

- **Scope:** all repositories (registry administrator only) or a single project (registry administrator or project admin).
- **Format:** Harbor-style JSON (`{"type":"PUSH_ARTIFACT","operator":…,"event_data":{"resources":[{"digest","tag","resource_url"}],"repository":{…}}}`) or Slack-compatible `{"text": "alice pushed …"}` — accepted by Slack and Mattermost incoming webhooks.
- Optional `Authorization` header (not shown in the web admin after saving), option to skip TLS certificate verification.
- Delivery in the background, up to 3 attempts on error; the last 20 deliveries of each webhook are visible in the web admin (kept in memory until restart). The "Send test" button sends a test event.
- The registry address in image links is taken from `RGSTR_AUTH_REALM`.

Keep in mind: a webhook makes the registry server send requests to the given URL, including into the internal network. Only registry administrators and project admins can create webhooks.

### Users in the web admin

On the "Users" page an administrator can:

- create a user with the "Administrator", "User" or "Read-only" role and a password (the "Generate" button makes up a random one). By default the password is temporary: at the first sign-in to `/ui` the user sets their own, and until then `docker login` with the temporary password does not work. The username and password are shown once — pass them to the user;
- change the role of, and delete, a user created in the web admin. A deleted user loses access immediately, even with a still valid token;
- reset the password of any user, including those from `RGSTR_USERS`.

Such users are stored in `<RGSTR_STORAGE>/users.json`. Users from `RGSTR_USERS` and the first administrator are shown in the list, but their role and existence are set in env. If a user with the same name as one created in the web admin appears in env, env wins. You cannot delete yourself or change your own role — so that you do not accidentally end up without an administrator.

For users created in the web admin, the rule "if `RGSTR_ADMINS` is empty, everyone can delete" does not apply: their permissions are determined by the role alone.

### Resetting an administrator password

The method depends on where the administrator is defined. The "Source" column on the "Users" page shows this: `first admin`, `env` or `created here`.

**If there is another administrator** — the simplest way: "Users" → "Reset password" for the user in question. You can also check "Require a password change at the first sign-in" right away.

**First administrator (`RGSTR_ADMIN_USER` / `RGSTR_ADMIN_PASSWORD`).** Set a new temporary password in env and restart — the saved password is deleted:

```bash
# Docker Compose: edit .env
RGSTR_ADMIN_PASSWORD=new-temporary-password
docker compose up -d          # specifically up -d: restart does not re-read .env

# systemd: edit /etc/rgstr/env
sudo systemctl restart rgstr
```

Sign in to `/ui` as `admin` with this password — the web admin asks you to set a permanent one. Putting the old value back into env later does not restore the forgotten password.

**Administrator from `RGSTR_USERS`.** Generate a new hash and replace it in `RGSTR_USERS` — the password saved in the web admin is reset, and the hash from env applies again:

```bash
docker run --rm --entrypoint /mkpasswd ghcr.io/piqab/rgstr alice new-password
# RGSTR_USERS='alice:$2a$10$...'  → replace the alice entry, then docker compose up -d / systemctl restart rgstr
```

**Administrator created in the web admin, and there are no other administrators.** Temporarily enable a first administrator with a separate name, sign in as it, and reset the password on the "Users" page:

```bash
# .env or /etc/rgstr/env
RGSTR_ADMIN_USER=recovery
RGSTR_ADMIN_PASSWORD=temporary-recovery-password
docker compose up -d   # or sudo systemctl restart rgstr
```

1. Sign in to `/ui` as `recovery` and set a permanent password for it (the web admin will ask).
2. "Users" → "Reset password" for the administrator who forgot the password, with "Require a password change at the first sign-in" checked.
3. Remove `RGSTR_ADMIN_USER` and `RGSTR_ADMIN_PASSWORD` from env, run `docker compose up -d` / `systemctl restart rgstr`, sign in as the recovered administrator and delete `recovery` on the "Users" page.

For recovery, use a name that does not belong to any existing user: if the name matches a user created in the web admin, env "overrides" it, and that user is removed from `users.json`.

**If you have no access to env, but have access to the data.** User passwords are stored in `<RGSTR_STORAGE>/users.json` (bcrypt). Removing a user's entry from this file while the registry is stopped restores the env password for a user from env, and deletes a user created in the web admin entirely.

**If after an upgrade your session was lost and the password does not work.** Check whether you replaced `.env` (for example, with a fresh `.env.example`):
- `RGSTR_AUTH_SECRET` changed — all sessions and `docker login`s are signed out; passwords are not affected;
- the `RGSTR_ADMIN_PASSWORD` value changed — the first administrator's password is reset to this value (by design, this is the reset method): sign in with it, and the web admin asks you to set a new one;
- in rgstr before 1.5.0, an empty or removed `RGSTR_ADMIN_PASSWORD` deleted the first administrator — set a temporary password as described above;
- the data volume or path changed (`RGSTR_STORAGE`, volume name, compose project name) — the registry started with empty data: both images and passwords are gone.

After a password reset or change, that user's web admin sessions end immediately; `docker login`s made with the old password stay valid until their token expires (`RGSTR_TOKEN_TTL`, 1 hour by default). Every reset is recorded in the audit log.

---

## Authentication

By default the registry is open (`RGSTR_AUTH_ENABLED=false`). To enable auth:

```bash
# 1. Generate password hashes
./mkpasswd alice secret1
./mkpasswd bob   secret2

# 2. Run with auth (hashes in single quotes)
RGSTR_AUTH_ENABLED=true \
RGSTR_AUTH_SECRET=my-signing-secret \
RGSTR_USERS='alice:$2a$10$...,bob:$2a$10$...' \
./rgstr
```

The Docker client automatically discovers the token endpoint via the `WWW-Authenticate` header and requests a token on `docker login`:

```bash
docker login localhost:5000
# Username: alice
# Password: secret1
```

### Configuring the Docker daemon for an HTTP registry

If the registry runs without TLS, add to `/etc/docker/daemon.json`:

```json
{
  "insecure-registries": ["myserver:5000"]
}
```

Then restart Docker: `sudo systemctl restart docker`.

---

## LDAP, Active Directory and single sign-on

Besides local users, rgstr accepts directory users. They
appear in the user list at their first sign-in (source "LDAP" or "SSO"),
can be project members, and their role is taken from directory groups.

Rules for both methods:

- **Local users take precedence.** A user from env or created in the web admin
  signs in only with their own password; a directory user with the same name
  cannot sign in. This is why the first administrator works even if the directory is unavailable.
- **Names are stored in lowercase**: `Alice` and `alice` are the same user.
- **Roles from groups.** If `*_ADMIN_GROUPS` or `*_READONLY_GROUPS` are set,
  the role is taken from groups at each sign-in: administrator, read-only, otherwise
  `*_DEFAULT_ROLE`. If they are not set, the role is changed in the web admin and saved.
- **Access restriction.** `*_ALLOWED_GROUPS` lets in only members of these
  groups (and of the role groups).
- A group is compared case-insensitively by full name/DN or by the `CN` from the DN:
  `registry-admins` matches `CN=registry-admins,OU=Groups,DC=corp`.
- Such a user's password is stored in the directory: it cannot be changed or reset in
  rgstr. Deleting in the web admin removes the user and their sessions; at the
  next sign-in they appear again — revoke access in the directory or via groups.

### LDAP and Active Directory

docker login and web admin sign-in accept the directory password. rgstr looks up
the user's entry (as a service account or anonymously), then
verifies the password by binding as the found entry. A successful check
is cached for a minute.

| Variable | Default | Description |
|---|---|---|
| `RGSTR_LDAP_URL` | — | `ldap://host:389` or `ldaps://host:636`. Empty — LDAP disabled |
| `RGSTR_LDAP_STARTTLS` | `false` | StartTLS over `ldap://` |
| `RGSTR_LDAP_CA_FILE` | system | Server CA certificate (PEM) |
| `RGSTR_LDAP_INSECURE_SKIP_VERIFY` | `false` | Do not verify the certificate (testing only) |
| `RGSTR_LDAP_BIND_DN`, `RGSTR_LDAP_BIND_PASSWORD` | anonymous | Service account for searching |
| `RGSTR_LDAP_BASE_DN` | — | Where to search for users |
| `RGSTR_LDAP_USER_FILTER` | `(&(objectClass=person)(uid=%s))` | Search filter; `%s` — the name (escaped) |
| `RGSTR_LDAP_GROUP_ATTR` | `memberOf` | User entry attribute with the list of groups |
| `RGSTR_LDAP_GROUP_FILTER` | — | Group search for directories without `memberOf`; `%s` — the user's DN |
| `RGSTR_LDAP_GROUP_BASE_DN` | `RGSTR_LDAP_BASE_DN` | Where to search for groups |
| `RGSTR_LDAP_ADMIN_GROUPS`, `RGSTR_LDAP_READONLY_GROUPS` | — | Role groups (comma-separated) |
| `RGSTR_LDAP_ALLOWED_GROUPS` | — | Who is allowed in at all |
| `RGSTR_LDAP_DEFAULT_ROLE` | `user` | Role without role groups: `user`, `readonly`, `admin` |

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

OpenLDAP without the `memberOf` overlay:

```bash
RGSTR_LDAP_URL=ldap://ldap.example:389
RGSTR_LDAP_STARTTLS=true
RGSTR_LDAP_BASE_DN='ou=people,dc=example,dc=org'
RGSTR_LDAP_GROUP_BASE_DN='ou=groups,dc=example,dc=org'
RGSTR_LDAP_GROUP_FILTER='(&(objectClass=groupOfNames)(member=%s))'
RGSTR_LDAP_ADMIN_GROUPS=registry-admins
```

### Single sign-on (OIDC)

The sign-in page gets a "Sign in with …" button that leads to
an OpenID Connect provider (Keycloak, Authentik, Dex, Entra ID, Google, GitLab).
The flow is authorization code with PKCE; the ID token signature is verified against the
provider's keys.

Docker cannot sign in through a browser, so an SSO user creates a
**CLI secret** in the web admin (a button in the header) and uses it as the password:

```bash
echo "$CLI_SECRET" | docker login registry.example.com -u dave --password-stdin
```

A new secret revokes the previous one. LDAP users can also create a
CLI secret so as not to store their directory password in CI.

| Variable | Default | Description |
|---|---|---|
| `RGSTR_OIDC_ISSUER` | — | Provider URL (issuer). Empty — OIDC disabled |
| `RGSTR_OIDC_CLIENT_ID`, `RGSTR_OIDC_CLIENT_SECRET` | — | Client at the provider; without a secret — a public client with PKCE |
| `RGSTR_OIDC_REDIRECT_URL` | from `RGSTR_AUTH_REALM` | Redirect URL: `https://<registry>/ui/oidc/callback` |
| `RGSTR_OIDC_SCOPES` | `openid profile email` | Requested scopes (add `groups` if the provider returns groups that way) |
| `RGSTR_OIDC_USERNAME_CLAIM` | `preferred_username` | Claim with the username (if absent — `email`) |
| `RGSTR_OIDC_GROUPS_CLAIM` | `groups` | Claim with groups; if it is not in the ID token, it is taken from userinfo |
| `RGSTR_OIDC_NAME` | `SSO` | Name on the sign-in button |
| `RGSTR_OIDC_ADMIN_GROUPS`, `RGSTR_OIDC_READONLY_GROUPS`, `RGSTR_OIDC_ALLOWED_GROUPS`, `RGSTR_OIDC_DEFAULT_ROLE` | | Same as for LDAP |

The username is taken from the claim and links the sign-in to the user's projects, so
choose a claim the user cannot change themselves: in Keycloak,
disallow editing the username (*Edit username* off); with Google and Entra ID,
use `email` (rgstr does not accept an unverified e-mail) or
`RGSTR_OIDC_USERNAME_CLAIM=sub`.

Keycloak: create a client of type *OpenID Connect*, enable *Client
authentication*, set *Valid redirect URIs* to
`https://registry.example.com/ui/oidc/callback`, add a *Group
Membership* mapper with the claim name `groups` (turn off *Full group path*).

```bash
RGSTR_OIDC_ISSUER=https://sso.example.com/realms/main
RGSTR_OIDC_CLIENT_ID=rgstr
RGSTR_OIDC_CLIENT_SECRET=...
RGSTR_OIDC_NAME=Keycloak
RGSTR_OIDC_ADMIN_GROUPS=registry-admins
```

## Pull-through cache

A project can be a read-only cache of another registry (Docker Hub, GHCR,
Quay, another rgstr): the first pull of an image fetches it from the
upstream and stores it, later pulls are served locally. This gets around
Docker Hub's pull limits, speeds up CI and keeps images available when the
upstream is down.

```bash
docker pull registry.example.com/dockerhub/library/nginx:1.27   # = docker.io/library/nginx:1.27
docker pull registry.example.com/ghcr/piqab/rgstr:1.9           # = ghcr.io/piqab/rgstr:1.9
```

- **Tags** are re-checked upstream at most every `RGSTR_PROXY_TTL` (5 min) with a
  HEAD request, which Docker Hub does not count against its pull limit;
  images by digest and layers never change and are fetched once.
- **Layers** are streamed to the client while they are stored: the first pull
  is not slower than pulling from the upstream directly.
- **When the upstream is down** or rate-limits, cached images are served as they
  are; only images never pulled fail (`502`, or `429` from the rate limit).
- **Multi-platform images:** only the platforms clients pull are downloaded.
- **Read-only:** pushing into a cache project is refused. Access works as in
  any project (members, roles, public). Old images can be removed with
  [retention policies](#get-ui) or by hand.

Set up a cache in the web admin (Projects → New project → "Pull-through
cache of another registry", administrators only) or in env:

```bash
RGSTR_PROXIES=dockerhub=https://registry-1.docker.io,ghcr=https://ghcr.io
RGSTR_PROXY_DOCKERHUB_USERNAME=me             # optional: higher Docker Hub limits
RGSTR_PROXY_DOCKERHUB_PASSWORD=dckr_pat_…     # password or access token
RGSTR_PROXY_DOCKERHUB_PUBLIC=true             # anonymous pull
RGSTR_PROXY_TTL=5m
```

Projects from `RGSTR_PROXIES` are created at startup and edited there.
On Docker Hub single-segment names live under `library/` (`dockerhub/nginx`
is `docker.io/library/nginx` too).

For containerd (Kubernetes nodes) the cache can stand in for Docker Hub in
`/etc/containerd/certs.d/docker.io/hosts.toml`:

```toml
server = "https://registry-1.docker.io"

[host."https://registry.example.com/v2/dockerhub"]
  capabilities = ["pull", "resolve"]
  override_path = true
```

## Vulnerability scanning

With `RGSTR_SCAN_ENABLED=true` images are scanned with
[Trivy](https://trivy.dev) (built into the Docker image): when they are
pushed or cached, on demand ("Scan" on the image page), and again every
`RGSTR_SCAN_INTERVAL` as the vulnerability database learns new
vulnerabilities. The image page shows the findings (severity, package,
installed and fixed versions, links); tags in the repository list show the
worst severity.

A project can refuse pulls of vulnerable images (project settings →
"Vulnerable images", e.g. "refuse pulls with critical vulnerabilities").
Clients get `403 denied` with the reason. Images not scanned yet are served.

| Variable | Default | Description |
|---|---|---|
| `RGSTR_SCAN_ENABLED` | `false` | Turn on scanning |
| `RGSTR_SCAN_ON_PUSH` | `true` | Scan new images (pushed or cached) |
| `RGSTR_SCAN_INTERVAL` | `24h` | Rescan tagged images this often |
| `RGSTR_SCAN_CONCURRENCY` | `1` | Scans at a time |
| `RGSTR_SCAN_TIMEOUT` | `15m` | Limit for one scan |
| `RGSTR_SCAN_TRIVY` | `trivy` | The Trivy binary (in the image: `/usr/local/bin/trivy`) |
| `RGSTR_SCAN_TRIVY_SERVER` | — | A Trivy server (`trivy server`) holding the database, for client/server mode |
| `RGSTR_SCAN_CACHE_DIR` | `<RGSTR_STORAGE>/.trivy` | Trivy's database (about 70 MB, downloaded on the first scan; not backed up) |

rgstr runs `trivy image` against itself with a short-lived pull token, so
it works with every storage driver and in a cluster (reports are stored next
to the data). Trivy's own settings (`TRIVY_DB_REPOSITORY` for a mirror of the
database, `TRIVY_OFFLINE_SCAN`, proxies) are passed through the environment.
Reports of deleted images are removed by garbage collection.

## Cluster (HA)

Several rgstr processes work as a single registry: any of them accepts push and
pull, and the failure or upgrade of one stops neither push nor pull.

```
          load balancer / Kubernetes Service
        ┌──────────┼──────────┐
     rgstr-1    rgstr-2    rgstr-N
        └─────┬────┴─────┬────┘
        PostgreSQL       S3
```

- **S3** stores the data: blobs, manifests, tags, unfinished uploads.
  A chunked upload (PATCH) can be continued by any process: each chunk and
  the sha256 state are saved immediately.
- **PostgreSQL** stores the shared state: users, projects, robots,
  policies, webhooks, settings, web admin sessions, audit log, pull
  counters. Changes are visible to all processes immediately (`LISTEN/NOTIFY`).
- **Garbage collection** runs in one process per interval and holds a shared
  lock: a push that makes data reachable waits for it, so GC
  never removes a layer of an image that is being pushed right now.
- **No state on disk:** processes can be added, removed and
  restarted at any time.

Verified with a load test (`test/ha`): three processes under constant push and
pull; every 1.5–3 s one of them is killed with `kill -9` and restarted; all
images remain intact, and no pull returns wrong data.

| Variable | Default | Description |
|---|---|---|
| `RGSTR_DATABASE_URL` | — | `postgres://user:pass@host:5432/rgstr?sslmode=require`; tables are created automatically |
| `RGSTR_STORAGE_DRIVER` | `filesystem` (`s3` if a bucket is set) | Where to store data |
| `RGSTR_STORAGE_S3_BUCKET` | — | Bucket (create it beforehand) |
| `RGSTR_STORAGE_S3_PREFIX` | — | Key prefix, for example `prod/` |
| `RGSTR_STORAGE_S3_ENDPOINT` | AWS for the region | `https://storage.yandexcloud.net`, `http://minio:9000` … |
| `RGSTR_STORAGE_S3_REGION` | `us-east-1` | Region |
| `RGSTR_STORAGE_S3_ACCESS_KEY`, `RGSTR_STORAGE_S3_SECRET_KEY` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Keys |
| `RGSTR_STORAGE_S3_PATH_STYLE` | `true` with endpoint | `host/bucket/key` addressing |
| `RGSTR_STORAGE_S3_REDIRECT` | `false` | Serve layers via redirect to a presigned URL: clients download directly from S3, bypassing rgstr. The endpoint must be reachable by clients |

All processes get the same environment, including `RGSTR_AUTH_SECRET`:
tokens issued by one are accepted by all. `/healthz` is process liveness,
`/readyz` is readiness (the database and storage are reachable); the load balancer needs
`/readyz`.

A data directory on a shared volume (NFS, CephFS) instead of S3 also works:
`RGSTR_STORAGE_DRIVER=filesystem` with `RGSTR_DATABASE_URL`.

**Migrating from single-process mode.** Stop rgstr and migrate the data:

```bash
RGSTR_DATABASE_URL=postgres://… RGSTR_STORAGE_S3_BUCKET=registry RGSTR_STORAGE_S3_ENDPOINT=… \
RGSTR_STORAGE_S3_ACCESS_KEY=… RGSTR_STORAGE_S3_SECRET_KEY=… \
  rgstr migrate -from /data
```

Blobs, manifests, tags, users, projects, settings, counters
and the audit log are copied; running it again copies whatever is missing. After
migration, the push time of tags is the migration time (S3 does not keep the original), which affects
age-based retention policies.

**Cluster backups** — use the storage's own tools: bucket versioning or replication
and PostgreSQL backups (pg_dump, pgBackRest, CloudNativePG). The built-in
`RGSTR_BACKUP_*` backups work only in single-process mode.

## Backups

rgstr takes backups on a schedule by itself: to S3-compatible storage (AWS S3,
MinIO, Ceph, SeaweedFS, Yandex Object Storage, Cloudflare R2 …) or to a
directory (a mounted NFS share, a second disk).

- **What is included:** the entire contents of `RGSTR_STORAGE` — images, users,
  projects, robots, policies, settings and the audit log. Unfinished uploads are not included.
- **No downtime.** A backup is taken on a running registry and is
  consistent: files are replaced atomically, and the archive writes metadata and
  manifests first, then blobs; garbage collection waits while the backup runs.
- **Format:** a plain tar `rgstr-backup-<UTC date-time>.tar` (image layers
  are already compressed, there is no point in compressing them again). It is sent to S3 as a multipart upload in
  parts; neither memory nor disk holds the whole backup.
- **Rotation:** after a successful backup, old ones beyond `RGSTR_BACKUP_KEEP` are deleted.
- A backup missed while rgstr was stopped is taken right after startup.
- Status is shown in the web admin on the "Backups" page (which also has "Back up now"),
  the time of the last successful one is in `/healthz` (`last_backup`) and in the
  `rgstr_backup_last_success_timestamp_seconds` metric. Handy for alerting.

| Variable | Default | Description |
|---|---|---|
| `RGSTR_BACKUP_TARGET` | — | `s3://bucket/prefix` or a directory (`/backups`, `file:///backups`). Empty — backups disabled |
| `RGSTR_BACKUP_SCHEDULE` | `0 3 * * *` | Cron schedule (minute hour day month day-of-week), UTC |
| `RGSTR_BACKUP_KEEP` | `7` | How many backups to keep |
| `RGSTR_BACKUP_S3_ENDPOINT` | AWS for the region | Storage address, for example `https://storage.yandexcloud.net`, `http://minio:9000` |
| `RGSTR_BACKUP_S3_REGION` | `us-east-1` | Region (`AWS_REGION`) |
| `RGSTR_BACKUP_S3_ACCESS_KEY`, `RGSTR_BACKUP_S3_SECRET_KEY` | `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | Access keys; `AWS_SESSION_TOKEN` is also honored |
| `RGSTR_BACKUP_S3_PATH_STYLE` | `true` with `RGSTR_BACKUP_S3_ENDPOINT` | `https://host/bucket/key` addressing (MinIO, Ceph); otherwise `https://bucket.host/key` |

The keys need permission to read, write, delete and list objects in the prefix.
Create the bucket beforehand. If you need immutable copies, enable
versioning or object lock in the storage: rgstr deletes only old copies under its own
prefix.

```bash
RGSTR_BACKUP_TARGET=s3://my-backups/rgstr
RGSTR_BACKUP_S3_ENDPOINT=https://storage.yandexcloud.net
RGSTR_BACKUP_S3_REGION=ru-central1
RGSTR_BACKUP_S3_ACCESS_KEY=...
RGSTR_BACKUP_S3_SECRET_KEY=...
```

### Restore

Stop rgstr and run `rgstr restore` with the same environment:

```bash
rgstr backups                      # list
rgstr restore latest               # the newest one, into an empty RGSTR_STORAGE
rgstr restore rgstr-backup-20261027-030000.tar
rgstr restore -force latest        # over existing data: the current data is moved to .before-restore-<time>/

# Docker Compose
docker compose stop rgstr
docker compose run --rm rgstr restore -force latest
docker compose start rgstr
```

While rgstr is running, `restore` refuses (the data is locked). During extraction,
the content of each blob is checked against its digest: a corrupted archive does not
affect the current data. After verifying, delete `.before-restore-*`.

For a one-off backup of a stopped registry there is `rgstr backup`; for a running one,
the button in the web admin or `POST /ui/api/backup/run` with an administrator token.

## TLS

Pass the certificate and key paths — the server switches to HTTPS automatically:

```bash
RGSTR_TLS_CERT=/etc/letsencrypt/live/registry.example.com/fullchain.pem \
RGSTR_TLS_KEY=/etc/letsencrypt/live/registry.example.com/privkey.pem \
./rgstr
```

Or use nginx/Caddy/HAProxy as a TLS terminator in front of the registry.

---

## Metrics

With `RGSTR_METRICS_ENABLED=true` the registry serves metrics in Prometheus format on `GET /metrics` (without authentication — expose it only inside the monitoring network or block the path on the reverse proxy):

| Metric | Type | Meaning |
|---|---|---|
| `rgstr_build_info{version}` | gauge | version |
| `rgstr_http_requests_total{method,code}` | counter | HTTP requests |
| `rgstr_events_total{action}` | counter | audit log events: `push`, `pull`, `delete_tag`, `login`, `login_failed`, `gc_run`, … |
| `rgstr_gc_runs_total{result}`, `rgstr_gc_freed_bytes_total` | counter | GC runs and freed space |
| `rgstr_gc_last_run_timestamp_seconds` | gauge | time of the last GC |
| `rgstr_repositories`, `rgstr_storage_bytes`, `rgstr_uploads_in_progress` | gauge | repositories, data on disk (recalculated once a minute), unfinished uploads |
| `rgstr_disk_total_bytes`, `rgstr_disk_free_bytes` | gauge | size and free space of the data volume |

Alert examples: `rgstr_disk_free_bytes / rgstr_disk_total_bytes < 0.1`, a spike in `rate(rgstr_events_total{action="login_failed"}[5m])`.

## fail2ban

Failed sign-ins (`docker login`, web admin, wrong current password on password change) are written to `<RGSTR_STORAGE>/audit.log` with the client IP. `deploy/fail2ban/` contains a filter and a jail: 5 failed attempts in 10 minutes — a one-hour ban.

Filter `/etc/fail2ban/filter.d/rgstr.conf`:

```ini
[Definition]
# fail2ban cuts the matched date ({"time":"2026-10-08T10:44:00) out of the line
# before checking failregex, so the expression starts with the fractional seconds.
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
# Docker Compose with the rgstr-data volume:
# logpath   = /var/lib/docker/volumes/rgstr-data/_data/audit.log
logtimezone = UTC
backend     = polling
maxretry    = 5
findtime    = 10m
bantime     = 1h
port        = 5000,http,https
# rgstr in Docker with a published port:
# banaction = iptables-multiport[chain="DOCKER-USER"]
```

Installation from the repository (or from the release archive):

```bash
sudo cp deploy/fail2ban/filter.d/rgstr.conf /etc/fail2ban/filter.d/
sudo cp deploy/fail2ban/jail.d/rgstr.local  /etc/fail2ban/jail.d/
sudo nano /etc/fail2ban/jail.d/rgstr.local   # logpath, ports, banaction for Docker
sudo fail2ban-regex /var/lib/rgstr/audit.log /etc/fail2ban/filter.d/rgstr.conf   # check
sudo systemctl reload fail2ban
sudo fail2ban-client status rgstr
```

- **`logpath`:** `/var/lib/rgstr/audit.log` when installed via `deploy/install.sh`; for Docker Compose with the `rgstr-data` volume — `/var/lib/docker/volumes/rgstr-data/_data/audit.log` (or the bind-mount path if you mounted `./data`).
- **Docker with a published port:** traffic to the container goes through Docker NAT, bypassing the `INPUT` chain, so ban in `DOCKER-USER`: uncomment the `banaction = iptables-multiport[chain="DOCKER-USER"]` line in the jail. If nginx on the host sits in front of the registry, the regular `banaction` works.
- **Real IP behind a proxy.** rgstr takes the IP from `X-Forwarded-For` only if the request came from a trusted proxy (`RGSTR_TRUSTED_PROXIES`, loopback and private networks by default), and takes the rightmost untrusted address in the chain — a client cannot substitute someone else's IP by sending the header itself. nginx from `nginx.conf` passes the header correctly. If the registry is directly reachable from a network with untrusted clients on private addresses, set `RGSTR_TRUSTED_PROXIES=none` or the specific proxy address.
- The username in the log is supplied by the client, but it is JSON-escaped, and the filter does not allow injecting a fake IP through it.

## Reverse proxy

### nginx on the host (ports 80/443 already in use)

If nginx is already running on the host, there is no need to start a containerized one. Copy the template from the repository and enable it:

```bash
sudo cp nginx.conf /etc/nginx/conf.d/rgstr.conf
# Replace registry.example.com with your domain
sudo nano /etc/nginx/conf.d/rgstr.conf
sudo nginx -t && sudo systemctl reload nginx
```

In docker-compose.yml, leave the nginx section commented out; rgstr listens on `localhost:5000`.

### nginx in a container (docker compose)

Uncomment the `nginx` section in `docker-compose.yml`. Suitable when there is no other web server on the host and ports 80/443 are free.

### HAProxy

An alternative to nginx — suitable if HAProxy is already used as a single entry point for several services.

Example configuration (`/etc/haproxy/haproxy.cfg`):

```
frontend https_in
    bind *:443 ssl crt /etc/letsencrypt/live/registry.example.com/fullchain.pem
    default_backend rgstr

    # HTTP → HTTPS redirect
    bind *:80
    redirect scheme https if !{ ssl_fc }

backend rgstr
    option forwardfor
    http-request set-header X-Forwarded-Proto https
    # Disable buffering for large images
    option http-server-close
    server rgstr 127.0.0.1:5000 check
```

```bash
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
```

> HAProxy passes TLS traffic directly to the backend without buffering, which is convenient for large images.

---

## Deploying on Linux

### Systemd (production)

```bash
# A binary from a release (see "Quick start → binary") or built locally:
#   make build-linux   → ./rgstr-linux-amd64
sudo ./deploy/install.sh ./rgstr
```

The script creates:
- a system user `rgstr`
- the `/var/lib/rgstr` directory for storage
- the `/etc/rgstr/env` configuration file for secrets (its variables override the values in the unit file)
- a systemd unit with hardening settings

Managing the service:
```bash
sudo systemctl status  rgstr
sudo systemctl restart rgstr
sudo journalctl -u rgstr -f
```

### Cross-compilation

```bash
make build-linux        # Linux amd64
make build-linux-arm64  # Linux arm64 (Graviton, Raspberry Pi)
make build-windows      # Windows amd64
make release            # All platforms at once
```

---

## API

All endpoints conform to the [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec/blob/main/spec.md).

| Method | Path | Description |
|---|---|---|
| `GET` | `/v2/` | API version check |
| `GET` | `/healthz` | Health check and version (no authentication) |
| `GET` | `/readyz` | Readiness: storage and (in the cluster) the database are reachable; `503` if not. For the load balancer (no authentication) |
| `GET` | `/ui` | Web UI |
| `GET` | `/stats` | Repository and pull statistics |
| `GET`, `POST` | `/v2/auth` | Get a Bearer token (GET with query or OAuth2 POST form, as containerd does) |
| `GET` | `/v2/_catalog` | List repositories |
| `GET` | `/v2/<name>/tags/list` | List tags |
| `HEAD` | `/v2/<name>/manifests/<ref>` | Check whether a manifest exists |
| `GET` | `/v2/<name>/manifests/<ref>` | Get a manifest |
| `PUT` | `/v2/<name>/manifests/<ref>` | Upload a manifest |
| `DELETE` | `/v2/<name>/manifests/<ref>` | Delete: by tag — only that tag, by digest — the manifest and all tags pointing to it |
| `HEAD` | `/v2/<name>/blobs/<digest>` | Check whether a blob exists |
| `GET` | `/v2/<name>/blobs/<digest>` | Download a blob (with Range support) |
| `DELETE` | `/v2/<name>/blobs/<digest>` | Unlink a blob from the repository; GC removes the data once no tagged image needs it |
| `POST` | `/v2/<name>/blobs/uploads/` | Start an upload |
| `GET` | `/v2/<name>/blobs/uploads/<uuid>` | Upload status |
| `PATCH` | `/v2/<name>/blobs/uploads/<uuid>` | Upload a chunk |
| `PUT` | `/v2/<name>/blobs/uploads/<uuid>` | Complete an upload |
| `DELETE` | `/v2/<name>/blobs/uploads/<uuid>` | Cancel an upload |

The `?n=<int>&last=<string>` parameters are supported for pagination in `/v2/_catalog` and `/v2/<name>/tags/list`.

### GET /ui

The registry web UI. Open it in a browser:

```
https://registry.example.com/ui
```

Features:
- Registry version — at the bottom of every page and on the sign-in form (and in the `/healthz` response: `{"status":"ok","version":"v1.9.1"}`)
- Russian and English UI: the language is taken from the browser, can be switched in the header and on the sign-in form, and is remembered
- Password change (the "Change password" button in the header) for any user. The new password is stored as a bcrypt hash in `<RGSTR_STORAGE>/users.json` and also applies to `docker login`
- Sign in with the same users as for `docker login`. The sign-in form is submitted the regular way (`POST /ui/login`), so the browser offers to save the username and password, and after a password change, to update it. Only the session token is stored in the browser, not the password
- The session is shared by all tabs and survives a browser restart; it lives for `RGSTR_SESSION_TTL` (12 hours) and is extended while the web admin is open. Signing out ends the session on the server (its token no longer works) and in all tabs. A password change or reset ends the user's other sessions
- With `RGSTR_AUTH_ENABLED=false` the sign-in form is not shown
- Statistics: number of repositories and pulls
- List of repositories with tags: digest, size, platforms. For multi-arch images all platforms are shown with the size of each; attestation manifests are skipped
- Repository search (case-insensitive)
- Deletion (buttons are visible only to users with delete permission):
  - **a tag** — only this tag is deleted, other tags of the same image remain;
  - **several tags** — checkboxes on tags and "Delete selected";
  - **an image** — the image and all tags pointing to it;
  - **a repository** — all tags of the repository; to confirm, you must type its name. Nested repositories (`team/app` when deleting `team`) are not affected.

  Deletion removes tags and manifests immediately — the image can no longer be pulled — while disk space is freed by garbage collection (GC). An administrator can check "Free the disk space now" in the confirmation: GC then runs right away only for the deleted data (the grace period is lifted only for it; uploads in progress at that moment are not affected), and the notification shows how much was freed. Without this checkbox, the space is freed by the next scheduled GC; data pushed within the grace period (`RGSTR_UPLOAD_TTL`) — after it ends
- The repository name can be selected and copied; the "Copy" button copies the full `host/repo` path. Copying works without HTTPS too
- Disk (for administrators): on the repositories page — free space out of the total and how much the registry data takes; on the garbage collection page — also how much the next GC will free, how much will be freed after the grace period, and the list of deleted items awaiting GC (repository / tag / image, who deleted it and when, size). When free space is below 10%, administrators see a warning on all pages
- Garbage collection (the "Garbage collection" page, administrators only):
  - schedule: off, every 1/6/12/24 hours, weekly, or a custom value. Saved in `/data/meta.json`, takes effect immediately without a restart, and takes precedence over `RGSTR_GC_INTERVAL`; a button restores the value from env;
  - manual run, including a dry run — shows what will be freed and how much space, without deleting anything;
  - "no grace period" mode — immediately frees space from just-deleted data, but can break a push in progress at that moment;
  - history of the last 30 runs: who started it, how much was freed, the space of which deleted repositories, tags and images was freed, which untagged images were removed
- Policies (the "Policies" page, administrators only):
  - **tag retention** — a rule sets a repository pattern (`team/**`), a tag pattern (`*`, `dev-*`) and what to keep: the N most recent by push time and/or those pushed in the last N days. A tag is deleted only if no matching rule keeps it. Rules are applied before each scheduled GC, manually, or as a dry run; run history is kept. If scheduled GC is off, rules are applied only manually;
  - **immutable tags** — a matching tag cannot be overwritten with another image and cannot be deleted: not by `docker push` (error `tag is immutable`), not through the web admin, not by a retention policy. A new tag matching the pattern can be pushed. Such tags are marked 🔒 in the repository list
- Image details — click a tag: `docker pull` commands by tag and by digest with a copy button, all tags of the image, size; for multi-arch images — platform switching; configuration (entrypoint, cmd, working directory, user, ports, volumes, environment variables, labels); build steps with `RUN`/`COPY`/… commands and the size of each layer; the raw manifest
- Audit log (the "Audit log" page, administrators only): who, when and from which IP pushed, pulled (downloaded a manifest), deleted a tag, image or repository, signed in to the web admin, entered a wrong password (in the web admin or on `docker login`), changed a password, changed users, policies or the GC schedule, ran GC or retention policies (scheduled runs are attributed to `system`). Filters by user, action and text. Stored in `<RGSTR_STORAGE>/audit.log` (one JSON line per event); at 10 MB the file is renamed to `audit.log.1`, so there is no more than ~20 MB of log on disk

Without TLS, the username and password are sent in plain text at sign-in — for external access, set up [TLS](#tls) or a reverse proxy.

The UI gets its data in a single request:

| Method | Path | Description |
|---|---|---|
| `GET` | `/ui/api/me` | Whether authentication is enabled, the current user and their permissions |
| `POST` | `/ui/api/login` | `{"username","password"}` → `{"token","user","admin"}` (for scripts) |
| `POST` | `/ui/login`, `/ui/password` | Web admin sign-in and password change forms (redirect back to `/ui`) |
| `GET` | `/ui/api/repos` | Repositories with tags, digests, sizes, platforms and push time |
| `POST` | `/ui/api/tags/delete` | `{"repo","tags":[…],"free_space"}` — delete tags, result per tag |
| `POST` | `/ui/api/images/delete` | `{"repo","digest","free_space"}` — delete an image with all its tags |
| `POST` | `/ui/api/repos/delete` | `{"repo","free_space"}` — delete a repository |
| `GET` | `/ui/api/disk` | Disk space (administrator); `?data=1` — also the registry data size; `?details=1` — also the GC estimate and the pending list |
| `GET` | `/ui/api/gc` | GC schedule and run history (administrator) |
| `POST` | `/ui/api/gc/run` | `{"dry_run","ignore_grace"}` — run GC (administrator) |
| `GET` | `/ui/api/backup` | Backup settings, status and list (administrator) |
| `POST` | `/ui/api/backup/run` | Start a backup now, responds `202` (administrator) |
| `POST` | `/ui/api/cli-secret` | New CLI secret for docker login (LDAP and SSO users) |
| `GET` | `/ui/api/scan?repo=&ref=` | Vulnerability summary and findings of an image (`&platform=` for one platform of an index) |
| `POST` | `/ui/api/scan/run` | `{"repo","digest"}` — scan now (users who may push) |
| `GET` | `/ui/api/policies` | Retention and immutability rules, run history (administrator) |
| `POST` | `/ui/api/policies/retention` | `{"rules":[{"repos","tags","keep_last","keep_days","disabled"}]}` — replace retention rules |
| `POST` | `/ui/api/policies/retention/run` | `{"dry_run"}` — apply retention rules now |
| `POST` | `/ui/api/policies/immutable` | `{"rules":[{"repos","tags","disabled"}]}` — replace immutability rules |
| `GET` | `/ui/api/users` | Users (administrator) |
| `POST` | `/ui/api/users/create` | `{"name","role","password","must_change"}` |
| `POST` | `/ui/api/users/role` | `{"name","role"}` — for users created in the web admin |
| `POST` | `/ui/api/users/password` | `{"name","password","must_change"}` — password reset |
| `POST` | `/ui/api/users/delete` | `{"name"}` — for users created in the web admin |
| `GET` | `/ui/api/image` | `?repo=&ref=` — image details: platforms, configuration, layers |
| `GET` | `/ui/api/projects` | Projects visible to the user |
| `GET` | `/ui/api/project` | `?name=` — a project: settings, members, repositories |
| `POST` | `/ui/api/projects/create` | `{"name","description","public","quota_bytes"}` (administrator) |
| `POST` | `/ui/api/projects/update` | `{"name","description","public","quota_bytes"}` (project admin; quota — administrator) |
| `POST` | `/ui/api/projects/member` | `{"name","user","role"}`; empty role — remove the member (project admin) |
| `POST` | `/ui/api/projects/grant` | `{"name","user","repos","role"}` — a role on repositories of the project matching `repos`; an empty role removes the rule (project admins) |
| `POST` | `/ui/api/projects/delete` | `{"name"}` — empty project only (administrator) |
| `GET` | `/ui/api/robots` | Robot accounts (administrator) |
| `POST` | `/ui/api/robots/create` | `{"name","description","permissions":[{"project","actions"}],"expires_days"}` → `{"name","secret"}` |
| `POST` | `/ui/api/robots/update` | `{"name","description","permissions","expires_days","disabled"}` |
| `POST` | `/ui/api/robots/secret` | `{"name"}` → new `{"secret"}` |
| `POST` | `/ui/api/robots/delete` | `{"name"}` |
| `GET` | `/ui/api/webhooks` | Webhooks the user can manage, and their recent deliveries |
| `POST` | `/ui/api/webhooks/save` | `{"id","name","url","project","events","format","auth_header","skip_verify","disabled"}`; without `id` — create |
| `POST` | `/ui/api/webhooks/delete` | `{"id"}` |
| `POST` | `/ui/api/webhooks/test` | `{"id"}` — send a test event |
| `GET` | `/ui/api/audit` | Audit log: `?user=&action=&q=&before=&limit=` (administrator) |
| `POST` | `/ui/api/gc/settings` | `{"interval":"6h"}` — schedule; `"0"` — off, `""` — value from env (administrator) |

---

### GET /stats

Returns the list of repositories, their tags and pull counts.

With `RGSTR_AUTH_ENABLED=true` it requires Basic auth (the same users as for the registry) or a Bearer token with catalog access.

```bash
curl https://registry.example.com/stats
# With authentication:
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

Pull counters are persisted in `stats.json` in the storage directory and survive restarts.

---

## Storage layout

```
<RGSTR_STORAGE>/                    # or an S3 bucket (RGSTR_STORAGE_S3_*): the same paths are object keys
├── blobs/
│   └── sha256/
│       └── <2 hex>/<62 hex>        # blob content (addressed by digest)
├── uploads/
│   └── <uuid>/
│       ├── chunk-<offset>          # chunks of an unfinished upload, one per PATCH
│       └── info.json               # uuid, repo, offset, started_at, sha256 state
├── repositories/
│   └── <namespace>/<repo>/
│       ├── manifests/
│       │   ├── by-digest/<hex>     # manifest content + content-type
│       │   └── tags/<tag>          # hex digest of the tag (pointer)
│       └── layers/
│           └── <hex>               # empty marker: the blob belongs to the repository
├── users.json                      # users from the web admin and changed passwords (bcrypt)
├── meta.json                       # projects, robots, policies, webhooks, settings, sessions, GC history
├── audit.log, audit.log.1          # audit log (one JSON line per event), rotated at 10 MB
├── stats.json                      # pull counters
└── .rgstr.lock                     # lock: one process per directory
```

In [cluster mode](#cluster-ha), `users.json`, `meta.json`, the audit log and the counters
are stored in PostgreSQL (tables `rgstr_docs`, `rgstr_audit`, `rgstr_pulls`,
`rgstr_jobs`) rather than in files; there is no directory lock.

An upload started on one process continues on any other: each chunk is
saved separately together with the sha256 state, and on completion the chunks
are joined into a blob (in S3, by a server-side copy).

Deduplication works automatically: if two repositories contain the same layer, it is stored on disk once.

Despite the shared storage, each repository serves only "its own" blobs — those uploaded to it, mounted into it, or referenced by its manifests (markers in `layers/`). Requesting another repository's blob by digest returns `404`, so a private repository's layer cannot be downloaded through a public one.

---

## Building and testing

Requires Go 1.26+.

```bash
make build      # build
make test       # unit and integration tests
make cover      # with coverage
make clean
```

Cluster tests run against real PostgreSQL and S3 and run only when
their addresses are set (this is how CI runs them):

```bash
docker run -d -p 5432:5432 -e POSTGRES_PASSWORD=pw -e POSTGRES_DB=rgstr postgres:16-alpine
# S3: SeaweedFS (or MinIO) with an rgstr-test bucket and keys
RGSTR_TEST_DATABASE_URL='postgres://postgres:pw@localhost:5432/rgstr?sslmode=disable' \
RGSTR_TEST_S3=http://localhost:9000 RGSTR_TEST_S3_KEY=… RGSTR_TEST_S3_SECRET=… \
  go test ./internal/db ./internal/storage ./internal/backup ./test/ha
```

`test/ha` starts three rgstr processes under push and pull load and kills them
one by one with `kill -9` (`RGSTR_TEST_HA_DURATION`, 40 s by default); images
are verified by digest.

---

## Releases (CI/CD)

The build is configured in `.github/workflows/`:

- `ci.yml` — on every push to `main` and every pull request: `go vet`, govulncheck (vulnerabilities in called code), tests; the `cluster` job runs the cluster tests on PostgreSQL and SeaweedFS (S3), including the `test/ha` load test;
- `release.yml` — build and publish:
  - push to `main` → image `ghcr.io/piqab/rgstr:main`;
  - tag `v*` → a GitHub Release with the binaries `rgstr-linux-{amd64,arm64}`, `mkpasswd-linux-{amd64,arm64}` and the archives `rgstr-<version>-linux-{amd64,arm64}.tar.gz` (each file has a `.sha256`) and the image `:<version>`, `:<major>.<minor>`, `:latest`.

The version is stored in the `VERSION` file (for example, `1.0.0`). It is also embedded into the binary by `make build`. To cut a release:

```bash
# 1. bump the version in VERSION and commit
# 2. push main and create a tag from the file
git push origin main
git tag v$(cat VERSION) && git push origin v$(cat VERSION)
```

If the tag does not match `v$(cat VERSION)`, the release build fails with an error.

The image is published using the built-in `GITHUB_TOKEN`; no additional secrets are needed. After the first publish, the GHCR package is private by default — for `docker pull` to work without login, open **Packages → rgstr → Package settings → Change visibility → Public**.

---

## Architecture

```
main.go, cli.go     — server startup; backup, backups, restore, migrate, version commands
internal/
├── config/    — configuration from environment variables
├── registry/  — registry HTTP API (/v2), routing, /healthz, /readyz, /stats
├── storage/   — content-addressable storage: blobs, uploads, manifests, GC
│                on top of a driver: filesystem or S3
├── s3/        — S3 client (SigV4 signing, multipart, copy, presigned URLs)
├── db/        — cluster PostgreSQL: shared documents, audit log, counters,
│                GC lock, claiming scheduled jobs
├── auth/      — tokens (JWT), users and roles, sessions, LDAP, OIDC, robots
├── meta/      — web admin metadata: projects, policies, webhooks, settings
├── ops/       — web admin operations (deletion, retention) with audit log and webhooks
├── maint/     — GC and retention scheduling
├── policy/    — tag retention rules and immutable tags
├── backup/    — scheduled backups and restore (single-process mode)
├── audit/     — audit log
├── stats/     — pull counters
├── metrics/   — Prometheus metrics
├── webhook/   — event notifications
├── glob/      — repository patterns
└── ui/        — web admin (embedded JS SPA) and its API
```

### Locking model

| Lock | Type | Protects |
|---|---|---|
| `gcMu` | `sync.RWMutex` | Process operations hold RLock; GC holds Lock — prevents GC from racing with writes |
| GC lock in PostgreSQL | advisory lock | In the cluster: a write that makes data reachable (manifest, blob-to-repository link, upload completion) holds it shared, GC holds it exclusive, across all processes at once |
| `blobMu[digest]` | `sync.Map[*sync.Mutex]` | Concurrent writes of the same blob — only the first goroutine writes, the others see the finished file |
| `uploadMu[uuid]` | `sync.Map[*sync.Mutex]` | Concurrent PATCH chunks of one session — serializes offset writes |
| Document row in PostgreSQL | `SELECT … FOR UPDATE` | In the cluster: changes to users and metadata are applied to the latest version, nothing is lost |
| `.rgstr.lock` | `flock` | Single-process mode: a second process on the same directory will not start |

All writes are atomic: on disk — write to a temporary file and `os.Rename`; in S3 —
an object appears only as a whole. Readers never see a partially
written file.

---

## License

[MIT](LICENSE)
