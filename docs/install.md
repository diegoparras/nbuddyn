# Installing nbuddyn

**English** · [Español](install.es.md) · [Português](install.pt.md)

Ten minutes, start to finish. nbuddyn is one small container that runs next to your n8n.

- [Before you start](#before-you-start)
- [1. Create a read-only user (Postgres only)](#1-create-a-read-only-user-postgres-only)
- [2. Run it](#2-run-it): [Docker](#docker) · [Docker Compose](#docker-compose) · [Easypanel](#easypanel) · [Other panels](#other-panels) · [From source](#from-source)
- [3. First look](#3-first-look)
- [Updating](#updating)
- [If something goes wrong](#if-something-goes-wrong)

Just want to look around first? `docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo`
starts a made-up n8n. Sign in as `demo` / `demo`.

## Before you start

nbuddyn is made for **n8n 3 and later**.

You need to know one thing: **which database your n8n uses.**

- If you never set one up, it is **SQLite**: a file called `database.sqlite` inside n8n's data folder.
- If your n8n has `DB_TYPE=postgresdb` in its settings, it is **Postgres**.

nbuddyn must be able to reach that database, so run it on the same server (and the same
Docker network) as n8n.

## 1. Create a read-only user (Postgres only)

Skip this step if your n8n uses SQLite.

Connect to n8n's database with any SQL tool and run this once. Change the password, and
use only letters and numbers so it needs no escaping later:

```sql
CREATE ROLE nbuddyn LOGIN PASSWORD 'choose-a-password';
GRANT SELECT (id, name, active, "isArchived", nodes, settings) ON workflow_entity TO nbuddyn;
GRANT SELECT (id, name, type) ON credentials_entity TO nbuddyn;
GRANT SELECT (id, "workflowId", status, "startedAt", "createdAt", "deletedAt") ON execution_entity TO nbuddyn;
GRANT SELECT (disabled, "mfaEnabled") ON "user" TO nbuddyn;
```

This user can read only the columns nbuddyn needs. It cannot read stored credentials,
password hashes or execution data, and it cannot write anything.

Optional, for two extras (who saved each workflow, and how long executions took):

```sql
GRANT SELECT ("versionId") ON workflow_entity TO nbuddyn;
GRANT SELECT ("versionId", authors) ON workflow_history TO nbuddyn;
GRANT SELECT ("stoppedAt") ON execution_entity TO nbuddyn;
```

## 2. Run it

Every way of running nbuddyn needs the same three things:

| What | Value |
|---|---|
| The image | `ghcr.io/diegoparras/nbuddyn:latest` |
| The port | `8787` |
| A volume at | `/data` (history, settings and users live there) |

And these settings:

| Variable | What to put |
|---|---|
| `NBUDDYN_DATABASE_URL` | Postgres: `postgres://nbuddyn:choose-a-password@HOST:5432/n8n`<br>SQLite: `sqlite:/n8n/database.sqlite` |
| `NBUDDYN_PASSWORD` | The password you will sign in to nbuddyn with. |
| `NBUDDYN_SECRET_KEY` | Recommended. 32 characters or more; it encrypts the secrets nbuddyn stores. Make one with `openssl rand -hex 32` and keep it. |
| `NBUDDYN_LANG` | Optional. `en`, `es` or `pt`. |

Everything else (n8n's address, Redis, task runners, alerts, more n8n instances) is set
later on the page. The [reference](reference.md#every-setting) lists every variable.

### Docker

Postgres:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  --network NETWORK_OF_YOUR_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  -e NBUDDYN_SECRET_KEY=paste-the-long-random-key-here \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_postgres` is the name of your Postgres container. `docker network ls` shows your
networks, and `docker inspect n8n_postgres` shows which one it is on.

SQLite:

```bash
docker run -d --name nbuddyn --restart unless-stopped -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  -e NBUDDYN_SECRET_KEY=paste-the-long-random-key-here \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_data` is the volume your n8n mounts at `/home/node/.n8n`. The `:ro` makes it
read-only: nbuddyn could not change n8n's files even if it wanted to.

### Docker Compose

Two ready-made files are in [`deploy/`](../deploy):

- [`compose.postgres.yml`](../deploy/compose.postgres.yml)
- [`compose.sqlite.yml`](../deploy/compose.sqlite.yml)

Download the one that fits, change the passwords inside, and start it:

```bash
docker compose -f compose.postgres.yml up -d
```

To add nbuddyn to the compose file your n8n already has, copy the `nbuddyn` service and
the `nbuddyn_data` volume into it. It then shares n8n's network without anything else.

### Easypanel

1. Open the project your n8n is in and press **+ Service → App**. Name it `nbuddyn`.
2. **Source → Docker Image.** Image: `ghcr.io/diegoparras/nbuddyn:latest`. Save.
3. **Environment.** Paste this, with your own values, and save:

   ```
   NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@PROJECT_SERVICE:5432/n8n
   NBUDDYN_PASSWORD=choose-a-login-password
   NBUDDYN_SECRET_KEY=paste-the-long-random-key-here
   NBUDDYN_LANG=en
   ```

   Inside Easypanel a service is reached as `project_service`. If the project is `acme`
   and the Postgres service is `n8n-db`, the host is `acme_n8n-db`.
4. **Mounts → Add Volume Mount.** Name `data`, mount path `/data`.
5. **Domains.** Add a domain (or use the one Easypanel offers) and set the port to `8787`.
6. Press **Deploy**. Open the domain and sign in as `nbuddyn`.

To create the read-only user from step 1, open the Postgres service in Easypanel, open
its console, run `psql -U postgres -d n8n` and paste the SQL.

**If your n8n on Easypanel uses SQLite**, nbuddyn has to see n8n's data folder. In
nbuddyn's service go to **Mounts → Add Bind Mount**:

- Host path: `/var/lib/docker/volumes/PROJECT_SERVICE_VOLUME/_data`
- Mount path: `/n8n`

`PROJECT_SERVICE_VOLUME` is n8n's project, service and volume names joined with `_`: for
project `acme`, service `n8n` and volume `data`, it is `acme_n8n_data`. Then set
`NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite` and deploy.

### Other panels

Portainer, Coolify, Dokploy, CapRover, Dockge and the rest all run a Docker image, and
nbuddyn needs nothing special. Whatever the panel calls them, fill in:

- **Image:** `ghcr.io/diegoparras/nbuddyn:latest`
- **Port:** `8787`
- **Persistent volume:** at `/data`
- **Environment variables:** the table in [Run it](#2-run-it)
- **Network:** the same one as n8n's database

A health check, if the panel asks for one: `GET /healthz` on port 8787.

These panels have not been tested one by one. If yours needs something different, please
[open an issue](https://github.com/diegoparras/nbuddyn/issues).

### From source

With [Rust](https://rustup.rs) installed:

```bash
git clone https://github.com/diegoparras/nbuddyn
```

```bash
cd nbuddyn && cargo build --release
```

```bash
NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@localhost:5432/n8n \
NBUDDYN_PASSWORD=choose-a-login-password \
NBUDDYN_DATA_DIR=./data \
./target/release/nbuddyn
```

Or build the image yourself: `docker build -t nbuddyn .`

## 3. First look

Sign in as `nbuddyn` with the password you chose. The first scan takes a few seconds.
Then open the menu (top right) and go to **Settings**:

1. **n8n's address.** Where you open n8n in the browser. Every finding then links to its workflow.
2. **n8n's Redis**, if your n8n runs in queue mode. This turns on the queue and worker checks. Workers and webhook processors are found by themselves.
3. **Task runners**, one per line, if you run them as separate containers.
4. **Alerts.** A Telegram bot or a webhook, with a button to send a test.

Put nbuddyn behind https before opening it to the internet: its report lists your weak points.

## Updating

Pull the new image and start the container again. Your history and settings are in the
`/data` volume and stay.

```bash
docker pull ghcr.io/diegoparras/nbuddyn:latest
```

```bash
docker compose up -d
```

On Easypanel, press **Deploy** again. To stay on a version you chose, use a tag such as
`ghcr.io/diegoparras/nbuddyn:0.19.0` instead of `latest`.

After updating **n8n**, check that nbuddyn can still read it:

```bash
docker run --rm --network NETWORK_OF_YOUR_N8N \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@n8n_postgres:5432/n8n \
  ghcr.io/diegoparras/nbuddyn:latest check
```

## If something goes wrong

| What you see | What to do |
|---|---|
| The container stops right away | Read its log. nbuddyn says which setting is missing or wrong. |
| It cannot connect to the database | nbuddyn and the database are not on the same network, or the host name is wrong. |
| Permission denied on a table | A `GRANT` from step 1 is missing. `nbuddyn check` prints the exact one to run. |
| SQLite: "can only be read this way while n8n is running" | Start n8n. The file can be read only while n8n is running. |
| Settings cannot be saved | No volume is mounted at `/data`. |
| The cluster page is empty | n8n's Redis is not set in Settings, or your n8n is not in queue mode. |

Still stuck? [Open an issue](https://github.com/diegoparras/nbuddyn/issues) with the
log. Take passwords out first.
