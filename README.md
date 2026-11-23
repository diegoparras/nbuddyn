<div align="center">

<img src="docs/img/logo.svg" width="88" alt="nbuddyn">

# nbuddyn

**The cockpit your self-hosted n8n is missing.**<br>
Open doors, silent failures and what is about to break, on one page. Read-only, tiny, and yours.

**English** · [Español](README.es.md) · [Português](README.pt.md)

[![CI](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml/badge.svg)](https://github.com/diegoparras/nbuddyn/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/diegoparras/nbuddyn?color=F5B83D)](https://github.com/diegoparras/nbuddyn/releases)
[![License: MIT](https://img.shields.io/badge/license-MIT-F5B83D.svg)](LICENSE)
![Platforms](https://img.shields.io/badge/image-amd64%20%7C%20arm64-555)
![Built with Rust](https://img.shields.io/badge/built%20with-Rust-555)

<a href="docs/img/tour.mp4"><img src="docs/img/tour.gif" width="820" alt="A one-minute tour of nbuddyn"></a>

<sub>A one-minute tour, recorded on the built-in demo. All the data shown is made up.</sub>

</div>

> [!IMPORTANT]
> nbuddyn is an independent, community project. It is **not affiliated with, endorsed by or sponsored by n8n GmbH**.
> It contains no n8n code and does not unlock or bypass any licensed n8n feature. See [Not affiliated with n8n](#not-affiliated-with-n8n).

## Why

n8n is very good at running workflows. It is quieter about governing them: which
webhooks anyone can call, which workflows fail with nobody told, where a key was pasted
into a node, whether the workers are alive.

nbuddyn sits next to your n8n, reads its database and its Redis, and answers those
questions with one score and a list of what to do first.

- **Read-only.** It switches its database session to read-only before the first query. It cannot change your n8n.
- **Tiny.** One static binary written in Rust. The image is a few MB and a typical instance uses under 30 MB of memory.
- **Private.** No telemetry, no account, no cloud. Nothing leaves your server unless you set up alerts.
- **Three languages.** English, Spanish and Portuguese, switchable on the page.

## Try it in 30 seconds

No n8n needed. This starts nbuddyn against a made-up n8n with the problems real ones have:

```bash
docker run --rm -p 8787:8787 ghcr.io/diegoparras/nbuddyn:latest demo
```

Open <http://localhost:8787> and sign in as `demo` / `demo`.

## What you get

| | |
|---|---|
| [![Overview](docs/img/overview.png)](docs/img/overview.png) **Overview.** One score, six lights, and what to do first. | [![Findings](docs/img/findings.png)](docs/img/findings.png) **Findings.** Each one says what to do, how sure nbuddyn is, and links to the workflow. |
| [![Cluster](docs/img/cluster.png)](docs/img/cluster.png) **Cluster.** The queue, workers, webhook processors, task runners and Redis. | [![Activity](docs/img/activity.png)](docs/img/activity.png) **Activity.** What changed between scans, and who saved it. |
| [![History](docs/img/history.png)](docs/img/history.png) **History.** Executions and score per day, kept even after n8n deletes them. | [![Credentials](docs/img/credentials.png)](docs/img/credentials.png) **Credentials.** Which workflows would break if you rotated one. Never the secret. |

<sub>Screenshots taken on the built-in demo. All the data shown is made up.</sub>

**What it checks**

- **Open doors:** MCP servers, chats, webhooks and forms without authentication.
- **Silent failures:** workflows that keep failing, executions stuck for hours, active workflows with no error workflow, workflows that stopped running.
- **Secrets:** keys written inside nodes (reported by kind, never by value), unencrypted calls, users without two-factor.
- **Queue and cluster:** no workers, mixed n8n versions, a queue piling up, Redis about to drop jobs, task runners not answering.
- **Housekeeping:** nodes removed in n8n 3, unused credentials, nodes that run system commands.

**What else it does**

- **Alerts** to Telegram or any webhook (Slack works as is) when something changes, never the whole report again.
- **Several n8n** from one nbuddyn: production and staging, or one per client.
- **Your rules:** set how severe each check is here, accept a finding with a reason, make acceptances expire.
- **Users, roles and single sign-on** (OpenID Connect), with an audit log.
- **An MCP endpoint**, so an AI assistant can ask about your n8n in plain words. Read-only too.

The full list is in the [reference](docs/reference.md).

## Install

You need two things: where n8n's database is, and a password for nbuddyn's own login.

**Your n8n uses Postgres.** Create a read-only user once (the SQL is in the
[guide](docs/install.md#1-create-a-read-only-user-postgres-only)), then:

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

**Your n8n uses SQLite** (the default when n8n is given no database):

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  ghcr.io/diegoparras/nbuddyn:latest
```

Open <http://localhost:8787> and sign in as `nbuddyn`. Everything else is set on the page, under **Settings**.

Step-by-step guides:

| | |
|---|---|
| [Docker](docs/install.md#docker) | One command, as above. |
| [Docker Compose](docs/install.md#docker-compose) | Ready-made files in [`deploy/`](deploy). |
| [Easypanel](docs/install.md#easypanel) | Click by click. |
| [Portainer, Coolify, Dokploy and others](docs/install.md#other-panels) | Anything that runs a Docker image. |
| [From source](docs/install.md#from-source) | `cargo build --release`. |

## Is it safe to put next to production?

- It **only reads**. With Postgres, give it a user that can read just the columns it needs: it cannot read stored credentials, password hashes or execution data.
- It runs as an unprivileged user in an image that holds one binary and nothing else: no shell, no package manager.
- The secrets it stores (database and Redis passwords, the Telegram token) are encrypted on disk.
- Images are signed and carry a bill of materials. How to verify one is in [SECURITY.md](SECURITY.md).
- The [threat model](docs/THREAT-MODEL.md) lists what protects each way in and what is knowingly left open.

No independent security audit has been done yet.

## What it does not do

nbuddyn watches; it does not fix or block. It never writes to n8n, so it cannot
deactivate a risky workflow for you. It does not look inside executions or credentials,
and it does not review what a workflow does with its data. The score sums up what it can
see. It is a radar, not an audit.

## Compatibility

nbuddyn is made for **n8n 3 and later**. Every change is tested against a real n8n 3.3,
on SQLite and on Postgres. It is also run against n8n 1.123 and 2.48, but those are not
what it is built for, and some checks (workers, webhook processors) need n8n 3. nbuddyn reads n8n's own database, which n8n may change between versions; after
updating n8n, `nbuddyn check` tells you whether everything can still be read.

## Documentation

- [Installation guide](docs/install.md)
- [Reference](docs/reference.md): every check, every setting, alerts, single sign-on, MCP
- [Security policy](SECURITY.md) and [threat model](docs/THREAT-MODEL.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)

## Not affiliated with n8n

nbuddyn is an independent open-source project. It is not affiliated with, endorsed by,
sponsored by or supported by n8n GmbH. "n8n" is a trademark of n8n GmbH and is used here
only to say what nbuddyn works with.

nbuddyn contains no n8n code. It does not modify n8n, and it does not unlock or bypass
any feature of n8n's paid plans: it turns nothing on inside n8n. It reads the database
and Redis of an n8n you host yourself, with the access you give it.

Some of what nbuddyn shows resembles things n8n offers in its paid plans, such as the
worker view, a longer history of executions, and audit events. nbuddyn builds its own,
simpler view from the outside and is not a substitute for them. If you need those
features inside n8n, with n8n's support behind them, get them from n8n.

For help with n8n itself, go to [n8n's own channels](https://n8n.io).

## License

[MIT](LICENSE). Free to use, change and share, at home or at work. The libraries nbuddyn
is built with keep their own open-source licenses.
