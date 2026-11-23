# Reference

Everything nbuddyn does and every setting it takes. To get it running, see the
[installation guide](install.md). This page is in English only.

nbuddyn is an independent project. It is not affiliated with or endorsed by n8n GmbH.

## What it checks

| Severity | Check |
|---|---|
| High | Active MCP servers and public chats without authentication |
| High | Workflows failing repeatedly (5 or more errors in 7 days) |
| High | Executions stuck for over an hour |
| High / Medium | Secrets written inside nodes (reported by kind, never by value) |
| Medium | Active webhooks and forms without authentication |
| Medium | Active workflows without an error workflow |
| Medium | Active workflows that used to run most days and stopped (needs the history) |
| Medium | Unencrypted `http://` calls to external hosts |
| Medium | Users without two-factor authentication |
| Medium / Low | Nodes removed in n8n 3 that are still present |
| Low | Nodes reading server environment variables |
| Low | Credentials no workflow uses |
| Info | Nodes that run system commands |

With Redis configured, it also watches the queue and the cluster:

| Severity | Check |
|---|---|
| High | No worker is running |
| High | The main n8n process is not running |
| High | Main, workers and webhook processors on different n8n versions |
| High | Redis almost out of memory (80% of its limit or more) |
| High / Medium | Executions piling up in the queue (100 waiting, urgent from 1000) |
| High / Medium | Redis may drop queue jobs: an eviction policy other than `noeviction` (urgent once it has evicted keys) |

The page then shows how many executions are waiting and running, how many workers and
webhook processors are alive, and Redis' memory. Workers are found through the registry
n8n 3 keeps in Redis, so there is nothing to list by hand; on older n8n versions the
member counts stay at zero and the worker check is skipped.

With the task runners listed, it asks each one whether it is alive:

| Severity | Check |
|---|---|
| High | A task runner is not answering its health check |

n8n keeps no record of external task runners in its database or in Redis, so nbuddyn
asks them directly. Each runner container already answers `GET /healthz` on port 5680
for this purpose.

## Its own history

n8n deletes old executions, and can be told not to save the successful ones at all.
nbuddyn counts every execution once as it finishes and keeps the totals: per day and
per workflow, how many succeeded, failed or were canceled, plus the score of each day.
The page shows the last 7, 30 or 90 days. On its first scan nbuddyn counts whatever
n8n still has, so the history does not start empty.

With one more grant on Postgres, the history also keeps how long executions took, and the
page shows each workflow's average and slowest run:

```sql
GRANT SELECT ("stoppedAt") ON execution_entity TO nbuddyn;
```

nbuddyn shows which n8n version is running. With Redis configured the processes say it
themselves; otherwise it comes from a table where n8n writes its version, which on
Postgres takes one more grant:

```sql
GRANT SELECT ON instance_version_history TO nbuddyn;
```

Every number opens. Click a day to see which workflows ran on it, the ones that failed
first. Click a workflow to see its own days, and pick a day there to list its executions:
when each started, how it ended, how long it took, and a link that opens it in n8n. That
list is read from n8n at that moment and only covers what n8n still keeps; nbuddyn keeps
the totals, not the executions, and never reads what went through them.

The history can be downloaded as a spreadsheet (CSV) from the History page, and as a
backup file from Settings.

Only totals are kept, in one small JSON file. No execution data is read or stored.
A workflow that was deleted stays in the history under its last known name.

## Alerts

nbuddyn alerts when something changes, never about the whole report:

- a finding appears at or above the level you choose (urgent only, or urgent and important);
- one of those goes away;
- an n8n cannot be read for three scans in a row, and when it can again;
- optionally, workflows that were created, edited, activated, deactivated or deleted.

The same finding never alerts twice within six hours. Alerts go to a **Telegram** chat
(a bot token from @BotFather and a chat id) and to any **webhook** that takes a JSON
POST: a Slack incoming webhook works as is, and so does an n8n webhook. Both are set in
**Settings**, where a button sends a test message.

## Users and security

nbuddyn has its own login page. The administrator in `NBUDDYN_USER` and `NBUDDYN_PASSWORD`
always exists; more users are added in **Settings** with one of two roles:

- **Administrator**: accepts findings, changes settings, manages instances and users.
- **Read only**: sees the reports and nothing that changes anything.

What protects the login and the page:

- Passwords of added users are stored only as salted PBKDF2-HMAC-SHA256 hashes
  (310,000 rounds), never in the clear.
- After five wrong passwords in a row a name has to wait, longer each time, up to 15 minutes.
- Sessions live in a cookie the page's scripts cannot read (`HttpOnly`, `SameSite=Strict`,
  and `Secure` behind https) and end after 12 hours or on sign out.
- Every response carries a strict Content-Security-Policy that only allows the script and
  styles shipped inside the page, plus the usual hardening headers; reports are never cached.
- Anything that changes state needs a header another site cannot send, and an administrator.
- An **audit log** in Settings records sign-ins, failed sign-ins, accepted findings, and
  changes to settings, instances and users, with who did each.

- **Secrets at rest are sealed.** The database and Redis passwords of instances added on
  the page, the Telegram token and the webhook address are encrypted with
  ChaCha20-Poly1305 before they are written. Set `NBUDDYN_SECRET_KEY` (32 characters or
  more) to keep the key out of the data directory; without it nbuddyn makes one and keeps
  it there in a file only it can read.

Scripts can still send a name and password with HTTP Basic on every API request.

### Signing in with your company's accounts (single sign-on)

nbuddyn speaks OpenID Connect, which Google, Microsoft Entra, Okta and Keycloak all
offer. People sign in at the provider; nbuddyn never sees a password. Register nbuddyn
there as a web application with the redirect address
`https://your-nbuddyn-host/auth/oidc/callback`, then set:

| Variable | Meaning |
|---|---|
| `NBUDDYN_OIDC_ISSUER` | The provider's address, such as `https://accounts.google.com`. Turns single sign-on on. |
| `NBUDDYN_OIDC_CLIENT_ID`, `NBUDDYN_OIDC_CLIENT_SECRET` | What the provider gave the application. |
| `NBUDDYN_PUBLIC_URL` | The https address people open nbuddyn at. |
| `NBUDDYN_OIDC_ADMINS` | Who becomes an administrator: e-mail addresses, or `@example.com` for a whole domain, separated by commas. |
| `NBUDDYN_OIDC_VIEWERS` | Who may look but not change. Same form. |
| `NBUDDYN_OIDC_NAME` | What the button says after "Sign in with". Default `SSO`. |

Someone on neither list is refused, and the attempt goes to the audit log. The flow uses
PKCE and a nonce and is tied to the browser that started it; the provider's signed
statement is verified against its published keys (RS256), and has to be for this
nbuddyn, fresh, and about a confirmed e-mail address. The administrator from
`NBUDDYN_PASSWORD` keeps working, as the way in if the provider is down.

### Encrypted connections to n8n's database and Redis

For Postgres, `sslmode` in the address works as it does everywhere else:

| `sslmode` | What nbuddyn does |
|---|---|
| none, or `prefer` | Encrypts when the server offers it. |
| `require` | Encrypts or does not connect. The server's certificate is not checked. |
| `verify-full` | Encrypts and only talks to a server whose certificate checks out. |
| `disable` | Never encrypts. |

For Redis, `rediss://` instead of `redis://` encrypts and checks the certificate.

Certificates are checked against the public authorities. If your server uses a private
one, as most managed databases do, give nbuddyn its certificate with `NBUDDYN_CA_FILE`.

## Credentials

**Credentials** lists every credential by name and type, never its secret, with the
workflows that use it: what would break if it were rotated or deleted.

## What changed

nbuddyn compares every scan with the one before and keeps a log, shown under **Activity**:

- findings that appeared and findings that were resolved;
- workflows created, edited, renamed, activated, deactivated or deleted, with who saved
  them when n8n records it;
- active workflows that used to run most days and have not run in three (reported as a
  finding).

The overview counts the last 24 hours, and a finding that appeared in that time is marked
as new. To name who saved a workflow on Postgres, nbuddyn needs two more grants; without
them everything else still works:

```sql
GRANT SELECT ("versionId") ON workflow_entity TO nbuddyn;
GRANT SELECT ("versionId", authors) ON workflow_history TO nbuddyn;
```

## Several n8n instances

One nbuddyn can watch several n8n: production and staging, or one per client. The first
is the one in `NBUDDYN_DATABASE_URL`. Add the others in **Settings**, with a name and a
database address (Postgres or SQLite). Each has its own score, findings, accepted
findings, cluster view and history, and a selector in the top bar switches between them.
Database passwords added this way are kept in `settings.json` in the data directory and
are never sent back to the browser.

## Settings on the page

The **Settings** button changes, without a restart: n8n's address, the default language,
the time between scans, the time zone, how long the history is kept, the task runners and
n8n's Redis. Environment variables give the starting values; what is saved on the page
wins from then on and is kept in `settings.json` in the data directory. Redis' password
is never sent back to the browser.

Three things stay in the environment, because without them there is no page to change
them from: the database connection, the page's own login, and the MCP token.

With n8n's address set, every finding links to its workflow in n8n's editor.

## Accepting a finding

Some findings are decisions, not mistakes: a webhook that is public on purpose. **Accept**
takes a finding out of the score, the lights and the counts, with an optional note saying
why, and lists it apart under *Accepted*, where it can be brought back. A finding that
gets worse (say, from important to urgent) comes back by itself.

## Your rules

What matters is not the same everywhere, so **Settings → Your rules** lets a team decide:

- how severe each check is here: more, less, or off. A company can make "users without
  two-factor" urgent and turn "unused credentials" off;
- whether nbuddyn tells you when a newer n8n is out. This is off by default, because it is
  the only thing nbuddyn asks outside your server: once a day it reads two public lists
  (`registry.npmjs.org` and `hub.docker.com`) and sends nothing about your n8n. An n8n
  that is ahead of the stable version is not reported as behind;
- whether accepting a finding needs a written reason;
- whether the credentials n8n 3 makes for its own assistant count as unused (they do
  not, unless you say so);
- how many days an acceptance lasts before the finding comes back for another look.

The score, the lights, the alerts and the audit log all follow those rules.

**nbuddyn watches; it does not block.** It cannot stop a risky workflow from being
published, because that would mean writing to n8n, and nbuddyn only reads. What it can do
is tell something that can act: point the alert webhook at an n8n workflow of your own
that, say, deactivates the offending workflow through n8n's API or opens a ticket. The
decision to act stays with you and inside n8n.

## For AI assistants (MCP)

nbuddyn answers the Model Context Protocol at `/mcp`, so an assistant such as Claude can
ask about your n8n in plain words. It offers six tools, all read-only: `list_instances`,
`get_status`, `list_findings`, `list_credentials`, `get_activity` and `get_history`. They
return what the page shows and nothing else: no secrets, no execution data, and no way
to change n8n.

It is off until you turn it on in **Settings → AI assistants (MCP)**. That section shows
the address to give the assistant, lists the assistants that connected, and lets you
disconnect any of them.

**Assistants that sign in (claude.ai, Claude Desktop and others).** In claude.ai go to
Settings → Connectors → Add custom connector and paste the address. Claude sends you to
nbuddyn, you sign in if you are not, and an administrator presses **Allow**. No token is
copied anywhere. This is the OAuth 2.1 flow the MCP specification describes: the
assistant registers itself, proves itself with PKCE, and gets a token that lasts an hour
and that it renews by itself. A connection nobody uses for 90 days ends.

**Clients that take a fixed token (Claude Code, scripts).** Press **Create token** in the
same section. It is shown once; nbuddyn keeps only its hash. With Claude Code:

```bash
claude mcp add --transport http nbuddyn https://your-nbuddyn-host/mcp --header "Authorization: Bearer your-token"
```

A token can also come from the environment in `NBUDDYN_MCP_TOKEN`, which turns the
endpoint on by itself until Settings says otherwise.

nbuddyn works out its own address from the request. Behind a proxy that does not pass
the original host on, set `NBUDDYN_PUBLIC_URL`.

### How sure nbuddyn is

Every finding is marked **Verified** or **To review**. Verified is a fact nbuddyn counted
or measured: a runner that does not answer, a workflow that failed 40 times. To review is
a sign it cannot be sure about from where it stands: a webhook without authentication may
validate its caller inside the workflow, and text that looks like a key may be an
example. Those findings say why they may be fine, and can be accepted.

nbuddyn does **not** check what a workflow does with its data, who may use what inside
n8n, the code of community nodes, how n8n is exposed to the network, or anything inside
executions and credentials. The score sums up what it can see. It is a radar, not an audit.


## Every setting

| Variable | Default | Meaning |
|---|---|---|
| `NBUDDYN_DATABASE_URL` | required | n8n's database: `postgres://user:password@host:5432/n8n` (use a read-only user) or `sqlite:/path/to/database.sqlite`. |
| `NBUDDYN_PASSWORD` | required | Password of the first administrator. The report lists your weak points; keep it private. |
| `NBUDDYN_NAME` | `n8n` | What the first instance is called on the page. |
| `NBUDDYN_N8N_URL` | unset | Where n8n's editor is, such as `https://n8n.example.com`. Findings then link to their workflow. |
| `NBUDDYN_REDIS_URL` | unset | n8n's Redis, as `redis://[user:password@]host[:port][/db]`, or `rediss://` to encrypt. Enables the queue and cluster checks. Percent-encode `@`, `/` and `%` in the password. |
| `NBUDDYN_RUNNER_URLS` | unset | External task runners, comma-separated, as `host`, `host:port` or `http://host:port/path`. Port 5680 and `/healthz` by default. Enables the runner check. |
| `NBUDDYN_SECRET_KEY` | made and kept in the data directory | Seals the secrets nbuddyn stores. Changing it makes saved secrets unreadable, so keep it. |
| `NBUDDYN_TELEGRAM_TOKEN`, `NBUDDYN_TELEGRAM_CHAT` | unset | Starting values for Telegram alerts. |
| `NBUDDYN_WEBHOOK_URL` | unset | Starting value for the alert webhook. |
| `NBUDDYN_ALERT_LEVEL` | `high` | `high` alerts on urgent findings, `medium` on important ones too. |
| `NBUDDYN_CA_FILE` | unset | A PEM file with extra certificate authorities to trust for Postgres (`sslmode=verify-full`) and Redis (`rediss://`). |
| `NBUDDYN_DATA_DIR` | `/data` in the image | Where the history, the saved settings and the accepted findings live. Mount a volume there, or they are lost with the container. Unset outside the image: no history, and nothing can be saved from the page. |
| `NBUDDYN_HISTORY_DAYS` | `400` | Days of history to keep. |
| `NBUDDYN_TIMEZONE` | the database's | Decides where a day ends, such as `America/Argentina/Buenos_Aires`. |
| `NBUDDYN_MCP_TOKEN` | unset | A token for MCP clients, at least 24 characters. Turns the MCP endpoint on until Settings says otherwise. Tokens can also be made in Settings. |
| `NBUDDYN_PUBLIC_URL` | worked out from the request | The https address people open nbuddyn at. Needed for single sign-on, and for assistants when a proxy hides the original host. |
| `NBUDDYN_USER` | `nbuddyn` | Name of the first administrator. |
| `NBUDDYN_LISTEN` | `0.0.0.0:8787` | Address to listen on. |
| `NBUDDYN_INTERVAL_SECONDS` | `300` | Seconds between scans (minimum 10). |
| `NBUDDYN_LANG` | `en` | Default language: `en`, `es` or `pt`. |
| `NBUDDYN_ALLOW_ANONYMOUS` | unset | `true` removes the login. Only behind another login. |
| `NBUDDYN_BULL_PREFIX` | `bull` | Set it if n8n uses another `QUEUE_BULL_PREFIX`. |
| `NBUDDYN_QUEUE_NAME` | `jobs` | The Bull queue n8n enqueues executions on. |
| `NBUDDYN_REDIS_KEY_PREFIX` | `n8n` | Set it if n8n uses another `N8N_REDIS_KEY_PREFIX`. |

nbuddyn sends Redis only read commands (`LLEN`, `ZCARD`, `SMEMBERS`, `MGET`, `INFO`). If your
Redis has ACLs, a user limited to `+@read +info` on `bull:*` and `n8n:*` is enough.

Task runners get one request each per scan: `GET /healthz`, nothing else, over plain
http: keep nbuddyn on the same private network as them. `GET /healthz` answers without a login, for health checks.

## Which n8n versions

nbuddyn is made for n8n 3 and later; older versions are tested but are not its target.

nbuddyn reads n8n's own database, and n8n does not promise to keep it the same. So
every change to nbuddyn is tested against real n8n **1.123, 2.48 and 3.3**, each on SQLite
and on Postgres: n8n is started, builds its database, and nbuddyn reads it.

To try a database address before running nbuddyn, or after updating n8n:

```bash
docker run --rm -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:password@n8n_postgres:5432/n8n \
  ghcr.io/diegoparras/nbuddyn:latest check
```

It says what it could read. If a grant is missing it prints the exact `GRANT` to run; if
the database is not one it knows, it says so instead of guessing.

## How big an n8n it can watch

Measured on every release against a real n8n database with 5,000 workflows of 20 nodes
each and one million executions:

| | |
|---|---|
| A full scan | about 4 seconds |
| Memory at its peak | about 165 MB |
| The report the page loads | about 180 KB |

A typical instance, with tens or a few hundred workflows, stays under 30 MB. Give
nbuddyn 64 MB for those and 256 MB for instances in the thousands. Workflows are read
and checked in pages of 200, so memory follows the size of the history, not of the
workflow definitions. Each group of findings lists up to 250; the count is always whole.

Sessions, users, the audit log, saved settings and the history live in the data
directory and survive restarts and updates.

## Releases

Versions are listed in the [changelog](../CHANGELOG.md). Images are tagged by version
(`ghcr.io/diegoparras/nbuddyn:0.21.0`) and `latest`, signed, and carry a bill of
materials. How to verify one, how to report a vulnerability, and what an attacker who
took over nbuddyn would and would not get, are in [SECURITY.md](../SECURITY.md). The [threat model](THREAT-MODEL.md) lists what
protects each way in and what is knowingly left open; no independent audit has been done
yet.
