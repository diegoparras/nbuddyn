# nbuddyn

**A tiny, read-only cockpit for self-hosted n8n.** · [Español](#español) · [Português](#português)

nbuddyn sits next to your n8n, reads its database and its Redis, checks its task runners, and tells you what n8n does not:
which doors are open, what is failing in silence, and what will break.

- **Read-only.** It switches its database session to read-only before the first query. It cannot change your n8n; the only things it writes are its own files.
- **One binary.** A few MB on disk and in memory, no other services to install.
- **Three languages.** English, Spanish and Portuguese, selectable on the page.

nbuddyn is an independent project. It is not affiliated with or endorsed by n8n GmbH.
It contains no n8n code and does not unlock, replace or bypass any licensed n8n feature.

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

The history can be downloaded as a spreadsheet (CSV) from the History page, and as a
backup file from Settings.

Only totals are kept, in one small JSON file. No execution data is read or stored.
A workflow that was deleted stays in the history under its last known name.

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

Scripts can still send a name and password with HTTP Basic on every API request.

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

## For AI assistants (MCP)

Set `NBUDDYN_MCP_TOKEN` and nbuddyn answers the Model Context Protocol at `/mcp`, so an
assistant such as Claude can ask about your n8n in plain words. It offers six tools,
all read-only: `list_instances`, `get_status`, `list_findings`, `list_credentials`, `get_activity` and
`get_history`. They return what the page
shows and nothing else: no secrets, no execution data, and no way to change n8n.

The endpoint is off without a token, and every request must carry it as
`Authorization: Bearer <token>`. With Claude Code:

```bash
claude mcp add --transport http nbuddyn https://your-nbuddyn-host/mcp --header "Authorization: Bearer your-token"
```

Checks read the saved definition of each workflow. A webhook that validates its caller
inside the workflow still shows as unauthenticated, because nbuddyn cannot see that logic.

## Run it

nbuddyn reads either database n8n can use.

**If your n8n uses SQLite** (the default when n8n is given no database), give nbuddyn
n8n's data folder, read-only, and point it at the file:

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -v n8n_data:/n8n:ro \
  -v nbuddyn_data:/data \
  -e NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  ghcr.io/diegoparras/nbuddyn:latest
```

`n8n_data` is the volume your n8n mounts at `/home/node/.n8n`. nbuddyn opens the file
read-only and never blocks n8n. Two things differ from Postgres: days are cut in UTC,
and the file can be read only while n8n is running.

**If your n8n uses Postgres**, create a read-only user in it (once):

```sql
CREATE ROLE nbuddyn LOGIN PASSWORD 'choose-a-password';
GRANT SELECT (id, name, active, "isArchived", nodes, settings) ON workflow_entity TO nbuddyn;
GRANT SELECT (id, name, type) ON credentials_entity TO nbuddyn;
GRANT SELECT (id, "workflowId", status, "startedAt", "createdAt", "deletedAt") ON execution_entity TO nbuddyn;
GRANT SELECT (disabled, "mfaEnabled") ON "user" TO nbuddyn;
```

These grants cover only the columns nbuddyn reads. The role cannot read stored
credentials, password hashes or execution data.

Then run the published image (`linux/amd64` and `linux/arm64`):

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  -v nbuddyn_data:/data \
  ghcr.io/diegoparras/nbuddyn:latest
```

To build it yourself instead: `docker build -t nbuddyn .`

Open `http://localhost:8787` and log in as `nbuddyn`.

| Variable | Default | Meaning |
|---|---|---|
| `NBUDDYN_DATABASE_URL` | required | n8n's database: `postgres://user:password@host:5432/n8n` (use a read-only user) or `sqlite:/path/to/database.sqlite`. |
| `NBUDDYN_PASSWORD` | required | Password of the first administrator. The report lists your weak points; keep it private. |
| `NBUDDYN_NAME` | `n8n` | What the first instance is called on the page. |
| `NBUDDYN_N8N_URL` | unset | Where n8n's editor is, such as `https://n8n.example.com`. Findings then link to their workflow. |
| `NBUDDYN_REDIS_URL` | unset | n8n's Redis, as `redis://[user:password@]host[:port][/db]`, or `rediss://` to encrypt. Enables the queue and cluster checks. Percent-encode `@`, `/` and `%` in the password. |
| `NBUDDYN_RUNNER_URLS` | unset | External task runners, comma-separated, as `host`, `host:port` or `http://host:port/path`. Port 5680 and `/healthz` by default. Enables the runner check. |
| `NBUDDYN_CA_FILE` | unset | A PEM file with extra certificate authorities to trust for Postgres (`sslmode=verify-full`) and Redis (`rediss://`). |
| `NBUDDYN_DATA_DIR` | `/data` in the image | Where the history, the saved settings and the accepted findings live. Mount a volume there, or they are lost with the container. Unset outside the image: no history, and nothing can be saved from the page. |
| `NBUDDYN_HISTORY_DAYS` | `400` | Days of history to keep. |
| `NBUDDYN_TIMEZONE` | the database's | Decides where a day ends, such as `America/Argentina/Buenos_Aires`. |
| `NBUDDYN_MCP_TOKEN` | unset | Turns on the MCP endpoint at `/mcp` and is the token clients must send. At least 24 characters. |
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

## Status

One page, two JSON endpoints (`/api/report?lang=es` and `/api/history?days=30`) and an MCP endpoint (`/mcp`). Tested against n8n 3.3 on
Postgres, n8n 2.48 on SQLite, and Redis 8. Planned next: alerts.

## Development

```bash
cargo test
```

## License

MIT. See [LICENSE](LICENSE).

---

## Español

**Una cabina mínima, de solo lectura, para n8n autoalojado.**

nbuddyn se instala al lado de tu n8n, lee su base de datos (Postgres o SQLite) y te dice lo que n8n no te dice:
qué puertas están abiertas, qué está fallando en silencio y qué se va a romper.

- **Solo lectura.** Pone su sesión de base de datos en modo lectura antes de la primera consulta. No puede modificar tu n8n.
- **Un solo binario.** Pocos MB en disco y en memoria, sin otros servicios que instalar.
- **Tres idiomas.** Inglés, español y portugués, elegibles en la página.

nbuddyn es un proyecto independiente, sin relación con n8n GmbH. No contiene código de n8n
y no desbloquea, reemplaza ni elude ninguna función licenciada de n8n.

**Uso:** si tu n8n usa SQLite, montá su carpeta de datos en solo lectura y poné
`NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite`. Si usa Postgres, creá un usuario de solo
lectura con el SQL de arriba. Después arrancá la imagen `ghcr.io/diegoparras/nbuddyn:latest`
con `NBUDDYN_DATABASE_URL` y `NBUDDYN_PASSWORD`, como en los ejemplos de arriba. Entrá a
`http://localhost:8787` con el usuario `nbuddyn`. El resto se configura desde el botón
**Ajustes** de la página.

Los chequeos leen la definición guardada de cada workflow. Un webhook que valida a quien
llama dentro del workflow igual aparece como sin autenticación, porque nbuddyn no ve esa lógica.

---

## Português

**Uma cabine mínima, somente leitura, para n8n auto-hospedado.**

O nbuddyn fica ao lado do seu n8n, lê o banco de dados (Postgres ou SQLite) e mostra o que o n8n não mostra:
quais portas estão abertas, o que está falhando em silêncio e o que vai quebrar.

- **Somente leitura.** Coloca a sessão do banco em modo leitura antes da primeira consulta. Não pode alterar o seu n8n.
- **Um único binário.** Poucos MB em disco e em memória, sem outros serviços para instalar.
- **Três idiomas.** Inglês, espanhol e português, selecionáveis na página.

O nbuddyn é um projeto independente, sem relação com a n8n GmbH. Não contém código do n8n
e não desbloqueia, substitui nem contorna nenhum recurso licenciado do n8n.

**Uso:** se o seu n8n usa SQLite, monte a pasta de dados dele em somente leitura e defina
`NBUDDYN_DATABASE_URL=sqlite:/n8n/database.sqlite`. Se usa Postgres, crie um usuário somente
leitura com o SQL acima. Depois inicie a imagem `ghcr.io/diegoparras/nbuddyn:latest` com
`NBUDDYN_DATABASE_URL` e `NBUDDYN_PASSWORD`, como nos exemplos acima. Acesse
`http://localhost:8787` com o usuário `nbuddyn`. O resto é configurado pelo botão
**Configurações** da página.

As verificações leem a definição salva de cada workflow. Um webhook que valida quem chama
dentro do workflow ainda aparece como sem autenticação, porque o nbuddyn não vê essa lógica.
