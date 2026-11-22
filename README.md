# nbuddyn

**A tiny, read-only cockpit for self-hosted n8n.** · [Español](#español) · [Português](#português)

nbuddyn sits next to your n8n, reads its database and its Redis, and tells you what n8n does not:
which doors are open, what is failing in silence, and what will break.

- **Read-only.** It switches its database session to read-only before the first query. It cannot change your n8n.
- **One binary.** About 2 MB, a few MB of memory, no other services to install.
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

Checks read the saved definition of each workflow. A webhook that validates its caller
inside the workflow still shows as unauthenticated, because nbuddyn cannot see that logic.

## Run it

Create a read-only user in n8n's Postgres (once):

```sql
CREATE ROLE nbuddyn LOGIN PASSWORD 'choose-a-password';
GRANT SELECT (id, name, active, "isArchived", nodes, settings) ON workflow_entity TO nbuddyn;
GRANT SELECT (id, name, type) ON credentials_entity TO nbuddyn;
GRANT SELECT (id, "workflowId", status, "startedAt", "createdAt", "deletedAt") ON execution_entity TO nbuddyn;
GRANT SELECT (disabled, "mfaEnabled") ON "user" TO nbuddyn;
```

These grants cover only the columns nbuddyn reads. The role cannot read stored
credentials, password hashes or execution data.

Build and run:

```bash
docker build -t nbuddyn .
```

```bash
docker run -d --name nbuddyn -p 8787:8787 \
  -e NBUDDYN_DATABASE_URL=postgres://nbuddyn:choose-a-password@n8n_postgres:5432/n8n \
  -e NBUDDYN_PASSWORD=choose-a-login-password \
  nbuddyn
```

Open `http://localhost:8787` and log in as `nbuddyn`.

| Variable | Default | Meaning |
|---|---|---|
| `NBUDDYN_DATABASE_URL` | required | Connection to n8n's Postgres. Use a read-only user. |
| `NBUDDYN_PASSWORD` | required | Password for the page. The report lists your weak points; keep it private. |
| `NBUDDYN_REDIS_URL` | unset | n8n's Redis, as `redis://[user:password@]host[:port][/db]`. Enables the queue and cluster checks. Percent-encode `@`, `/` and `%` in the password. |
| `NBUDDYN_USER` | `nbuddyn` | User name for the page. |
| `NBUDDYN_LISTEN` | `0.0.0.0:8787` | Address to listen on. |
| `NBUDDYN_INTERVAL_SECONDS` | `300` | Seconds between scans (minimum 10). |
| `NBUDDYN_LANG` | `en` | Default language: `en`, `es` or `pt`. |
| `NBUDDYN_ALLOW_ANONYMOUS` | unset | `true` removes the login. Only behind another login. |
| `NBUDDYN_BULL_PREFIX` | `bull` | Set it if n8n uses another `QUEUE_BULL_PREFIX`. |
| `NBUDDYN_QUEUE_NAME` | `jobs` | The Bull queue n8n enqueues executions on. |
| `NBUDDYN_REDIS_KEY_PREFIX` | `n8n` | Set it if n8n uses another `N8N_REDIS_KEY_PREFIX`. |

nbuddyn sends Redis only read commands (`LLEN`, `ZCARD`, `SMEMBERS`, `MGET`, `INFO`). If your
Redis has ACLs, a user limited to `+@read +info` on `bull:*` and `n8n:*` is enough.

The connections to Postgres and Redis are not encrypted in this version, so keep nbuddyn on
the same private network as both. `GET /healthz` answers without a login, for health checks.

## Status

One page and one JSON endpoint (`/api/report?lang=es`). Tested against the n8n 3.3 database
schema and a Redis 7 server. Planned next: task runner health, history that survives n8n's
pruning, a read-only MCP endpoint, and alerts.

## Development

```bash
cargo test
```

## License

MIT. See [LICENSE](LICENSE).

---

## Español

**Una cabina mínima, de solo lectura, para n8n autoalojado.**

nbuddyn se instala al lado de tu n8n, lee su base de datos y te dice lo que n8n no te dice:
qué puertas están abiertas, qué está fallando en silencio y qué se va a romper.

- **Solo lectura.** Pone su sesión de base de datos en modo lectura antes de la primera consulta. No puede modificar tu n8n.
- **Un solo binario.** Unos 2 MB, pocos MB de memoria, sin otros servicios que instalar.
- **Tres idiomas.** Inglés, español y portugués, elegibles en la página.

nbuddyn es un proyecto independiente, sin relación con n8n GmbH. No contiene código de n8n
y no desbloquea, reemplaza ni elude ninguna función licenciada de n8n.

**Uso:** creá un usuario de solo lectura en el Postgres de n8n con el SQL de arriba, construí
la imagen con `docker build -t nbuddyn .` y arrancala con `NBUDDYN_DATABASE_URL` y
`NBUDDYN_PASSWORD`. Entrá a `http://localhost:8787` con el usuario `nbuddyn`. Para que la
página abra en español por defecto, agregá `NBUDDYN_LANG=es`.

Los chequeos leen la definición guardada de cada workflow. Un webhook que valida a quien
llama dentro del workflow igual aparece como sin autenticación, porque nbuddyn no ve esa lógica.

---

## Português

**Uma cabine mínima, somente leitura, para n8n auto-hospedado.**

O nbuddyn fica ao lado do seu n8n, lê o banco de dados e mostra o que o n8n não mostra:
quais portas estão abertas, o que está falhando em silêncio e o que vai quebrar.

- **Somente leitura.** Coloca a sessão do banco em modo leitura antes da primeira consulta. Não pode alterar o seu n8n.
- **Um único binário.** Cerca de 2 MB, poucos MB de memória, sem outros serviços para instalar.
- **Três idiomas.** Inglês, espanhol e português, selecionáveis na página.

O nbuddyn é um projeto independente, sem relação com a n8n GmbH. Não contém código do n8n
e não desbloqueia, substitui nem contorna nenhum recurso licenciado do n8n.

**Uso:** crie um usuário somente leitura no Postgres do n8n com o SQL acima, construa a
imagem com `docker build -t nbuddyn .` e inicie com `NBUDDYN_DATABASE_URL` e
`NBUDDYN_PASSWORD`. Acesse `http://localhost:8787` com o usuário `nbuddyn`. Para abrir a
página em português por padrão, adicione `NBUDDYN_LANG=pt`.

As verificações leem a definição salva de cada workflow. Um webhook que valida quem chama
dentro do workflow ainda aparece como sem autenticação, porque o nbuddyn não vê essa lógica.
