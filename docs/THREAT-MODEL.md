# Threat model

Written for whoever reviews nbuddyn's security, inside a company or as an outside audit.
It says what nbuddyn holds, who could attack it and how, what stands in their way, and
what is knowingly left open. Nobody independent has reviewed nbuddyn yet; this document
is the starting point for the first one who does.

## What nbuddyn is

One process and one binary. It reads an n8n instance's database (Postgres or SQLite) and
optionally its Redis, asks task runners for their health, keeps counts and settings in a
data directory, and serves a web page, a JSON API and an MCP endpoint.

## What is worth protecting

| Asset | Where it is | Why it matters |
|---|---|---|
| Passwords to n8n's databases and Redis | Environment; `settings.json` (sealed) | Read access to every workflow definition |
| The report | Memory; served to signed-in users | A map of the instance's weak points |
| Workflow definitions | Read from n8n, held in memory during a scan | May contain secrets people wrote into nodes |
| Alert destinations | `settings.json` (sealed) | A Telegram bot token, a webhook address |
| Users and sessions | `users.json` (salted PBKDF2), `sessions.json` (token hashes) | Access to all of the above |
| The audit log | `audit.json` | Evidence of who did what |

nbuddyn never holds: n8n's stored credentials, n8n's encryption key, execution data, or
n8n users' password hashes. The documented database grants do not allow reading them.

## Who is trusted with what

- **n8n's database and Redis** are trusted to be the ones configured. Their content is
  *not* trusted: workflow names, node parameters and Redis values are treated as data,
  rendered as text, and never executed or used to build queries.
- **Administrators** are trusted fully. **Read-only users** are trusted to see the
  report and nothing that changes state.
- **The network between nbuddyn and what it reads** is trusted only as far as TLS is
  configured (`sslmode=verify-full`, `rediss://`). Runner health checks are plain http.
- **A reverse proxy** in front of nbuddyn is trusted to say whether the browser used
  https (`X-Forwarded-Proto`), which only decides the cookie's `Secure` flag.

## Ways in, and what stands in the way

| Entry point | Threat | Mitigation |
|---|---|---|
| Login form | Password guessing | Per-name delay after 5 failures, doubling to 15 min; slow hash; failures audited |
| Login form | User enumeration by timing | The same hashing work is done for unknown names |
| Session cookie | Theft by script | `HttpOnly`; strict CSP allows only the page's own script |
| Session cookie | Cross-site use | `SameSite=Strict`; state changes need a header other sites cannot send |
| Any page | Injected script through a workflow name | DOM built with `textContent`; CSP without `unsafe-inline` for scripts |
| Any page | Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| Links into n8n | A crafted workflow id | Ids outside `[A-Za-z0-9_-]` get no link; the base address is validated |
| Single sign-on | Forged or replayed ID token | RS256 signature checked against the provider's keys; issuer, audience, expiry, nonce checked; PKCE; flow bound to the starting browser |
| Single sign-on | An outsider with a valid account at the provider | Only listed addresses and domains get a role |
| MCP endpoint | Unauthenticated use | Off without a token; token of 24+ characters compared in constant time |
| MCP endpoint | A prompt-injected assistant | Every tool only reads; nothing it can call changes n8n or nbuddyn |
| Settings | A database address pointing somewhere unexpected | Admin only; this is inherent in the feature and audited |
| Alert webhook | Server-side request to an internal address | Admin only; audited. Not otherwise restricted (see open points) |
| CSV export | Formula injection in a spreadsheet | Fields starting with `= + - @` are neutralised |
| Data directory | Read by someone with a backup | Secrets sealed with ChaCha20-Poly1305; passwords hashed; sessions stored as hashes |
| n8n's database | nbuddyn changing data | Read-only session and read-only file open, enforced before the first query; column-level grants recommended |
| Supply chain | A tampered image | Built by GitHub Actions from this repository; signed with cosign; SBOM and provenance attached |
| Supply chain | A vulnerable dependency | Few dependencies, no HTTP client or Redis library; `Cargo.lock` committed |

## Knowingly open

- **No independent audit.** Everything above is the author's claim.
- **The key that seals secrets defaults to a file in the data directory.** Someone with
  the whole directory can open them. Setting `NBUDDYN_SECRET_KEY` closes this.
- **Plain-text environment variables** hold the database address and the first
  administrator's password, as in most container deployments.
- **An administrator can make nbuddyn connect anywhere** (database, Redis, webhook,
  runners). There is no allow-list of destinations.
- **Sessions are not bound to an IP or device**, and last 12 hours.
- **No rate limit on the API** beyond the login. A signed-in user can ask as often as
  they like; scans themselves run on a fixed interval.
- **The audit log is a local file** an administrator of the host can edit. It is not
  tamper-evident and is not shipped anywhere.
- **Runner health checks are unencrypted and unauthenticated**, and so can be spoofed
  by someone on that network. They only affect one finding.
- **ID tokens are accepted only with RS256.** Providers using ES256 will not work.
- **Checks are heuristics.** nbuddyn can miss a real problem. It is not a substitute
  for reviewing workflows.

## For an auditor: where to look first

1. `src/web.rs`: authentication, the write-header check, role checks on every handler.
2. `src/auth.rs` and `src/oidc.rs`: password handling, sessions, token verification.
3. `src/vault.rs`: sealing of secrets and key handling.
4. `src/db.rs` and `src/sqlite.rs`: that nothing can write, and that no query is built
   from data read from n8n (two places format numbers nbuddyn itself read into SQL).
5. `assets/index.html`: that nothing read from the API reaches `innerHTML`.
6. `src/http.rs`, `src/cluster.rs`, `src/runners.rs`: the hand-written protocol clients.
