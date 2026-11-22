# Security

nbuddyn reads the database of your automation platform and tells you where it is weak.
A flaw in nbuddyn matters, and reports are welcome.

## Reporting a vulnerability

Please do **not** open a public issue. Use GitHub's private reporting instead:
**Security → Report a vulnerability** on this repository. Say what you found, how to
reproduce it, and which version you used (Settings → About, or `/healthz` is not enough:
the version is on the Settings page).

You will get an answer within seven days. Fixes for confirmed reports are released as soon
as they are ready, and the report is credited unless you prefer otherwise.

## Supported versions

Only the latest release gets fixes. nbuddyn is one small binary; updating is replacing
the image.

## What nbuddyn can and cannot do to your n8n

- It only **reads**. Its Postgres session is switched to read-only before the first
  query, its SQLite file is opened read-only with writes refused, and it sends Redis only
  read commands. The recommended database user has `SELECT` on a handful of columns and
  cannot read stored credentials, password hashes or execution data.
- It makes **no outbound connections** except the ones you configure: n8n's database and
  Redis, the runners' health checks, and your alert destinations. No telemetry, no
  update checks.
- It **stores**, in its data directory: settings, the history of counts, users with
  salted password hashes, open sessions by the hash of their token, and an audit log.
  Passwords and tokens inside settings are sealed with ChaCha20-Poly1305.

## What an attacker who takes over nbuddyn gets

Being honest about this is part of the product:

- Everything nbuddyn can read: the names and definitions of your workflows, the names
  and types of credentials (not their secrets), and execution counts.
- The passwords nbuddyn holds for the databases and Redis it watches, which is why its
  database user should be read-only and column-limited.
- Nothing that lets them change n8n, unless the database user was given more than the
  documented grants.

## Verifying a release

Images are built by GitHub Actions from this repository and signed with
[cosign](https://docs.sigstore.dev/) using the workflow's own identity, with no long-lived key:

```bash
cosign verify ghcr.io/diegoparras/nbuddyn:latest \
  --certificate-identity-regexp '^https://github.com/diegoparras/nbuddyn/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Each image also carries a software bill of materials and build provenance, which
`docker buildx imagetools inspect ghcr.io/diegoparras/nbuddyn:latest --format '{{ json .SBOM }}'` shows.
