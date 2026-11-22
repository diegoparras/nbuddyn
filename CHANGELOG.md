# Changelog

Every release of nbuddyn, newest first. Versions follow [semantic versioning](https://semver.org):
while the first number is 0, the second one changes when something you rely on may change.

## 0.17.0

- **Your rules**: per-check severity, a required reason when accepting, and
  acceptances that expire.

## 0.16.0

- **Single sign-on** with OpenID Connect: Google, Microsoft Entra, Okta, Keycloak.
  Roles come from lists of e-mail addresses and domains.
- A changelog, a security policy, and images signed with cosign that carry a bill of
  materials.

## 0.15.0

- **Big instances.** Measured against a real n8n database with 5,000 workflows and a
  million executions: a scan takes about 4 seconds and peaks at about 165 MB, down from
  440 MB. A group of findings lists at most 250 and keeps its full count.
- **Sessions survive restarts.** Updating nbuddyn signs nobody out.

## 0.14.0

- **How sure each finding is.** Findings are marked *Verified* or *To review*, and the
  latter say why they may be fine. The page lists what nbuddyn does not check.

## 0.13.0

- **Compatibility.** Every change is tested against real n8n 1.123, 2.48 and 3.3 on
  SQLite and Postgres. A scan that cannot read n8n says why: the exact `GRANT` to run, or
  that the version is not one it knows. New command: `nbuddyn check`.

## 0.12.0

- **Alerts** to Telegram and to any JSON webhook, about what changed in a scan.
- **Secrets at rest are sealed** with ChaCha20-Poly1305 (`NBUDDYN_SECRET_KEY`).

## 0.11.0

- **Credentials**: which workflows use each credential.
- **Durations**: each workflow's average and slowest run, with one optional grant.
- **Downloads**: the history as CSV and as a backup file. A favicon.

## 0.10.0

- **Encrypted connections** to Postgres (`sslmode`) and Redis (`rediss://`), with
  `NBUDDYN_CA_FILE` for private certificate authorities.

## 0.9.0

- **A login page**, users with two roles, an audit log, a brake on password guessing,
  and a strict Content-Security-Policy. The browser's password box is gone.

## 0.8.0

- **Activity**: what changed between scans, and workflows that stopped running.

## 0.7.0

- **Several n8n instances** in one nbuddyn.

## 0.6.0

- **The page became an application**: Overview, Findings, Cluster, History, Settings.

## 0.5.0

- **SQLite**, the database n8n uses by default. A published image for amd64 and arm64.

## 0.4.0

- **Settings on the page**, links into n8n's editor, and accepting findings.

## 0.3.0

- **A read-only MCP endpoint** for AI assistants.

## 0.2.0

- **Its own history** of executions and scores, which outlives n8n's pruning.

## 0.1.0

- The first radar: a score, findings from n8n's Postgres, the queue and cluster through
  Redis, and task runner health.
