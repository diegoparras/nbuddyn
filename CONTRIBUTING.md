# Contributing to nbuddyn

Thank you for wanting to help. Issues and pull requests are welcome in English, Spanish
or Portuguese.

## Reporting a problem

[Open an issue](https://github.com/diegoparras/nbuddyn/issues/new/choose) and say which
n8n version and database you use, what you expected and what you saw. Take passwords,
tokens and host names out of logs first.

A security problem is different: please do not open a public issue. Follow
[SECURITY.md](SECURITY.md).

## Three rules that do not bend

1. **nbuddyn only reads.** No change may write to n8n's database, Redis or files.
2. **No n8n code.** nbuddyn is independent of n8n GmbH. Do not copy code from n8n's
   repository, and do not add anything that unlocks or replaces a paid n8n feature.
3. **Three languages.** Text people see goes in `src/i18n.rs` in English, Spanish and
   Portuguese.

## Working on the code

You need [Rust](https://rustup.rs). Then:

```bash
cargo test
```

```bash
cargo clippy --all-targets --locked -- -D warnings
```

To see your change in a browser without an n8n:

```bash
cargo run -- demo
```

Open <http://localhost:8787> and sign in as `demo` / `demo`.

A few habits of this codebase:

- Few dependencies. The Redis, HTTP and MCP clients are written by hand on purpose; ask
  in an issue before adding a crate.
- The page is one file, `assets/index.html`, with no build step and no framework.
- A new check needs a test, an entry in `src/i18n.rs`, and a line in
  `docs/reference.md`.
- Add a line to `CHANGELOG.md` for anything a user would notice.

Continuous integration runs the tests and then reads real n8n databases (1.123, 2.48 and
3.3, each on SQLite and Postgres). A pull request has to pass all of it.

## License

By contributing you agree that your work is released under the [MIT license](LICENSE).
