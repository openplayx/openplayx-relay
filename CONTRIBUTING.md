# Contributing

Thanks for your interest. Bug reports, fixes and small improvements are welcome.

## Issues

- Search existing issues first.
- For bugs, include the version (`openplayx-relay version` or the commit), the platform,
  what you did and the output of `openplayx-relay status` and `journalctl -u openplayx-relay`.
  Remove UUIDs, tokens, domains, certificates and IP addresses before posting:
  logs strip known secrets, but check them yourself.
- Security problems: do **not** open a public issue, see [SECURITY.md](SECURITY.md).

## Pull requests

1. Open an issue first for anything larger than a small fix, so we can agree
   on the approach.
2. Keep changes focused; one topic per pull request.
3. Run the tests before pushing:

   ```bash
   (cd src && go test ./...)          # unit tests + in-process end-to-end test
   (cd src && go test -short ./...)   # quick run, skips the end-to-end test
   ```

4. `src/` is shared with [openplayx-home](https://github.com/openplayx/openplayx-home): apart from
   `src/role.go`, both repositories must stay identical. Make the same change
   in both, and say so in the pull request.
5. Update the README in both languages (`README.md` and `README.zh-CN.md`)
   and `docs/` when behaviour, configuration or commands change.
6. Upgrading sing-box or frp means changing `src/go.mod` / `src/go.sum`,
   reviewing the upstream changes and running the end-to-end test; mention the
   upstream release notes in the pull request.

By contributing you agree that your contribution is licensed under this
repository's license (GPL-3.0-or-later).
