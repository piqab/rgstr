# Contributing to rgstr

Thanks for your interest! Bug reports, ideas and pull requests are welcome,
in English or Russian.

- **Bugs and features:** open an [issue](https://github.com/piqab/rgstr/issues/new/choose).
  For larger changes, please open an issue first to agree on the approach.
- **Security problems:** see [SECURITY.md](SECURITY.md), never a public issue.

## Development

Requirements: Go 1.26+ (the module works with older Go, but releases are
built with the newest patch release).

```bash
go vet ./...
go test -race ./...
go run . # RGSTR_STORAGE=./data, listens on :5000
```

The web admin is plain JavaScript in `internal/ui/static`, embedded into the
binary: no build step, reload the page after `go run .`.

## Pull requests

- Keep a pull request to one change, with tests for new behaviour.
- Match the surrounding code style; run `gofmt`.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
  `feat: ...`, `fix: ...`, `docs: ...`.
- Do not change `VERSION`: maintainers set it when releasing.

By contributing you agree that your contribution is licensed under the
[MIT License](LICENSE).
