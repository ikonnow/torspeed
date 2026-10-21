# Contributing

Issues and pull requests are welcome.

## Ground rules

- **Pure Go standard library** – no third-party Go dependencies. This is a
  deliberate design decision: the binary must stay auditable and build
  anywhere with just `go build`.
- Run `make check` before submitting – it gates on `gofmt`, `go vet`,
  `go test -race`, and the JS syntax/unit checks for the extension.
- Tests must stay hermetic: no Tor daemon, no network access, no sleeps
  longer than a few milliseconds.
- The extension files under `extension/` are the single source of truth –
  they are embedded into the binary via `go:embed`.

## Development

```sh
make        # all checks + build
make test   # Go tests only
```

Keep the README in sync when flags, API routes or behavior change.
