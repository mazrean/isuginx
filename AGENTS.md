# Repository Guidelines — isuginx

ISUCON-oriented nginx helper utility, written in Go.

> Agent configuration is managed via [apm](https://github.com/microsoft/apm).
> Common conventions live in `mazrean/apm-plackage/common`; Go-specific rules
> come from `mazrean/apm-plackage/go`. Run `apm install` to materialise locally.

## Build & Test

- `go build ./...`
- `go test -v ./...`
- `golangci-lint run`

## Conventions

- Single-file `main.go` utility; keep it small.
- Specs go under `specs/`; use `mazrean/agent-skills/skills/writing-*`.
- Commit using Conventional Commits (`committing-code` skill).
