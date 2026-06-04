# Contributing

Thanks for considering a contribution. The project is small (~600 LOC of Go), the surface area is intentionally narrow, and we'd like to keep it that way.

## What we want

- Bug reports with a reliable repro and ideally a failing test.
- Platform ports (FreeBSD, OpenBSD, Linux on other arches).
- Documentation fixes — typos, clearer phrasing, better diagrams.
- Security hardening that doesn't bloat the binary or add dependencies.

## What we probably won't merge

- New dependencies. We're under 5 direct deps and intend to stay that way.
- Multi-protocol support (smtp-over-ws, dns-over-ws, etc). Use [chisel](https://github.com/jpillora/chisel) instead.
- Config files / TOML / YAML. The product surface is flags + `-ldflags`; that's enough.
- A built-in control plane. We ship one example (Adversario Arena) — others should fork or build their own.
- Performance "optimizations" that add complexity for < 10% wins.

## Dev loop

```bash
git clone https://github.com/dc-holdings-spa/arena-tunnel.git
cd arena-tunnel

# Build both binaries
make build

# Run server
./dist/arena-tunnel-server-linux-amd64 --listen 127.0.0.1:8888 --wg 127.0.0.1:51820 &

# Run client (you need a working local WG server to bridge to)
sudo ./dist/arena-tunnel-client-linux-amd64 -priv <priv> -pub <pub> -ip 10.200.0.2 -host localhost

# Lint
make lint

# Format
make fmt
```

## Style

- Standard `gofmt`. `make fmt` runs `gofmt -s -w`.
- One package per binary. No internal/ tree until we have ≥ 3 binaries that share code.
- Errors: wrap with `fmt.Errorf("%w", err)` when adding context; never silently swallow.
- Logging: `log.Printf`. No structured logging until v1.0 — we keep it parseable to humans tailing journalctl.
- Variable names: short, mnemonic. `ws`, `udp`, `dev`, `tdev`. Not `webSocketConnection`.

## PR checklist

- [ ] CI passes (build matrix + lint).
- [ ] You added/updated docs if you changed behavior.
- [ ] Commit messages explain WHY, not just what (the diff shows what).
- [ ] No new dependencies, OR you've justified them in the PR description.

## Release process

Maintainers only:

```bash
make release VERSION=v0.2.0
```

Pushes a tag → CI builds for 5 platforms → GitHub Release is auto-created with checksums and binaries attached.

## Code of Conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). The short version: be respectful, assume good faith, don't make me read a 10-paragraph manifesto in an issue.

## Maintainers

- Diego Collao (@dcollaoa) — adversario.cl
- Adversario AI agents — for routine reviews and CI babysitting
