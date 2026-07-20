# dproxy

Run untrusted developer toolchains — `node`, `npm`, `npx`, `bun`, `python`, `uv`,
`go`, `cargo`, `rustc`, and more — in disposable, locked-down containers so
package and build code cannot reach unrelated host resources. dproxy proxies the
whole toolchain, not only package installation.

dproxy is a single stateless host binary (no daemon, no persistent containers).
Every command runs in a fresh `--rm` container with `CAP_DROP=ALL`, a read-only
root filesystem, `no-new-privileges`, and explicit resource limits. Networking is
deny-by-default and, when enabled, is filtered through a digest-pinned gateway.

## Host support

**Linux today.** dproxy runs on Linux hosts with Docker Engine.

macOS and Windows are tracked **same-release work**, not a future version: the
gateway dataplane backends (PF on darwin, WFP on windows) and the non-Linux
hardened-filesystem-ownership backends are not yet implemented. See
[`docs/platform-backends.md`](docs/platform-backends.md) for the concrete work
items and their fail-closed acceptance criteria. The design commitment is
all-OS from day one — see the
[design spec](docs/superpowers/specs/2026-07-18-dproxy-design.md).

## Prerequisites

- Linux host
- Docker Engine (API ≥ 1.40), reachable by the invoking user
- A Go toolchain is only required to build dproxy itself

## Install

```sh
go install github.com/i-rocky/dproxy/cmd/dproxy@latest
dproxy install
```

`dproxy install` wires global shims and shell integration (PATH + completion)
into your shell rc with no project required. Restart your shell (or re-source
its rc) afterward. On first use of a tool, dproxy auto-locks that tool's image
digest into a global project so the digest-pinning invariant holds even without
a prior `dproxy init`.

## Per-project use

```sh
cd my-project
dproxy init          # writes .dproxy.toml (requested tools + sandbox policy)
dproxy lock          # resolves images and pins digests to .dproxy.lock
dproxy npm install   # runs `npm install` sandboxed
```

`dproxy <tool> [args]` runs the tool in the foreground and relays its terminal,
signals, and exit status. `dproxy --explain <tool>` prints the resolved plan
(mounts, egress allowlist, resource limits) without running anything.

## Health check and setup

```sh
dproxy doctor
```

`dproxy doctor` verifies the Docker engine, the user configuration, and the
bundled plugins. When the user configuration is missing it **auto-provisions**:
it resolves the published gateway image for your platform, pulls it, and writes a
digest-pinned `~/.config/dproxy/config.toml`. Run it once after install.

## Plugins

dproxy is driven by plugin manifests (TOML) that declare a tool's image, caches,
commands, and registry egress. The official set — `node`/`npm`/`npx`, `python`/
`pip`/`uv`, `go`/`gofmt`, `cargo`/`rustc`/`rustfmt`, `bun`/`bunx` — is **embedded
in the dproxy binary**, with provenance (repository + commit + manifest digest)
derived from the build so a plain `go install` works without release flags. To
use additional or custom plugins, trust an external Git repository:

```sh
dproxy plugin add --trust https://github.com/you/your-dproxy-plugins
dproxy plugin list
```

## How it works

For each invocation dproxy finds the nearest `.dproxy.toml`, verifies
`.dproxy.lock`, resolves the tool image by **immutable digest**, builds the
sandbox policy, and starts the command container. When networking is enabled it
also creates a per-invocation network and a trusted filtering gateway that
enforces DNS redirection to a validated resolver and pinned-endpoint allowlists.
All per-invocation containers and networks are removed when the command exits.

See the [design spec](docs/superpowers/specs/2026-07-18-dproxy-design.md) for the
full architecture, trusted computing base, and threat model.

## Security posture

dproxy exposes no host resources except explicitly mounted project paths and
dproxy-managed caches. See [`SECURITY.md`](SECURITY.md) for the full policy.

Two limitations are stated honestly:

- **The project directory is mounted read/write.** Tools must be able to create
  lockfiles, dependencies, and build output, so sandboxed code can read and
  modify project contents — including `.env`, source, and `.git` when present.
  Host files are protected by being absent, not by UID isolation.
- **Registry-front egress has a residual channel.** When a tool's allowlist is
  derived from its manifest (e.g. `npm` → `registry.npmjs.org`), shared CDN
  fronts mean an allowed destination cannot always be distinguished from an
  unrelated one on the same front.

## Documentation

- [Design spec](docs/superpowers/specs/2026-07-18-dproxy-design.md)
- [Platform backends (macOS/Windows tracking)](docs/platform-backends.md)
- [Security policy](SECURITY.md)

## License

MIT — see [LICENSE](LICENSE).
