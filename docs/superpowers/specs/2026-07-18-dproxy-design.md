# Dproxy Design

## Purpose

Dproxy runs development toolchains in disposable containers so untrusted package and build code cannot access unrelated host resources. It proxies complete toolchains—not only package installation—including commands such as `node`, `npm`, `npx`, `bun`, `bunx`, `python`, `uv`, `go`, `cargo`, and `rustc`.

Dproxy is a public MIT-licensed Go project. It uses existing official tool images wherever possible. Normal command execution does not build images, and every command container runs with `--rm`.

## Security Guarantee

Dproxy exposes no host resources except explicitly mounted project paths and dproxy-managed caches. Sandboxed code can freely use resources granted inside that boundary.

The project directory is mounted read/write so tools can create lockfiles, dependencies, generated files, and build output. Consequently, sandboxed code can read and modify project contents, including `.env`, source files, and `.git` when they exist in the project. Project secrets can be exfiltrated whenever code can both read them and communicate with an allowed network destination. Dproxy does not claim otherwise.

Host files remain protected because they are absent, not because the container UID is a complete security boundary. Matching the host UID and GID exists to produce correctly owned project files.

## Architecture

Dproxy is a single stateless host binary. It has no daemon and no persistent command containers. Managed command shims invoke the same binary, which detects the requested tool from `argv[0]`.

For each invocation, dproxy:

1. Finds the nearest `.dproxy.toml` by walking upward from the current directory.
2. Loads the matching declarative provider manifest.
3. Verifies `.dproxy.lock` is consistent with project configuration.
4. Resolves the locked tool image by immutable digest.
5. Constructs mounts, resource restrictions, environment, ports, and networking from trusted core policy.
6. Creates an isolated per-invocation network and trusted filtering gateway when networking is enabled.
7. Starts the command container in the foreground.
8. Relays its terminal, signals, and exit status.
9. Removes all per-invocation containers and networking resources.

The trusted computing base consists of the dproxy binary, the container engine, the selected tool image, the pinned dproxy gateway image, and dproxy's core policy implementation. Plugin repositories contain data and are never executed.

## Files and Directories

Project state:

```text
.dproxy.toml        Requested tools and sandbox policy
.dproxy.lock        Resolved versions, image digests, and plugin revisions
.dproxy/id          Stable generated project identity
```

User state follows XDG locations, with equivalent fallbacks where an XDG variable is unset:

```text
~/.config/dproxy/config.toml
~/.local/share/dproxy/plugins/
~/.local/share/dproxy/shims/
~/.cache/dproxy/
~/.local/bin/<managed tool symlinks>
```

Dproxy targets Linux, macOS, and Windows from day one. It is not a phased
release: the product is "all or nothing" across operating systems. Today the
verified implementation runs on Linux with Docker Engine; the macOS (PF) and
Windows (WFP) gateway backends and the non-Linux filesystem-ownership backends
are tracked same-release work in `docs/platform-backends.md`, not a future
version. An OS is only treated as supported once its backends pass the same
security integration suite; until then the CLI fails closed on unsupported OSes.
Docker Desktop and Podman are not silently treated as equivalent to Docker
Engine — their isolation behavior must pass the same suite before use.

## Container Execution

Each tool invocation creates a fresh command container with these core restrictions:

```text
--rm
--user <host-uid>:<host-gid>
--cap-drop ALL
--security-opt no-new-privileges
--read-only
--pids-limit <configured-limit>
--memory <configured-limit>
--workdir /workspace/<relative-directory>
```

The project root is mounted read/write at `/workspace`. Project-scoped caches are mounted only at paths declared by a validated provider. Writable `tmpfs` mounts provide `/tmp` and an ephemeral container home. No other host path is mounted.

Dproxy prohibits host root and home mounts, arbitrary absolute host paths, Docker and Podman sockets, host PID/IPC/network namespaces, privileged mode, added capabilities, devices, SSH/GPG agents, and security-profile overrides. Plugins cannot weaken these rules.

The host environment is not inherited. Dproxy constructs a minimal environment containing terminal settings, ephemeral home and cache paths, and explicit project configuration. Files such as `.env` remain visible as part of the project mount.

Official ecosystem images are preferred. Images are selected for compatibility rather than automatically preferring Alpine; musl-based images are used only when the resolved provider declares them compatible. A provider may expose multiple binaries already present in its image, but dproxy does not compose toolchains or build custom images. When an official image lacks a required cross-ecosystem tool, dproxy reports the incompatibility.

## Network Isolation

Network modes are:

- `none`: the command has no network access beyond its own loopback interface.
- `public`: traffic is routed through a trusted filtering gateway that permits public destinations and denies host and protected networks.
- `allowlist`: the gateway permits only configured domains and ports, while applying all `public` protections.

A tool's plugin manifest declares the registry fronts it needs (for example
`npm`→npmjs.org, `pip`→pypi.org, `cargo`→crates.io). Manifest egress is a floor:
whenever the gateway runs, the effective allowlist is the union of the tool's
manifest egress and any user-declared entries, so a tool can always reach its
own registry and the user may widen but never narrow below the floor. When a
project leaves the network mode unset (the default for frictionless use),
dproxy derives an allowlist from the invoked tool's manifest egress rather than
falling back to open access. Registry fronts commonly sit behind shared CDNs
(npmjs behind Cloudflare/Fastly, PyPI behind Fastly), so domain allowlisting
narrows but does not fully eliminate exfiltration: a malicious install step can
still reach any origin co-hosted on a permitted CDN. DNS-answer pinning and the
deny-first firewall tighten this further, but the residual CDN channel is a
known, accepted limit rather than a complete seal.

Ordinary unfiltered Docker bridge networking is not available through persistent project or plugin policy. Any future diagnostic escape hatch must be an explicit, conspicuous command-line action.

For `public` and `allowlist`, dproxy creates a unique internal Docker network. The command container attaches only to that network. A digest-pinned dproxy gateway container attaches to both the internal network and an outbound network. Both containers use `--rm`; the network is removed after execution.

The gateway blocks host and Docker bridge addresses, private networks, loopback, link-local, multicast, reserved ranges, cloud metadata endpoints, IPv4-mapped IPv6 bypasses, protected DNS answers, and redirects from public to protected destinations. Filtering covers IPv4, IPv6, DNS, and raw supported transport paths rather than relying only on HTTP proxy environment variables. The command container receives no additional capability; only the trusted gateway receives the narrow networking privileges necessary to filter and route traffic.

Ports are published only when explicitly configured. Publishing permits host-to-container connections to development servers without granting the command container access to host networking.

## Plugins

Plugins are versioned TOML manifests. The official set is embedded in the dproxy binary (with build-derived provenance, so a plain `go install` works without release flags); additional plugins are fetched from explicitly trusted Git repositories. They declare:

- Plugin name and schema version.
- Provided binary names.
- Approved official image repositories.
- Version discovery and version-to-tag mapping.
- Container entrypoint and typed argument mapping.
- Cache locations and compatibility keys.
- Safe fixed environment defaults.
- Registry egress: the host:port fronts a tool may reach from the sandbox.
- Compatibility and platform metadata.

Plugins cannot contain executable hooks, shell fragments, arbitrary Docker arguments, arbitrary mounts, environment passthrough, host namespaces, devices, privileged mode, added capabilities, or security overrides.

Git synchronization never executes repository Git hooks, scripts, or binaries. Dproxy validates manifests strictly and rejects unknown fields. Project lockfiles pin repository URL, Git commit, manifest hash, and schema version. Updates display capability changes before acceptance.

Dproxy ships official plugins embedded in the binary and also supports explicitly trusted community Git repositories. Adding a non-official repository requires an explicit trust action and records its immutable revision.

## Shims and Commands

`dproxy setup` (or `dproxy install`) installs managed symlinks in `~/.local/bin`. The symlinks target a single generic shim, a byte copy of the dproxy binary, under `~/.local/share/dproxy/shims`; the per-tool name is read from `argv[0]`. Symlink targets are constrained to that managed directory (symlink-resistance), which is why the generic shim is a copy rather than a link to the install path. Dproxy never overwrites an unmanaged path without explicit authorization. Ownership records and verified symlink targets ensure updates and uninstall remove only dproxy-managed entries.

Because the generic shim is a frozen copy, it would lag behind the real binary after an upgrade (for example `go install @latest` updates `~/go/bin/dproxy` but not the copy). To make a single upgrade update the whole install, `install` records the managing binary's absolute path next to the generic shim; on every invocation the generic shim reads that record and re-execs the recorded binary via `execve`, preserving `argv`, environment, controlling terminal, and exit status. The frozen copy's staleness is therefore transparent — the next invocation after an upgrade runs the fresh binary with no second command. If the record is absent or points somewhere invalid, the shim silently falls through to its own dispatch. `dproxy doctor` additionally refreshes the copy and record as a self-heal.

Shims are used instead of shell aliases so dispatch works from interactive shells, scripts, IDE terminals, and `/usr/bin/env <tool>`. Direct dispatch remains available as `dproxy <tool> [arguments...]`.

Primary commands include:

```text
dproxy init
dproxy lock
dproxy update <tool>|--all
dproxy tool add|remove
dproxy plugin add|remove|sync|list|inspect
dproxy setup
dproxy doctor
dproxy cache list|clean|prune
dproxy --explain <tool> ...
dproxy --dry-run <tool> ...
dproxy uninstall
```

## Configuration and Locking

An example `.dproxy.toml`:

```toml
schema = 1

[tools]
node = "24"
bun = ">=1.3, <2"
python = "3.14"
uv = "0.8"

[sandbox]
network = "public"
memory = "4GiB"
cpus = 4
pids = 512

[sandbox.ports]
"3000" = 3000
"4200" = 4200

[sandbox.environment]
NODE_ENV = "development"
```

The requested constraints are resolved into `.dproxy.lock`. Each tool entry records the request, exact version, image repository, tag, digest, and platform. Each plugin entry records its repository, commit, manifest hash, and schema version.

Normal execution does not re-resolve versions and never silently selects `latest`. Missing or stale lock state causes a closed failure with an instruction to run `dproxy lock`. Images are pulled and run by digest. Release metadata supports signature verification, but immutable digests remain mandatory.

## Caching

Command containers and their root filesystems are disposable. Project changes, dproxy-managed caches, and pulled images persist.

Caches are isolated by stable project ID, plugin, tool, compatibility version, operating system, and architecture. They are not shared across projects by default. A project ID stored in `.dproxy/id` preserves cache identity when a project moves.

Cache mounts are limited to provider-declared container paths. Cleanup operates only within verified dproxy-owned directories, does not follow untrusted symlinks, and refuses ambiguous targets.

## Process Lifecycle

Dproxy preserves stdin, stdout, stderr, terminal size, color behavior, interactive prompts, signals, and the command's exact exit status. It allocates a TTY only when the caller has one. Long-running development servers and concurrent invocations are supported.

Every Docker object receives ownership labels containing a managed marker, project ID, and cryptographically random invocation ID. Cleanup after success, failure, interruption, or a later recovery pass requires labels and recorded identifiers to agree; names alone are insufficient.

If gateway setup or any isolation control fails, dproxy fails closed and never falls back to unsafe execution.

## Errors and Diagnostics

Errors identify whether failure came from dproxy setup or the proxied command. Container command failures preserve their exit code. Targeted diagnostics cover missing configuration, stale locks, unknown shims, path collisions, unsupported platforms, unavailable engines, gateway failures, digest mismatches, and stale managed resources.

`--explain` reports the resolved provider, image digest, mounts, environment names, network policy, ports, and command. `--dry-run` emits the planned operation without starting containers. Sensitive values are redacted.

## Platform Backends

Two subsystems are inherently kernel-coupled and are isolated behind per-OS
backends so dproxy can target Linux, macOS, and Windows without weakening core
policy:

1. **Gateway dataplane** — transparent DNS/TCP/UDP interception and the
   deny-first firewall. The Linux backend is `nftables`; macOS requires a PF
   backend and Windows a WFP backend. Each backend must reproduce the audited
   `BuildRulePlan` ordering and pass the same attestation and adversarial tests.
2. **Hardened filesystem ownership** — the crash-safe, symlink-resistant
   transactions that protect shim, cache, project identity, and plugin state.
   The Linux backend uses `openat2`/`RESOLVE_BENEATH`/`renameat2`; macOS and
   Windows need ownership models that preserve the same no-symlink,
   verify-before-mutate guarantees without those Linux primitives.

Container user identity is also platform-specific: Linux and Docker-Desktop-on-Linux
match the host UID/GID to produce correctly owned files; Windows has no
UID/GID model and Docker Desktop (macOS/Windows) runs containers in a Linux VM
whose host↔container UID mapping and network topology differ from native Linux.
These differences are characterized per-OS rather than treated as equivalent.

The concrete work items, acceptance criteria, and current compile-time blockers
for the macOS and Windows backends live in `docs/platform-backends.md`.

## Implementation Stack

The CLI and gateway are implemented in Go. The project favors the standard library and a small reviewed dependency set.

Expected components include a hand-rolled CLI dispatcher, `pelletier/go-toml/v2`, Masterminds semver constraints, the Docker Go SDK, `golang.org/x/sys`, `miekg/dns`, and `google/nftables`. The gateway is published as a minimal signed dproxy image pinned by digest; users do not build it during command execution.

GitHub Actions provides CI. Releases include signed binaries, checksums, a software bill of materials, gateway image metadata, and reproducible-build information where practical.

## Testing Requirements

Dproxy core must maintain strictly greater than 80% meaningful statement coverage and meaningful decision-path coverage. CI fails at 80% or below. Go does not expose a native branch-percentage metric equivalent to LLVM tooling, so decision coverage is enforced through reviewed table-driven positive and negative cases for every policy branch.

Generated code, trivial platform bindings, and fixtures may be excluded only through an explicit reviewed allowlist. Tests must assert behavior rather than merely execute lines. Every security policy rule requires both permitted and rejected cases, and every security regression receives a permanent test.

Unit tests cover configuration, locking, provider validation, version resolution, mount construction, path normalization, environment handling, cache ownership, symlink resistance, shim ownership, Docker labels, and diagnostic redaction.

Integration tests use real disposable containers to verify project writes and ownership, denial of unrelated host resources, network filtering, IPv4/IPv6 and DNS bypass resistance, port publication, terminal behavior, signals, exit status, resource limits, concurrent invocation, cleanup, and cache separation.

Adversarial fixtures enumerate files and environment state, inspect `/proc`, probe networks, attempt cache poisoning and path traversal, modify allowed project content, create Git hooks, fork processes, exhaust resources, and exercise DNS and redirect bypasses. Expected access to the mounted project remains allowed; every undeclared host access must fail.

Security integration tests fail closed when a required capability is unavailable. They are never silently skipped in a release qualification job. Coverage reports and security-suite results are published in CI.

## Acceptance Criteria

The design is complete when:

- Managed shims transparently dispatch supported tool commands.
- Every command and gateway container is disposable.
- Only the project, declared caches, ephemeral filesystems, and explicit ports are exposed.
- Host environment, files, services, agents, sockets, and protected networks are unavailable.
- Plugins remain strictly declarative and cannot weaken core policy.
- Tool and plugin resolution is reproducible through committed immutable lock data.
- Interactive and long-running commands behave like their native equivalents.
- Isolation failures stop execution rather than downgrade security.
- The meaningful coverage gate remains strictly above 80%, and the adversarial security suite passes.
