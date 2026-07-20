# Security policy

dproxy runs untrusted developer toolchains — package managers, compilers, build
scripts — inside disposable containers. Its job is to ensure that code cannot
reach host resources it was not explicitly granted. This document describes what
dproxy protects, how, and — importantly — what it does **not** protect against.

## Reporting a vulnerability

Report suspected vulnerabilities through GitHub's private vulnerability
reporting on the repository (Security → Report a vulnerability). Do not open a
public issue for security problems. Include the dproxy version (`dproxy
version`), the host OS, the container engine version, and a reproduction.

## Trust model

The trusted computing base is small and explicit:

- the **dproxy binary** itself,
- the **container engine** (Docker Engine on Linux),
- the **selected tool image** (resolved by immutable digest, never by tag),
- the **pinned dproxy gateway image** (also digest-pinned), and
- dproxy's **core policy implementation**.

Plugin repositories are **data, never executed**: a manifest describes how to
invoke a tool; it is not run. The host, the engine daemon, and the kernel
enforcing cgroups/namespaces/netfilter are trusted.

## Isolation controls

Every command container is created with all of the following, enforced by
`internal/engine` and verified before start:

- `--rm` — the container is destroyed when the command exits; nothing persists.
- `CAP_DROP=ALL` — no Linux capabilities, including `DAC_OVERRIDE`.
- Read-only root filesystem.
- `no-new-privileges`.
- Resource limits: pids, memory, and CPU are all bounded and required.
- UID/GID matching the invoking user — this exists so project files are owned
  correctly, **not** as a security boundary (see Limitations).
- Explicit mounts only: the project directory and dproxy-managed caches. No
  host secrets, `~/.ssh`, `~/.aws`, Docker socket, or `/proc` of the host are
  exposed.

## Network controls

Networking is deny-by-default. Three modes:

- **none** — loopback only; no external network.
- **public** — a filtering gateway permits outbound but drops protected
  destinations (RFC1918, link-local, cloud metadata `169.254.169.254`, etc.).
- **allowlist** — DNS is redirected to a validated in-gateway resolver; an
  answer is accepted only if its domain and port are allowed, and the resolved
  address is pinned as a (address, port) endpoint in netfilter. This defeats
  DNS rebinding: the name is resolved and authorized once, then the connection
  is forced to that exact endpoint.

The gateway is a separate container with `NET_ADMIN` and an nftables ruleset
that is **deny-first** (the base chain policy is drop). The command container
shares the gateway's network namespace, so all of its traffic passes through
the filter.

### Per-tool egress

A tool's outbound allowlist is derived from its plugin manifest
(`npm`/`bun` → npmjs, `python` → pypi, `cargo` → crates.io, etc.). The official
manifests ship **embedded in the dproxy binary** (with build-derived provenance);
additional plugins come from explicitly trusted Git repositories
(`dproxy plugin add --trust`). Either way, the effective allowlist is a
floor-union: the tool always reaches its own registry fronts, and a project may
widen but never narrow below that floor.

## Fail-closed guarantees

dproxy fails closed by construction:

- **Controls install atomically.** DNS interception, TCP/UDP forwarding, and the
  firewall all install before readiness is published. A partially configured
  gateway is never reported healthy; the readiness file is created only on
  success.
- **Health is attested, not assumed.** A health probe re-derives the expected
  nftables ruleset from policy and compares it byte-for-byte (modulo
  kernel-remapped registers) against what is actually installed in the kernel.
  A mismatch fails the probe. The probe is authenticated with a shared token.
- **Images are digest-pinned.** Resolution is by `@sha256:` digest; a tag-only
  reference is refused. The gateway image is pinned the same way.
- **Unsupported configurations are refused.** A missing isolation control, an
  unpinned image, or a network/netns state that does not match the policy is
  rejected before any container starts. An unsupported host OS fails closed at
  startup with a clear message.

## Limitations and residual risk

These are inherent to the design and are stated plainly:

- **The project directory is read/write.** Tools must create lockfiles,
  dependencies, and build output, so sandboxed code can read and modify project
  contents — including `.env`, source files, and `.git` when they are present.
  If code can both read a project secret and reach an allowed network
  destination, that secret can be exfiltrated. dproxy does not claim otherwise.
  Keep secrets out of the project tree, or grant network access only to tools
  that do not read them.
- **The container UID is not a complete security boundary.** Host files are
  protected primarily by being absent from the container, not by UID isolation.
- **Registry-front egress has a shared-CDN residual channel.** Manifest-derived
  allowlists target registry fronts by hostname; when an allowed front and an
  unrelated service share a CDN front (or an attacker controls a path on an
  allowed host), the filter cannot reliably distinguish them.
- **The gateway requires `NET_ADMIN`.** This is scoped to the gateway container
  only and used solely to install its own netfilter rules; it is not granted to
  command containers.
- **Linux only.** The hardened gateway (nftables) and filesystem-ownership
  backends are Linux-specific. macOS and Windows backends are tracked same-
  release work (see `docs/platform-backends.md`); until they land, those OSes
  fail closed.

## Hardening checklist for users

- Prefer `network: none`. Enable egress only for tools that need it.
- Keep secrets out of the mounted project directory.
- Pin tool images with `dproxy lock` and review the lockfile.
- Run `dproxy doctor` to verify the engine and configuration.
- Audit plugin manifests before trusting a repository (`dproxy plugin inspect`).
