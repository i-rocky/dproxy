# Platform backends — same-release work for macOS and Windows

Dproxy targets Linux, macOS, and Windows from day one (see the design spec's
Platform Backends section). Today only the Linux backend is implemented and
verified. This file tracks the concrete work required to bring macOS and
Windows to the same bar. It is **not** a deferred phase — it is open work that
must land for those OSes to be supported.

The CLI fail-closes on unsupported OSes (`internal/cli/root.go`,
`assertSupportedRuntime`) and the hardened layer currently does not compile off
Linux. Expanding `supportedOSes` requires the backends below to pass the full
security integration suite; the gate must never be widened first.

## Current cross-OS compile blockers (Linux-only primitives)

A `GOOS=darwin go build ./...` fails today at, minimally:

- `internal/shim` — `unix.Renameat2`, `unix.RENAME_NOREPLACE`,
  `unix.RENAME_EXCHANGE` (atomic, no-replace directory-entry publication).
- `internal/cache` — `unix.Openat2`, `unix.OpenHow`,
  `unix.RESOLVE_BENEATH`, `unix.RESOLVE_NO_SYMLINKS` (descriptor-bounded path
  resolution), plus `Renameat2`.
- `internal/gateway` — `github.com/google/nftables`, `/proc/sys/net/...`
  forwarding, `SO_MARK`; the entire nftables ruleset and attestation path.

`internal/project` and `internal/plugin` are **not** compile blockers: their
hardened ancestry walks use portable `unix.Open`/`Openat`/`Fstat` with
`O_NOFOLLOW`/`O_DIRECTORY` and device+inode ownership records, all of which
build on darwin. They still require OS-backend verification (see Backend 2)
because the no-symlink/atomic-publication invariants rely on the surrounding
`openat2`/`renameat2` primitives that the other packages lack off Linux.

## Backend 1 — Gateway dataplane

Contract: reproduce the audited rule ordering from
`internal/gateway/dataplane.go` (`BuildRulePlan`) and `nft.go` (`NFT.Install`,
`NFT.Pin`), and pass `VerifyNFTAttestation`-equivalent attestation plus the
adversarial DNS/redirect/IPv4-IPv6 bypass suite.

- **Linux (done):** nftables — `internal/gateway/nft.go`. Reference backend.
- **macOS:** PF (Packet Filter). Translate the `BuildRulePlan` semantics (control
  mark bypass, established/related, DNS redirect to the local resolver,
  protected-prefix drops, pinned/public allow, default drop) into a PF ruleset
  loaded into a dedicated anchor. PF has no nftables-style "set with timeout"
  primitive; pinned-endpoint expiry needs an equivalent (e.g. `pfctl` refresh of
  a table with expiring entries, or a short-TTL re-pin). Confirm transparent
  DNS/TCP/UDP redirection works under PF and that `SO_MARK`-equivalent marking
  of the gateway's own upstream DNS is available (`pf` route/host tagging).
- **Windows:** WFP (Windows Filtering Platform). Implemented as a callout
  driver (kernel) or via the user-mode WFP API where sufficient. Requires C/C++
  or a Go cgo binding; pure-Go WFP is not available. Reproduce the redirect,
  pin, and drop semantics and the readiness attestation. This is the largest
  single backend.

Acceptance: identical deny-first behavior, DNS-answer pinning, redirect
re-evaluation, and the full `test/integration` network suite passing on the OS.

## Backend 2 — Hardened filesystem ownership

Contract: preserve the crash-safe, symlink-resistant, verify-before-mutate
ownership transactions that protect shim entries (`internal/shim/manager.go`),
cache directories (`internal/cache/cache.go`), project identity
(`internal/project/discovery.go`), and plugin state (`internal/plugin/store.go`).
The invariants are: publish via temp entry + atomic rename that fails if the
target already exists; record and verify device+inode+kind before any mutation;
never follow symlinks during resolution; refuse ambiguous targets.

- **Linux (done):** `openat2`/`RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS` +
  `renameat2(RENAME_NOREPLACE|RENAME_EXCHANGE)` + fd-relative ops. Reference.
- **macOS:** no `openat2`/`RESOLVE_BENEATH`. Use `openat` with `O_NOFOLLOW`
  per-component walks plus `fstat`/`lstat` checks, and `renamex_np` with
  `RENAME_EXCL`/`RENAME_SWAP` (Apple-specific) for atomic no-replace/swap
  publication. Verify each step rejects symlink substitution. `renamex_np`
  availability and semantics on the target filesystem (APFS vs others) must be
  confirmed.
- **Windows:** no POSIX symlinks-as-default. Shims currently are symlinks to a
  generic argv0 binary; Windows needs an equivalent dispatch (e.g. small
  launcher executables, or NTFS reparse points) that preserves the
  ownership-record verification model. `ReplaceFile`/`MoveFileExEx` with
  `REPLACEFILE_EXIST` semantics must be mapped to the no-replace atomic publish
  the Linux backend relies on. Re-examine UID/GID: Windows has none, so the
  `--user uid:gid` mapping and file-ownership guarantees need a Windows-specific
  story.

Acceptance: the shim/cache/project/plugin unit suites (traversal, ownership,
collision, concurrent replacement) pass with the OS backend, and integration
tests confirm correct file ownership for project writes.

## Container engine per-OS

Docker Engine on Linux is the verified target. Docker Desktop (macOS/Windows)
runs containers in a Linux VM: the in-VM gateway can still use the Linux
nftables backend, but host-side assumptions break — notably
`engine.ActiveDockerSubnets` discovery and the hardcoded `bridge` egress
network (`internal/cli/system.go`) assume native Linux Docker networking and
must be characterized against Desktop's VM topology before Desktop is treated
as supported. Windows Containers (vs Linux containers under Desktop) are a
separate path and not in scope for the day-one target.
