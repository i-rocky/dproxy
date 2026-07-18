# Dproxy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Build a stateless Go CLI that runs development tools in disposable, least-privilege Docker containers with declarative plugins, immutable locks, isolated caches, and filtered networking.

**Architecture:** Managed shims invoke a trusted Go policy core. The core resolves project configuration and inert plugin manifests into a typed execution plan, then a Docker adapter creates a disposable command container and, when networked, a disposable filtering gateway on a unique internal network.

**Tech Stack:** Go 1.25, Cobra, pelletier/go-toml/v2, Masterminds/semver/v3, Docker Go SDK, golang.org/x/term, golang.org/x/sys, slog, GitHub Actions.

## Global Constraints

- MIT license; Linux with Docker Engine is the supported host.
- Every command and gateway container is automatically removed.
- Normal execution never builds tool images; images are locked by digest.
- Only the project, typed caches, ephemeral filesystems, and explicit ports are exposed.
- Host environment, home, root, agents, devices, namespaces, and engine sockets are absent.
- Plugins are strictly declarative and cannot weaken core policy.
- Isolation, gateway, or digest-verification failures stop execution.
- Meaningful statement coverage is strictly greater than 80%, with positive and negative tests for every security decision.
- Each task uses TDD and ends in an independent commit.

---

## File Map

    cmd/dproxy/main.go                 Entry point
    internal/cli/root.go               Commands and shim dispatch
    internal/project/discovery.go      Root, workdir, project ID
    internal/config/config.go          Strict project configuration
    internal/plugin/manifest.go        Provider schema
    internal/plugin/store.go           Safe Git synchronization
    internal/lock/lock.go              Immutable lockfile
    internal/resolver/resolver.go      Version and digest resolution
    internal/policy/plan.go            Trusted plan construction
    internal/cache/cache.go            Safe cache paths
    internal/shim/manager.go           Managed symlinks
    internal/engine/docker.go          Docker SDK adapter
    internal/network/policy.go         Destination policy
    internal/network/orchestrator.go   Network/gateway lifecycle
    internal/runtime/runtime.go        TTY, signals, exit, cleanup
    internal/gateway/                  Filtering gateway
    internal/diagnostic/explain.go     Redacted plans
    test/integration/                  Adversarial Docker suite

### Task 1: Bootstrap CLI, configuration, and project discovery

**Files:**
- Create: go.mod
- Create: LICENSE
- Create: cmd/dproxy/main.go
- Create: internal/cli/root.go
- Create: internal/cli/root_test.go
- Create: internal/fault/fault.go
- Create: internal/project/discovery.go
- Create: internal/project/discovery_test.go
- Create: internal/config/config.go
- Create: internal/config/config_test.go

**Interfaces:**
- Produces cli.Execute(ctx context.Context, argv0 string, args []string, stdout, stderr io.Writer) int.
- Produces project.Find(start string) (Project, error), where Project contains Root, RelativeWorkdir, and ID.
- Produces config.Load(path string) (Config, error) with typed tools, sandbox, ports, environment, and network allowlist.

- [ ] **Step 1: Write failing command, discovery, and strict-decoding tests**

    func TestVersion(t *testing.T) {
        var out, errOut bytes.Buffer
        code := Execute(context.Background(), "dproxy", []string{"version"}, &out, &errOut)
        require.Equal(t, 0, code)
        require.Equal(t, "dproxy dev\n", out.String())
    }

    func TestFindNearestProject(t *testing.T) {
        root := t.TempDir()
        nested := filepath.Join(root, "a", "b")
        require.NoError(t, os.MkdirAll(nested, 0755))
        require.NoError(t, os.WriteFile(filepath.Join(root, ".dproxy.toml"), []byte("schema = 1\n"), 0644))
        p, err := Find(nested)
        require.NoError(t, err)
        require.Equal(t, root, p.Root)
        require.Equal(t, "a/b", p.RelativeWorkdir)
    }

    func TestConfigRejectsUnknownSecurityField(t *testing.T) {
        path := writeConfig(t, "schema=1\n[sandbox]\nprivileged=true\n")
        _, err := Load(path)
        require.ErrorContains(t, err, "unknown field")
    }

- [ ] **Step 2: Run go test ./internal/cli ./internal/project ./internal/config -v**

Expected: FAIL because the module and functions do not exist.

- [ ] **Step 3: Implement the smallest passing CLI and strict config loader**

    func Execute(ctx context.Context, argv0 string, args []string, stdout, stderr io.Writer) int {
        root := newRootCommand(stdout, stderr)
        root.SetArgs(args)
        if err := root.ExecuteContext(ctx); err != nil {
            fmt.Fprintln(stderr, err)
            return 2
        }
        return 0
    }

    func Load(path string) (Config, error) {
        raw, err := os.ReadFile(path)
        if err != nil { return Config{}, err }
        var c Config
        dec := toml.NewDecoder(bytes.NewReader(raw))
        dec.DisallowUnknownFields()
        if err := dec.Decode(&c); err != nil { return Config{}, err }
        if c.Schema != 1 { return Config{}, ErrSchema }
        return c, validate(c)
    }

Find walks upward, verifies containment before computing the relative workdir, rejects symlinked identity files, and atomically creates a random 128-bit project ID. main.go exits with Execute’s status. Typed errors never contain secret values.

- [ ] **Step 4: Run gofmt -w cmd internal && go mod tidy && go test -race ./...**

Expected: PASS.

- [ ] **Step 5: Commit**

    git add go.mod go.sum LICENSE cmd internal
    git commit -m "feat: bootstrap dproxy projects and configuration"

### Task 2: Add declarative plugins and safe Git synchronization

**Files:**
- Create: internal/plugin/manifest.go
- Create: internal/plugin/manifest_test.go
- Create: internal/plugin/store.go
- Create: internal/plugin/store_test.go
- Create: internal/plugin/git.go
- Create: plugins/official/node.toml
- Create: plugins/official/bun.toml
- Create: plugins/official/python.toml
- Create: plugins/official/go.toml
- Create: plugins/official/rust.toml

**Interfaces:**
- Produces plugin.LoadManifest(io.Reader) (Manifest, error) and Manifest.Command(binary string).
- Produces Store.Add, Store.Sync, Store.Resolve and a Git interface whose methods receive literal argument lists.

- [ ] **Step 1: Write failing schema and repository-trust tests**

    func TestManifestRejectsExecutableFields(t *testing.T) {
        for _, field := range []string{"hook=\"sh evil\"", "docker_args=[\"--privileged\"]", "mount=\"/:/host\""} {
            input := "schema=1\nname=\"x\"\nbins=[\"x\"]\n" + field
            _, err := LoadManifest(strings.NewReader(input))
            require.Error(t, err, field)
        }
    }

    func TestCommunityRepositoryRequiresTrust(t *testing.T) {
        s := newTestStore(t)
        err := s.Add(context.Background(), "https://example.test/plugins.git", TrustDecision{})
        require.ErrorIs(t, err, ErrTrustRequired)
    }

- [ ] **Step 2: Run go test ./internal/plugin -v**

Expected: FAIL because plugin types do not exist.

- [ ] **Step 3: Implement a closed manifest schema and non-executing Git adapter**

Manifest contains schema, name, binaries, approved image repository/tag mapping, typed commands, container cache paths, fixed environment, and platform metadata. Decode with unknown-field rejection. Validate basename-only binaries, unique names, clean absolute container paths, command prefixes, and fixed environment values.

Git uses exec.CommandContext with literal arguments and no shell. Set GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null, GIT_TERMINAL_PROMPT=0, and core.hooksPath to an empty owned directory. Checkout detached commits; reject symlinks and non-manifest files from the indexed tree; persist trust, commit, and hashes atomically.

- [ ] **Step 4: Add official manifests and run gofmt -w internal/plugin && go test -race ./internal/plugin**

Expected: PASS, including tests that load all official manifests and prove metacharacters remain inert arguments.

- [ ] **Step 5: Commit**

    git add internal/plugin plugins/official go.mod go.sum
    git commit -m "feat: add safe declarative plugin registry"

### Task 3: Resolve immutable locks and construct execution policy

**Files:**
- Create: internal/lock/lock.go
- Create: internal/lock/lock_test.go
- Create: internal/resolver/resolver.go
- Create: internal/resolver/resolver_test.go
- Create: internal/policy/plan.go
- Create: internal/policy/plan_test.go

**Interfaces:**
- Produces resolver.Registry.Tags and Digest plus resolver.Resolve.
- Produces lock.Load, lock.WriteAtomic, and File.Verify.
- Produces policy.Build(Input) (Plan, error).

- [ ] **Step 1: Write failing deterministic-resolution and least-privilege tests**

    func TestResolveHighestMatchingDigest(t *testing.T) {
        reg := fakeRegistry{
            tags: []string{"23.9.0", "24.1.0", "24.4.1", "25.0.0"},
            digest: "sha256:" + strings.Repeat("d", 64),
        }
        got, err := Resolve(context.Background(), configWith("node", "24"), manifests(), reg)
        require.NoError(t, err)
        require.Equal(t, "24.4.1", got.Tools["node"].Version)
        require.Equal(t, reg.digest, got.Tools["node"].Digest)
    }

    func TestPlanHasNoHostAuthority(t *testing.T) {
        got, err := Build(validInput("npm", []string{"install"}))
        require.NoError(t, err)
        require.True(t, got.ReadOnlyRoot)
        require.True(t, got.NoNewPrivileges)
        require.Equal(t, []string{"ALL"}, got.CapDrop)
        require.NotContains(t, got.Environment, "AWS_SECRET_ACCESS_KEY")
        require.Equal(t, []string{"npm", "install"}, got.Command)
    }

- [ ] **Step 2: Run go test ./internal/lock ./internal/resolver ./internal/policy -v**

Expected: FAIL because the packages do not exist.

- [ ] **Step 3: Implement lock and plan types**

    type Tool struct { Requested, Version, Image, Tag, Digest, Platform string }
    type File struct {
        Schema int
        ConfigSHA256 string
        Tools map[string]Tool
        Plugins map[string]Plugin
    }

    type Plan struct {
        InvocationID, ProjectID, Image, Workdir string
        Command []string
        Environment map[string]string
        Mounts []Mount
        Tmpfs []Tmpfs
        Ports []Port
        UID, GID, Pids int
        MemoryBytes int64
        CPUs float64
        ReadOnlyRoot, NoNewPrivileges, AutoRemove bool
        CapDrop []string
        Network Network
    }

Sort map keys for hashing and output. Require exact platform and sha256 plus 64 lowercase hexadecimal characters. Write locks with file and parent fsync plus atomic rename. Policy accepts only the project and cache-manager paths; rejects root mounts, unlocked images, reserved environment keys, unsafe ports, invalid bounds, and unknown commands. Copy all collections.

- [ ] **Step 4: Run gofmt and race tests, then fuzz policy.Build for 10 seconds**

Expected: PASS; repeated lock serialization is byte-identical and fuzzing produces no escaped mount or panic.

- [ ] **Step 5: Commit**

    git add internal/lock internal/resolver internal/policy go.mod go.sum
    git commit -m "feat: lock toolchains and build execution policy"

### Task 4: Manage caches, shims, and diagnostics safely

**Files:**
- Create: internal/cache/cache.go
- Create: internal/cache/cache_test.go
- Create: internal/shim/manager.go
- Create: internal/shim/manager_test.go
- Create: internal/diagnostic/explain.go
- Create: internal/diagnostic/explain_test.go

**Interfaces:**
- Produces cache.Manager.Path, Clean, and Prune.
- Produces shim.Manager.Sync, Remove, and Owned.
- Produces diagnostic.Explain(policy.Plan) string.

- [ ] **Step 1: Write failing traversal, ownership, collision, and redaction tests**

    func TestCacheRejectsTraversal(t *testing.T) {
        _, err := newCache(t).Path("project", "node", "../escape", "24", "linux-amd64")
        require.ErrorIs(t, err, ErrUnsafeKey)
    }

    func TestShimRefusesUnmanagedCollision(t *testing.T) {
        m := newShimManager(t)
        writeRegularFile(t, filepath.Join(m.BinDir, "node"))
        require.ErrorIs(t, m.Sync(map[string]Target{"node": {Binary: "node"}}), ErrCollision)
    }

    func TestExplainRedactsEnvironment(t *testing.T) {
        got := Explain(planWithEnv(map[string]string{"TOKEN": "secret"}))
        require.Contains(t, got, "TOKEN=<redacted>")
        require.NotContains(t, got, "secret")
    }

- [ ] **Step 2: Run go test ./internal/cache ./internal/shim ./internal/diagnostic -v**

Expected: FAIL because managers and Explain do not exist.

- [ ] **Step 3: Implement descriptor-relative ownership checks**

Permit only alphanumeric, dot, underscore, and hyphen cache keys. Use openat2 with RESOLVE_BENEATH and RESOLVE_NO_SYMLINKS and fail closed when secure deletion cannot be proven. Create one generic argv0 shim; managed links in ~/.local/bin point to it. Record and verify target/inode ownership before atomic update or removal. Explain emits image digest, destinations, ports, policy, and environment names only.

- [ ] **Step 4: Run gofmt and race tests including concurrent symlink replacement**

Expected: PASS.

- [ ] **Step 5: Commit**

    git add internal/cache internal/shim internal/diagnostic
    git commit -m "feat: manage caches shims and redacted plans"

### Task 5: Implement the Docker engine boundary and runtime lifecycle

**Files:**
- Create: internal/engine/engine.go
- Create: internal/engine/docker.go
- Create: internal/engine/docker_test.go
- Create: internal/runtime/runtime.go
- Create: internal/runtime/runtime_test.go

**Interfaces:**
- Engine provides Verify, PullByDigest, CreateNetwork, StartGateway, StartCommand, Attach, Wait, Signal, RemoveContainer, RemoveNetwork, and ListOwned.
- runtime.Run(ctx, Dependencies, Plan, IO) returns command exitCode and setup error separately.

- [ ] **Step 1: Write failing Docker mapping and cleanup tests**

    func TestDockerMapsIsolationControls(t *testing.T) {
        api := &fakeDockerAPI{}
        _, err := NewDocker(api).StartCommand(context.Background(), lockedDownPlan())
        require.NoError(t, err)
        h := api.lastCreate.HostConfig
        require.True(t, h.ReadonlyRootfs)
        require.Equal(t, []string{"ALL"}, h.CapDrop)
        require.Equal(t, []string{"no-new-privileges"}, h.SecurityOpt)
        require.False(t, h.Privileged)
        require.Nil(t, h.Devices)
    }

    func TestRunReturnsExitAndCleansUp(t *testing.T) {
        d := fakeDependencies(42)
        code, err := Run(context.Background(), d, lockedDownPlan(), testIO())
        require.NoError(t, err)
        require.Equal(t, 42, code)
        require.Equal(t, []string{"remove-command", "remove-gateway", "remove-network"}, d.cleanupCalls())
    }

- [ ] **Step 2: Run go test ./internal/engine ./internal/runtime -v**

Expected: FAIL because the packages do not exist.

- [ ] **Step 3: Implement exact SDK mapping and lifecycle relay**

Reject non-Linux/unverified engines, insufficient API versions, missing controls, and digestless images. Never call a shell or Docker CLI. Map typed labels, user, mounts, tmpfs, resources, readonly root, cap drop, no-new-privileges, internal network, ports, and auto-remove.

Attach before start, use raw mode only for a TTY, restore it with defer, forward SIGINT/SIGTERM/SIGWINCH, preserve command status, and clean with a bounded context after cancellation. Never log environment values.

- [ ] **Step 4: Run gofmt -w internal/engine internal/runtime && go test -race ./internal/engine ./internal/runtime**

Expected: PASS. Integration-tagged Docker smoke, TTY, signal, and exit tests must PASS on release workers rather than skip.

- [ ] **Step 5: Commit**

    git add internal/engine internal/runtime go.mod go.sum
    git commit -m "feat: execute hardened disposable containers"

### Task 6: Build the filtered gateway and network orchestrator

**Files:**
- Create: internal/network/policy.go
- Create: internal/network/policy_test.go
- Create: internal/network/orchestrator.go
- Create: internal/network/orchestrator_test.go
- Create: internal/gateway/main.go
- Create: internal/gateway/filter.go
- Create: internal/gateway/filter_test.go
- Create: build/gateway/Dockerfile

**Interfaces:**
- network.Policy exposes AllowsIP, AllowsDomain, and AllowsPort.
- gateway.Filter.ResolveAndAuthorize returns pinned public addresses.
- Orchestrator.Start returns an idempotently closable Session.

- [ ] **Step 1: Write failing protected-range, rebinding, and rollback tests**

    func TestPublicBlocksProtectedAddresses(t *testing.T) {
        blocked := []string{"127.0.0.1", "10.0.0.1", "172.17.0.1", "192.168.1.1", "169.254.169.254", "::1", "fc00::1", "::ffff:127.0.0.1"}
        for _, raw := range blocked {
            require.False(t, Public().AllowsIP(netip.MustParseAddr(raw)), raw)
        }
    }

    func TestStartRollsBackOnGatewayHealthFailure(t *testing.T) {
        e := &fakeEngine{healthErr: errors.New("bad")}
        _, err := NewOrchestrator(e).Start(context.Background(), publicRequest())
        require.Error(t, err)
        require.Equal(t, []string{"remove-gateway", "remove-network"}, e.rollbackCalls)
    }

- [ ] **Step 2: Run go test ./internal/network ./internal/gateway -v**

Expected: FAIL because filtering and orchestration do not exist.

- [ ] **Step 3: Implement deny-first filtering and fail-closed setup**

Use IANA special-purpose IPv4/IPv6 prefixes plus active Docker subnets. Unmap mapped IPv4, canonicalize IDNs, reject ambiguous numeric forms, evaluate every DNS answer, pin authorized addresses for each connection, and re-evaluate redirects. Gateway loads a read-only JSON policy and exits unless DNS, transparent TCP/UDP forwarding, and firewall setup succeed.

Orchestrator creates a random invocation ID and internal network, starts the digest-pinned gateway, requires authenticated health, and only then allows the command. Mode none uses an isolated network without gateway. Roll back resources in reverse order. The scratch gateway image is built only for test/release, never normal execution.

- [ ] **Step 4: Run race tests, destination fuzzing for 20 seconds, gateway self-test, and concurrent orchestration tests**

Expected: PASS with unique networks, protected ranges denied, public fixtures allowed, and exactly-once cleanup.

- [ ] **Step 5: Commit**

    git add internal/network internal/gateway build/gateway
    git commit -m "feat: enforce filtered disposable networking"

### Task 7: Wire the complete CLI and adversarial integration suite

**Files:**
- Modify: internal/cli/root.go
- Modify: internal/cli/root_test.go
- Modify: cmd/dproxy/main.go
- Create: test/integration/harness_test.go
- Create: test/integration/isolation_test.go
- Create: test/integration/network_test.go
- Create: test/integration/lifecycle_test.go
- Create: test/integration/cache_test.go
- Create: test/fixtures/attacker/main.go
- Create: test/fixtures/servers/main.go

**Interfaces:**
- Produces init, lock, update, tool, plugin, setup, doctor, cache, uninstall, explain, dry-run, direct dispatch, and argv0 dispatch.
- Produces release-blocking adversarial evidence.

- [ ] **Step 1: Test shim dispatch and create a failing attacker scenario**

    func TestShimDispatchesBinary(t *testing.T) {
        deps := fakeDeps()
        code := ExecuteWithDeps(context.Background(), "npm", []string{"install"}, deps)
        require.Equal(t, 0, code)
        require.Equal(t, []string{"npm", "install"}, deps.plan.Command)
    }

    func TestSandboxDeniesHostAndAllowsProject(t *testing.T) {
        result := runAttacker(t, publicPolicyFixture())
        require.True(t, result.ProjectWrite)
        require.False(t, result.HostCanaryRead)
        require.False(t, result.HostEnvRead)
        require.False(t, result.DockerSocketPresent)
    }

- [ ] **Step 2: Run unit CLI tests and integration tests**

Expected: FAIL until dispatch and the hermetic fixture networks/images are wired.

- [ ] **Step 3: Wire commands and complete adversarial fixtures**

Direct and shim calls share one resolution path. Return 2 for usage/setup errors, 125 for sandbox creation, and the command’s status after start. Dry-run performs no Docker mutation.

The attacker attempts host-canary reads, environment/proc enumeration, engine-socket access, host/private/metadata/public probes over IPv4/IPv6, DNS rebinding, symlink swaps, cross-project cache poisoning, excess forks/memory, and an allowed project write. Create hermetic public/private/metadata servers. Test interruption and query ownership labels for zero leaks. Run two projects concurrently to prove separation.

- [ ] **Step 4: Run go test -race ./... and go test -tags=integration -count=3 -race ./test/integration -v**

Expected: all PASS three times with no labeled Docker objects left.

- [ ] **Step 5: Commit**

    git add cmd internal/cli test
    git commit -m "feat: complete dproxy command flow and isolation tests"

### Task 8: Enforce coverage, CI, release integrity, and documentation

**Files:**
- Create: scripts/check-coverage.sh
- Create: .github/workflows/ci.yml
- Create: .github/workflows/release.yml
- Create: README.md
- Create: SECURITY.md
- Create: docs/plugin-schema.md
- Create: docs/threat-model.md

**Interfaces:**
- Produces release gates, signed artifacts, documentation, and the published gateway digest contract.

- [ ] **Step 1: Write and test the strict coverage gate**

    #!/bin/sh
    set -eu
    profile=coverage.out
    percent=$(go tool cover -func="$profile" | awk '/^total:/ {gsub("%", "", $3); print $3}')
    awk -v p="$percent" 'BEGIN {
        if (p <= 80.0) {
            printf "coverage %.1f%% must be >80%%\n", p > "/dev/stderr"
            exit 1
        }
    }'

Run unit tests with coverage.out and verify this fails when coverage is 80% or lower.

- [ ] **Step 2: Add meaningful positive and negative tests until the gate passes**

Run go test -race ./... -coverprofile=coverage.out and scripts/check-coverage.sh. Expected: PASS strictly above 80%. Inspect uncovered policy decisions and add behavioral assertions, never execution-only tests.

- [ ] **Step 3: Add CI and release workflows**

CI runs formatting, vet, race tests, coverage, official-manifest validation, gateway self-test, Docker integration, and adversarial tests. Release uses pinned builders, creates static CLI binaries and scratch gateway, emits checksums and SBOMs, signs binaries/image with keyless Sigstore, publishes the immutable gateway digest, and rejects skipped qualification jobs.

- [ ] **Step 4: Write user, schema, threat-model, and disclosure documentation**

README covers init, tool add/remove, lock, setup, shims, networking, ports, cache, explain, and uninstall. Threat model explicitly says project files including .env are readable and can be exfiltrated to permitted destinations. Plugin docs enumerate every allowed field and rejection rule. SECURITY.md defines private reporting.

- [ ] **Step 5: Run final qualification**

    gofmt -w .
    go vet ./...
    go test -race ./... -coverprofile=coverage.out
    sh scripts/check-coverage.sh
    go test -tags=integration -count=3 ./test/integration -v

Expected: all PASS, coverage strictly greater than 80%, and no dproxy-labeled Docker resources remain.

- [ ] **Step 6: Commit**

    git add .github scripts README.md SECURITY.md docs go.mod go.sum
    git commit -m "build: enforce secure release qualification"

## Final Verification

- [ ] Race-enabled unit tests pass with coverage strictly greater than 80%.
- [ ] Vet and formatting checks pass.
- [ ] Integration/adversarial tests pass three consecutive times.
- [ ] Docker contains no completed dproxy invocation objects.
- [ ] Explain output for every official provider contains no secrets or undeclared mounts.
- [ ] Every design acceptance criterion maps to passing evidence.

