package cli

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/i-rocky/dproxy/internal/cache"
	"github.com/i-rocky/dproxy/internal/config"
	"github.com/i-rocky/dproxy/internal/engine"
	"github.com/i-rocky/dproxy/internal/lock"
	"github.com/i-rocky/dproxy/internal/network"
	"github.com/i-rocky/dproxy/internal/plugin"
	"github.com/i-rocky/dproxy/internal/policy"
	"github.com/i-rocky/dproxy/internal/project"
	"github.com/i-rocky/dproxy/internal/registry"
	"github.com/i-rocky/dproxy/internal/resolver"
	commandruntime "github.com/i-rocky/dproxy/internal/runtime"
	"github.com/i-rocky/dproxy/internal/shim"
	"github.com/i-rocky/dproxy/internal/testimage"
	"github.com/i-rocky/dproxy/plugins/official"

	dockerclient "github.com/docker/docker/client"
	"github.com/moby/term"
)

type systemRunner struct{}

func newSystemRunner() Runner { return systemRunner{} }

func (systemRunner) PlanCommand(_ context.Context, name string, args []string) (string, error) {
	switch name {
	case "cache":
		if len(args) == 2 && args[0] == "prune" && args[1] == "--all" {
			return "cache prune --all (would remove every managed project cache)", nil
		}
		if len(args) == 1 && args[0] == "list" {
			return "cache list (read-only)", nil
		}
		return "", errors.New("usage: dproxy --dry-run cache list|prune --all")
	default:
		return "", fmt.Errorf("dry-run is not supported for administrative command %q", name)
	}
}

type systemState struct {
	project                                  project.Project
	config                                   config.Config
	user                                     config.UserConfig
	store                                    *plugin.Store
	manifest                                 plugin.Manifest
	locked                                   lock.File
	platform, cacheRoot, stateRoot, dataRoot string
}

func (systemRunner) Resolve(ctx context.Context, binary string, args []string) (policy.Plan, error) {
	return resolveSystemPlan(ctx, binary, args, false)
}

func (systemRunner) ResolveReadOnly(ctx context.Context, binary string, args []string) (policy.Plan, error) {
	return resolveSystemPlan(ctx, binary, args, true)
}

func resolveSystemPlan(ctx context.Context, binary string, args []string, readOnly bool) (policy.Plan, error) {
	state, err := loadSystemState(ctx, binary, readOnly)
	if err != nil {
		return policy.Plan{}, err
	}
	tool, ok := state.locked.Tools[binary]
	if !ok {
		for _, provided := range state.manifest.Bins {
			if candidate, exists := state.locked.Tools[provided]; exists {
				tool, ok = candidate, true
				break
			}
		}
	}
	if !ok {
		return policy.Plan{}, fmt.Errorf("tool %q is not locked; run dproxy lock", binary)
	}
	cachePaths := map[string]string{}
	manager := cache.Manager{Root: state.cacheRoot}
	for _, declaration := range state.manifest.Caches {
		compatibility := compatibility(tool.Version, declaration.Compatibility)
		var path string
		if readOnly {
			path, err = manager.PlannedPath(state.project.ID, state.manifest.Name, binary, compatibility, strings.ReplaceAll(state.platform, "/", "-"))
		} else {
			path, err = manager.Path(state.project.ID, state.manifest.Name, binary, compatibility, strings.ReplaceAll(state.platform, "/", "-"))
		}
		if err != nil {
			return policy.Plan{}, err
		}
		cachePaths[declaration.Path] = path
	}
	return policy.Build(policy.Input{InvocationID: "planning", ProjectID: state.project.ID, ProjectRoot: state.project.Root, RelativeWorkdir: state.project.RelativeWorkdir, CacheRoot: state.cacheRoot, Platform: state.platform, Binary: binary, CachePaths: cachePaths, Arguments: args, UID: os.Getuid(), GID: os.Getgid(), Tool: tool, Manifest: state.manifest, Sandbox: state.config.Sandbox, ReadOnlyPlanning: readOnly})
}

func (systemRunner) Run(ctx context.Context, plan policy.Plan, streams Streams) (int, error) {
	return systemExecute(ctx, plan, streams)
}

var systemExecute = executeSystemPlan

func executeSystemPlan(ctx context.Context, plan policy.Plan, streams Streams) (int, error) {
	mappedImage, err := systemImageReferenceMapper(plan.Image)
	if err != nil {
		return 0, err
	}
	plan.Image = mappedImage
	user, _, runtimeStateRoot, _, err := loadUserState()
	if err != nil {
		return 0, err
	}
	de, orchestrator, err := systemRuntimeFactory(user)
	if err != nil {
		return 0, err
	}
	tty, fd := terminal(streams.Stdin)
	runtimeStreams := commandruntime.IO{Stdin: streams.Stdin, Stdout: streams.Stdout, Stderr: streams.Stderr, TTY: tty}
	if tty {
		runtimeStreams.MakeRaw = func() (func() error, error) {
			state, err := term.MakeRaw(fd)
			return func() error { return term.RestoreTerminal(fd, state) }, err
		}
		runtimeStreams.TerminalSize = func() (uint, uint, error) {
			size, err := term.GetWinsize(fd)
			if err != nil {
				return 0, 0, err
			}
			return uint(size.Height), uint(size.Width), nil
		}
	}
	code, runErr := systemRuntimeRun(ctx, commandruntime.Dependencies{Engine: de, Network: orchestrator, NetworkRequest: network.Request{GatewayImage: user.GatewayImage, EgressNetworkID: "bridge", StateDir: filepath.Join(runtimeStateRoot, "network")}}, plan, runtimeStreams)
	if runErr != nil {
		var post *commandruntime.PostStartError
		if errors.As(runErr, &post) {
			return code, runErr
		}
		return code, fmt.Errorf("%w: %v", ErrSandboxCreation, runErr)
	}
	return code, nil
}

var systemRuntimeRun = commandruntime.Run
var systemImageReferenceMapper = func(reference string) (string, error) { return reference, nil }
var systemRuntimeFactory = func(user config.UserConfig) (engine.Engine, commandruntime.NetworkManager, error) {
	api, err := dockerAPI(user)
	if err != nil {
		return nil, nil, err
	}
	de := engine.NewDocker(api)
	return de, network.NewOrchestrator(de), nil
}

func (systemRunner) Command(ctx context.Context, name string, args []string, streams Streams) error {
	switch name {
	case "init":
		return initProject(args)
	case "lock":
		return resolveLock(ctx, nil)
	case "update":
		return resolveLock(ctx, args)
	case "tool":
		return toolCommand(args)
	case "plugin":
		return pluginCommand(ctx, args, streams)
	case "setup":
		return setupCommand(streams)
	case "install":
		return installCommand(args, streams)
	case "doctor":
		return doctorCommand(ctx, streams)
	case "cache":
		return cacheCommand(args, streams)
	case "uninstall":
		if len(args) != 0 {
			return errors.New("usage: dproxy uninstall")
		}
		return uninstallCommand()
	default:
		return errors.New("unknown administrative command")
	}
}

func initProject(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: dproxy init")
	}
	if _, err := os.Lstat(".dproxy.toml"); err == nil {
		return errors.New("project is already initialized")
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := config.WriteAtomic(".dproxy.toml", config.Config{Schema: 1, Tools: map[string]string{}, Sandbox: config.Sandbox{}}); err != nil {
		return err
	}
	_, err := project.Find(".")
	return err
}

func resolveLock(ctx context.Context, args []string) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "--all" && strings.HasPrefix(args[0], "-") {
		return errors.New("usage: dproxy lock | dproxy update <tool>|--all")
	}
	p, err := project.Find(".")
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(p.Root, ".dproxy.toml"))
	if err != nil {
		return err
	}
	cfg, err := config.Load(filepath.Join(p.Root, ".dproxy.toml"))
	if err != nil {
		return err
	}
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return err
	}
	store, err := plugin.NewStore(filepath.Join(dataRoot, "plugins"), nil)
	if err != nil {
		return err
	}
	manifests := map[string]plugin.Manifest{}
	officialManifests, officialErr := official.Load()
	for name := range cfg.Tools {
		manifest, resolveErr := store.Resolve(name)
		if resolveErr != nil && officialErr == nil {
			var found bool
			manifest, found = officialManifests[name]
			if found {
				resolveErr = nil
			}
		}
		if resolveErr != nil {
			return fmt.Errorf("resolve provider for %q: %w", name, resolveErr)
		}
		manifests[name] = manifest
	}
	resolved, err := registryResolve(ctx, cfg, manifests, runtime.GOOS+"/"+runtime.GOARCH, lock.HashConfig(raw))
	if err != nil {
		return err
	}
	return lock.WriteAtomic(filepath.Join(p.Root, ".dproxy.lock"), resolved)
}

var registryResolve = func(ctx context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
	return resolver.Resolve(ctx, cfg, manifests, platform, hash, registry.New(nil))
}

func toolCommand(args []string) error {
	if len(args) < 2 || len(args) > 3 || args[0] != "add" && args[0] != "remove" {
		return errors.New("usage: dproxy tool add <name> [constraint] | remove <name>")
	}
	p, err := project.Find(".")
	if err != nil {
		return err
	}
	path := filepath.Join(p.Root, ".dproxy.toml")
	cfg, err := config.Load(path)
	if err != nil {
		return err
	}
	if args[0] == "add" {
		constraint := "*"
		if len(args) == 3 {
			constraint = args[2]
		}
		err = cfg.SetTool(args[1], constraint)
	} else {
		if len(args) != 2 {
			return errors.New("usage: dproxy tool remove <name>")
		}
		err = cfg.RemoveTool(args[1])
	}
	if err != nil {
		return err
	}
	return config.WriteAtomic(path, cfg)
}

func pluginCommand(ctx context.Context, args []string, streams Streams) error {
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return err
	}
	store, err := plugin.NewStore(filepath.Join(dataRoot, "plugins"), nil)
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: dproxy plugin add|remove|sync|list|inspect")
	}
	switch args[0] {
	case "add":
		if len(args) != 3 || args[1] != "--trust" {
			return errors.New("usage: dproxy plugin add --trust <https-repository>")
		}
		_, err = store.Add(ctx, args[2], plugin.TrustDecision{Explicit: true})
		return err
	case "remove":
		if len(args) != 2 {
			return errors.New("usage: dproxy plugin remove <name>")
		}
		return store.Remove(args[1])
	case "sync":
		if len(args) != 2 {
			return errors.New("usage: dproxy plugin sync <name>")
		}
		_, err = store.Sync(ctx, args[1])
		return err
	case "list":
		if len(args) != 1 {
			return errors.New("usage: dproxy plugin list")
		}
		return json.NewEncoder(streams.Stdout).Encode(store.List())
	case "inspect":
		if len(args) != 2 {
			return errors.New("usage: dproxy plugin inspect <name>")
		}
		item, inspectErr := store.Inspect(args[1])
		if inspectErr != nil {
			return inspectErr
		}
		return json.NewEncoder(streams.Stdout).Encode(item)
	default:
		return errors.New("usage: dproxy plugin add|remove|sync|list|inspect")
	}
}

func setupCommand(streams Streams) error {
	p, err := project.Find(".")
	if err != nil {
		return err
	}
	locked, err := lock.Load(filepath.Join(p.Root, ".dproxy.lock"))
	if err != nil {
		return err
	}
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return err
	}
	store, err := plugin.NewStore(filepath.Join(dataRoot, "plugins"), nil)
	if err != nil {
		return err
	}
	targets := map[string]shim.Target{}
	officialManifests, _ := official.Load()
	for binary := range locked.Tools {
		manifest, resolveErr := store.Resolve(binary)
		if resolveErr != nil {
			var found bool
			manifest, found = officialManifests[binary]
			if found {
				resolveErr = nil
			}
		}
		if resolveErr != nil {
			return resolveErr
		}
		for _, provided := range manifest.Bins {
			targets[provided] = shim.Target{Binary: provided}
		}
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0700); err != nil {
		return err
	}
	manager := shim.Manager{BinDir: filepath.Join(home, ".local", "bin"), ShimDir: filepath.Join(dataRoot, "shims"), Executable: executable}
	if err := manager.Sync(targets); err != nil {
		return err
	}
	fmt.Fprintf(streams.Stdout, "installed %d managed tool shims\n", len(targets))
	return nil
}

// defaultGatewayImage is the published deny-first gateway dproxy doctor pulls
// and pins when provisioning a user configuration. Tagged :latest; doctor
// resolves it to a platform-specific digest so the pin is immutable.
const defaultGatewayImage = "ghcr.io/i-rocky/dproxy-gateway:latest"

// officialLoad is the bundled-plugin loader; a variable so doctor's plugin
// check can be injected in tests (the test binary carries no provenance).
var officialLoad = official.Load

func doctorCommand(ctx context.Context, streams Streams) error {
	w := streams.Stdout
	fmt.Fprintln(w, "dproxy doctor")
	configDir, derr := os.UserConfigDir()
	if derr != nil {
		return fmt.Errorf("locate user config directory: %w", derr)
	}
	configPath := filepath.Join(configDir, "dproxy", "config.toml")
	user, loadErr := config.LoadUser(configPath)
	healthy := true
	// Engine check (injectable for tests). Uses the loaded engine endpoint, if any.
	if err := systemDoctorVerify(ctx, user); err != nil {
		fmt.Fprintf(w, "  docker engine: FAIL (%v)\n", err)
		return fmt.Errorf("docker engine: %w", err)
	}
	fmt.Fprintln(w, "  docker engine: OK")

	switch {
	case loadErr == nil:
		fmt.Fprintf(w, "  user configuration: OK (gateway %s)\n", user.GatewayImage)
	case errors.Is(loadErr, os.ErrNotExist):
		fmt.Fprintln(w, "  user configuration: MISSING — provisioning a gateway image")
		ref, ensureErr := ensureGatewayImage(ctx)
		if ensureErr != nil {
			fmt.Fprintf(w, "  gateway image: FAIL (%v)\n", ensureErr)
			return fmt.Errorf("provision gateway image: %w", ensureErr)
		}
		if werr := config.WriteUserAtomic(configPath, config.UserConfig{Schema: 1, GatewayImage: ref}); werr != nil {
			fmt.Fprintf(w, "  user configuration: FAIL (write: %v)\n", werr)
			return fmt.Errorf("write user configuration: %w", werr)
		}
		fmt.Fprintf(w, "  user configuration: FIXED (wrote %s, gateway %s)\n", configPath, ref)
	default:
		fmt.Fprintf(w, "  user configuration: FAIL (invalid: %v)\n", loadErr)
		healthy = false
	}
	if manifests, lerr := officialLoad(); lerr == nil {
		fmt.Fprintf(w, "  official plugins: OK (%d loadable)\n", len(manifests))
	} else {
		fmt.Fprintf(w, "  official plugins: FAIL (%v)\n", lerr)
		healthy = false
	}
	if _, _, dataRoot, rerr := userRoots(); rerr == nil {
		if store, serr := plugin.OpenStore(filepath.Join(dataRoot, "plugins"), nil); serr == nil {
			if repos := store.List(); len(repos) > 0 {
				fmt.Fprintf(w, "  trusted plugin repositories: %d\n", len(repos))
			}
		}
	}
	// Shims: the managed generic shim is a frozen copy of this binary made at
	// install time, so it goes stale after an upgrade (e.g. `go install`) and
	// every shimmed tool then fails with "plugin not found" until it is
	// refreshed. Detect staleness and repair it here so a re-install is not
	// required after every upgrade.
	executable, execErr := os.Executable()
	_, _, dataRoot, rootErr := userRoots()
	if execErr != nil || rootErr != nil {
		fmt.Fprintln(w, "  shims: run 'dproxy install' to (re)create managed tool shims")
	} else {
		shimPath := filepath.Join(dataRoot, "shims", genericShimName)
		stale, staleErr := shimBinaryIsStale(executable, shimPath)
		switch {
		case staleErr != nil:
			fmt.Fprintf(w, "  shims: FAIL (%v)\n", staleErr)
			healthy = false
		case !stale:
			fmt.Fprintln(w, "  shims: OK")
		default:
			n, refreshErr := refreshManagedShims()
			if refreshErr != nil {
				fmt.Fprintf(w, "  shims: FAIL (refresh: %v)\n", refreshErr)
				healthy = false
			} else {
				fmt.Fprintf(w, "  shims: FIXED (refreshed %d managed tool shims)\n", n)
			}
		}
	}
	if healthy {
		fmt.Fprintln(w, "all checks passed")
		return nil
	}
	return errors.New("one or more checks failed; see above")
}

// ensureGatewayImage provisions a digest-pinned gateway image: it resolves the
// published gateway's platform digest and pulls it, falling back to building
// from source (only possible in a source checkout). Returns a reference usable
// as UserConfig.GatewayImage. It is a variable so doctor's autofix path can be
// exercised in tests without a Docker engine.
var ensureGatewayImage = func(ctx context.Context) (string, error) {
	api, err := dockerclient.NewClientWithOpts(dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation())
	if err != nil {
		return "", err
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if digest, err := registry.New(nil).Digest(ctx, defaultGatewayImage, platform); err == nil {
		ref := "ghcr.io/i-rocky/dproxy-gateway@" + digest
		if err := engine.NewDocker(api).PullByDigest(ctx, ref); err == nil {
			return ref, nil
		}
	}
	if id, err := testimage.Scratch(ctx, api, "cmd/gateway", "gateway"); err == nil {
		return id, nil
	}
	return "", errors.New("published gateway image unavailable and source build failed (offline, or no source checkout)")
}

var systemDoctorVerify = func(ctx context.Context, user config.UserConfig) error {
	api, err := dockerAPI(user)
	if err != nil {
		return err
	}
	return engine.NewDocker(api).Verify(ctx)
}

// genericShimName is the frozen copy of the dproxy binary that every per-tool
// symlink targets (see internal/shim.genericName). Kept in sync by hand.
const genericShimName = "dproxy-shim"

// shimBinaryIsStale reports whether the managed generic shim is missing or
// differs from the running dproxy executable. The shim is a byte copy made at
// install time, so after an upgrade (e.g. `go install @latest`) it lags behind
// the real binary and every shimmed tool resolves to "plugin not found" until it
// is refreshed. A missing shim is treated as stale.
func shimBinaryIsStale(executable, shimPath string) (bool, error) {
	want, err := sha256OfFile(executable)
	if err != nil {
		return false, err
	}
	got, err := sha256OfFile(shimPath)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return string(got) != string(want), nil
}

func sha256OfFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return nil, err
	}
	return h.Sum(nil), nil
}

// refreshManagedShims re-copies the running dproxy binary into the managed shim
// directory and re-creates the per-tool symlinks, repairing staleness after an
// upgrade. It is the same operation `dproxy install` performs, minus the shell
// rc/completion wiring, so doctor stays a diagnostic. Injectable for tests.
var refreshManagedShims = func() (int, error) {
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return 0, err
	}
	executable, err := os.Executable()
	if err != nil {
		return 0, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return 0, err
	}
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0700); err != nil {
		return 0, err
	}
	// The hardened shim manager opens ShimDir beneath dataRoot with openat2
	// RESOLVE_BENEATH semantics, which create only the final path component — so
	// the parents must already exist (otherwise a first-run doctor on a fresh
	// machine fails with ENOENT). Mirror installCommand's directory setup.
	if err := os.MkdirAll(dataRoot, 0700); err != nil {
		return 0, err
	}
	targets, err := officialTargets()
	if err != nil {
		return 0, err
	}
	manager := shim.Manager{BinDir: filepath.Join(home, ".local", "bin"), ShimDir: filepath.Join(dataRoot, "shims"), Executable: executable}
	keep, _ := manageableTargets(manager, targets)
	if err := manager.Sync(keep); err != nil {
		return 0, err
	}
	return len(keep), nil
}

func cacheCommand(args []string, streams Streams) error {
	cacheRoot, _, _, err := userRoots()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: dproxy cache list|clean|prune --all")
	}
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return errors.New("usage: dproxy cache list")
		}
		entries, err := os.ReadDir(cacheRoot)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if entry.IsDir() && !strings.HasPrefix(entry.Name(), ".") {
				fmt.Fprintln(streams.Stdout, entry.Name())
			}
		}
		return nil
	case "prune":
		if len(args) != 2 || args[1] != "--all" {
			return errors.New("usage: dproxy cache prune --all (removes every managed project cache)")
		}
		return (cache.Manager{Root: cacheRoot}).Prune(map[string]struct{}{})
	case "clean":
		if len(args) != 4 {
			return errors.New("usage: dproxy cache clean <plugin> <tool> <compatibility>")
		}
		p, err := project.Find(".")
		if err != nil {
			return err
		}
		return (cache.Manager{Root: cacheRoot}).Clean(p.ID, args[1], args[2], args[3], strings.ReplaceAll(runtime.GOOS+"/"+runtime.GOARCH, "/", "-"))
	default:
		return errors.New("usage: dproxy cache list|clean|prune --all")
	}
}

func uninstallCommand() error {
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	manager := shim.Manager{BinDir: filepath.Join(home, ".local", "bin"), ShimDir: filepath.Join(dataRoot, "shims"), Executable: executable}
	owners := filepath.Join(dataRoot, "shims", ".owners")
	entries, err := os.ReadDir(owners)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			name := strings.TrimSuffix(entry.Name(), ".json")
			if name == "dproxy-shim" {
				continue
			}
			if err := manager.Remove(name); err != nil {
				return err
			}
		}
	}
	generic := filepath.Join(dataRoot, "shims", "dproxy-shim")
	if genericInfo, err := os.Lstat(generic); err == nil {
		recordRaw, readErr := os.ReadFile(filepath.Join(owners, "dproxy-shim.json"))
		var record struct{ Device, Inode uint64 }
		var stat syscall.Stat_t
		statErr := syscall.Stat(generic, &stat)
		if readErr != nil || json.Unmarshal(recordRaw, &record) != nil || statErr != nil || !genericInfo.Mode().IsRegular() || record.Device != uint64(stat.Dev) || record.Inode != stat.Ino {
			return errors.New("managed generic shim target is unsafe")
		}
		if err := os.Remove(generic); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(owners, "dproxy-shim.json")); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func loadSystemState(ctx context.Context, binary string, readOnly bool) (systemState, error) {
	p, findErr := findProject(".", readOnly)
	if errors.Is(findErr, project.ErrNotFound) {
		return loadGlobalSystemState(ctx, binary, readOnly)
	}
	if findErr != nil {
		return systemState{}, fmt.Errorf("discover project: %w", findErr)
	}
	configPath := filepath.Join(p.Root, ".dproxy.toml")
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return systemState{}, err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return systemState{}, err
	}
	user, cacheRoot, stateRoot, dataRoot, err := loadUserState()
	if err != nil {
		return systemState{}, err
	}
	if err := ensureRootParents(cacheRoot, stateRoot, dataRoot); err != nil {
		return systemState{}, err
	}
	locked, err := lock.Load(filepath.Join(p.Root, ".dproxy.lock"))
	if err != nil {
		return systemState{}, fmt.Errorf("load lock (run dproxy lock): %w", err)
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if err := locked.Verify(lock.HashConfig(raw), platform); err != nil {
		return systemState{}, fmt.Errorf("verify lock (run dproxy lock): %w", err)
	}
	var store *plugin.Store
	if readOnly {
		store, err = plugin.OpenStore(filepath.Join(dataRoot, "plugins"), nil)
	} else {
		store, err = plugin.NewStore(filepath.Join(dataRoot, "plugins"), nil)
	}
	if err != nil && !readOnly {
		return systemState{}, err
	}
	var manifest plugin.Manifest
	if store != nil {
		manifest, err = store.Resolve(binary)
	} else {
		err = plugin.ErrNotFound
	}
	if err != nil {
		bundled, bundleErr := official.Load()
		if bundleErr == nil {
			var found bool
			manifest, found = bundled[binary]
			if found {
				err = nil
			} else {
				err = plugin.ErrNotFound
			}
		}
	}
	if err != nil {
		return systemState{}, fmt.Errorf("resolve provider for %q: %w", binary, err)
	}
	return systemState{project: p, config: cfg, user: user, store: store, manifest: manifest, locked: locked, platform: platform, cacheRoot: cacheRoot, stateRoot: stateRoot, dataRoot: dataRoot}, nil
}

func findProject(start string, readOnly bool) (project.Project, error) {
	if readOnly {
		return project.FindReadOnly(start)
	}
	return project.Find(start)
}

// loadGlobalSystemState serves tool invocations issued outside any project.
// It materializes a global default project (so the current directory becomes
// /workspace), auto-locks the requested tool by immutable digest on first use,
// and reuses the per-tool global lock on subsequent runs.
func loadGlobalSystemState(ctx context.Context, binary string, readOnly bool) (systemState, error) {
	cacheRoot, stateRoot, dataRoot, err := userRoots()
	if err != nil {
		return systemState{}, err
	}
	if err := ensureRootParents(cacheRoot, stateRoot, dataRoot); err != nil {
		return systemState{}, err
	}
	// Resolve the manifest before requiring user configuration so a typo fails
	// fast and offline instead of demanding a gateway image.
	manifest, err := resolveGlobalManifest(binary, dataRoot)
	if err != nil {
		return systemState{}, err
	}
	user, err := loadUserConfig()
	if err != nil {
		return systemState{}, err
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	globalDir := filepath.Join(dataRoot, "global-project")
	p, err := project.FindOrGlobal(".", globalDir)
	if err != nil {
		return systemState{}, fmt.Errorf("discover global project: %w", err)
	}
	locked, lockErr := loadGlobalLock(ctx, globalDir, manifest, platform, readOnly)
	if lockErr != nil {
		return systemState{}, lockErr
	}
	return systemState{project: p, config: config.Config{Schema: 1, Sandbox: config.Sandbox{}}, user: user, manifest: manifest, locked: locked, platform: platform, cacheRoot: cacheRoot, stateRoot: stateRoot, dataRoot: dataRoot}, nil
}

// loadGlobalLock returns a verified per-tool global lock, resolving and
// persisting it on first use (or when stale). Resolution happens on the host
// and needs registry network access; the result is pinned by digest.
func loadGlobalLock(ctx context.Context, globalDir string, manifest plugin.Manifest, platform string, readOnly bool) (lock.File, error) {
	lockPath := filepath.Join(globalDir, manifest.Name+".lock.json")
	locked, lockErr := lock.Load(lockPath)
	if lockErr == nil {
		if verifyErr := locked.Verify(lock.GlobalConfigHash(), platform); verifyErr != nil {
			lockErr = verifyErr
		}
	}
	if lockErr != nil {
		resolved, resolveErr := registryResolve(ctx, config.Config{Schema: 1, Tools: map[string]string{manifest.Name: "*"}}, map[string]plugin.Manifest{manifest.Name: manifest}, platform, lock.GlobalConfigHash())
		if resolveErr != nil {
			return lock.File{}, fmt.Errorf("auto-lock tool %q: %w", manifest.Name, resolveErr)
		}
		if !readOnly {
			if writeErr := lock.WriteAtomic(lockPath, resolved); writeErr != nil {
				return lock.File{}, fmt.Errorf("persist global lock: %w", writeErr)
			}
		}
		return resolved, nil
	}
	return locked, nil
}

// resolveGlobalManifest resolves a tool manifest from the trusted plugin store,
// falling back to the bundled official plugins (release builds only).
func resolveGlobalManifest(binary, dataRoot string) (plugin.Manifest, error) {
	if store, storeErr := plugin.OpenStore(filepath.Join(dataRoot, "plugins"), nil); storeErr == nil {
		if manifest, err := store.Resolve(binary); err == nil {
			return manifest, nil
		}
	}
	bundled, bundleErr := official.Load()
	if bundleErr != nil {
		return plugin.Manifest{}, fmt.Errorf("resolve provider for %q: %w", binary, plugin.ErrNotFound)
	}
	manifest, found := bundled[binary]
	if !found {
		return plugin.Manifest{}, fmt.Errorf("resolve provider for %q: %w", binary, plugin.ErrNotFound)
	}
	return manifest, nil
}

func loadUserState() (config.UserConfig, string, string, string, error) {
	cacheRoot, stateRoot, dataRoot, err := userRoots()
	if err != nil {
		return config.UserConfig{}, "", "", "", err
	}
	user, err := loadUserConfig()
	if err != nil {
		return config.UserConfig{}, "", "", "", err
	}
	return user, cacheRoot, stateRoot, dataRoot, nil
}

func loadUserConfig() (config.UserConfig, error) {
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return config.UserConfig{}, err
	}
	user, err := config.LoadUser(filepath.Join(configRoot, "dproxy", "config.toml"))
	if err != nil {
		return config.UserConfig{}, fmt.Errorf("load user configuration (set a pinned gateway image): %w", err)
	}
	return user, nil
}

// ensureRootParents creates the standard XDG parent directories (~/.cache,
// ~/.local/state, ~/.local/share) when absent. The cache manager opens its root
// with openat2/beneath semantics and only creates the final component, so a
// missing parent (e.g. ~/.cache on a fresh home) would otherwise fail with
// "file does not exist" on the first run.
func ensureRootParents(roots ...string) error {
	for _, root := range roots {
		if root == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(root), 0700); err != nil {
			return fmt.Errorf("create %s: %w", filepath.Dir(root), err)
		}
	}
	return nil
}

func userRoots() (string, string, string, error) {
	cacheRoot, err := os.UserCacheDir()
	if err != nil {
		return "", "", "", err
	}
	dataRoot := os.Getenv("XDG_DATA_HOME")
	if dataRoot == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", "", "", e
		}
		dataRoot = filepath.Join(home, ".local", "share")
	}
	stateRoot := os.Getenv("XDG_STATE_HOME")
	if stateRoot == "" {
		home, e := os.UserHomeDir()
		if e != nil {
			return "", "", "", e
		}
		stateRoot = filepath.Join(home, ".local", "state")
	}
	return filepath.Join(cacheRoot, "dproxy"), filepath.Join(stateRoot, "dproxy"), filepath.Join(dataRoot, "dproxy"), nil
}

func dockerAPI(user config.UserConfig) (*dockerclient.Client, error) {
	opts := []dockerclient.Opt{dockerclient.FromEnv, dockerclient.WithAPIVersionNegotiation()}
	if user.EngineEndpoint != "" {
		opts = append(opts, dockerclient.WithHost(user.EngineEndpoint))
	}
	return dockerclient.NewClientWithOpts(opts...)
}
func terminal(reader any) (bool, uintptr) {
	file, ok := reader.(*os.File)
	if !ok {
		return false, 0
	}
	fd := file.Fd()
	return term.IsTerminal(fd), fd
}
func compatibility(version, mode string) string {
	parts := strings.SplitN(version, ".", 3)
	switch mode {
	case "major":
		if len(parts) > 0 {
			return parts[0]
		}
	case "minor":
		if len(parts) > 1 {
			return strings.Join(parts[:2], ".")
		}
	}
	return version
}
