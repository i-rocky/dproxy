package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"dproxy/internal/cache"
	"dproxy/internal/config"
	"dproxy/internal/engine"
	"dproxy/internal/lock"
	"dproxy/internal/network"
	"dproxy/internal/plugin"
	"dproxy/internal/policy"
	"dproxy/internal/project"
	"dproxy/internal/registry"
	"dproxy/internal/resolver"
	commandruntime "dproxy/internal/runtime"
	"dproxy/internal/shim"
	"dproxy/plugins/official"

	dockerclient "github.com/docker/docker/client"
	"github.com/moby/term"
)

type systemRunner struct{}

func newSystemRunner() Runner { return systemRunner{} }

type systemState struct {
	project                                  project.Project
	config                                   config.Config
	user                                     config.UserConfig
	store                                    *plugin.Store
	manifest                                 plugin.Manifest
	locked                                   lock.File
	platform, cacheRoot, stateRoot, dataRoot string
}

func (systemRunner) Resolve(_ context.Context, binary string, args []string) (policy.Plan, error) {
	state, err := loadSystemState(binary)
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
		path, err := manager.Path(state.project.ID, state.manifest.Name, binary, compatibility, strings.ReplaceAll(state.platform, "/", "-"))
		if err != nil {
			return policy.Plan{}, err
		}
		cachePaths[declaration.Path] = path
	}
	return policy.Build(policy.Input{InvocationID: "planning", ProjectID: state.project.ID, ProjectRoot: state.project.Root, RelativeWorkdir: state.project.RelativeWorkdir, CacheRoot: state.cacheRoot, Platform: state.platform, Binary: binary, CachePaths: cachePaths, Arguments: args, UID: os.Getuid(), GID: os.Getgid(), Tool: tool, Manifest: state.manifest, Sandbox: state.config.Sandbox})
}

func (systemRunner) Run(ctx context.Context, plan policy.Plan, streams Streams) (int, error) {
	return systemExecute(ctx, plan, streams)
}

var systemExecute = executeSystemPlan

func executeSystemPlan(ctx context.Context, plan policy.Plan, streams Streams) (int, error) {
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
		return code, fmt.Errorf("%w: %v", ErrSandboxCreation, runErr)
	}
	return code, nil
}

var systemRuntimeRun = commandruntime.Run
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
	if err := config.WriteAtomic(".dproxy.toml", config.Config{Schema: 1, Tools: map[string]string{}, Sandbox: config.Sandbox{Network: "none"}}); err != nil {
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

func doctorCommand(ctx context.Context, streams Streams) error {
	user, _, _, _, err := loadUserState()
	if err != nil {
		return err
	}
	p, err := project.Find(".")
	if err != nil {
		return err
	}
	if _, err = config.Load(filepath.Join(p.Root, ".dproxy.toml")); err != nil {
		return err
	}
	if err := systemDoctorVerify(ctx, user); err != nil {
		return err
	}
	fmt.Fprintln(streams.Stdout, "configuration, project, and Docker engine are healthy")
	return nil
}

var systemDoctorVerify = func(ctx context.Context, user config.UserConfig) error {
	api, err := dockerAPI(user)
	if err != nil {
		return err
	}
	return engine.NewDocker(api).Verify(ctx)
}

func cacheCommand(args []string, streams Streams) error {
	cacheRoot, _, _, err := userRoots()
	if err != nil {
		return err
	}
	if len(args) == 0 {
		return errors.New("usage: dproxy cache list|clean|prune")
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
		if len(args) != 1 {
			return errors.New("usage: dproxy cache prune")
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
		return errors.New("usage: dproxy cache list|clean|prune")
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

func loadSystemState(binary string) (systemState, error) {
	p, err := project.Find(".")
	if err != nil {
		return systemState{}, fmt.Errorf("discover project: %w", err)
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
	locked, err := lock.Load(filepath.Join(p.Root, ".dproxy.lock"))
	if err != nil {
		return systemState{}, fmt.Errorf("load lock (run dproxy lock): %w", err)
	}
	platform := runtime.GOOS + "/" + runtime.GOARCH
	if err := locked.Verify(lock.HashConfig(raw), platform); err != nil {
		return systemState{}, fmt.Errorf("verify lock (run dproxy lock): %w", err)
	}
	store, err := plugin.NewStore(filepath.Join(dataRoot, "plugins"), nil)
	if err != nil {
		return systemState{}, err
	}
	manifest, err := store.Resolve(binary)
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

func loadUserState() (config.UserConfig, string, string, string, error) {
	cacheRoot, stateRoot, dataRoot, err := userRoots()
	if err != nil {
		return config.UserConfig{}, "", "", "", err
	}
	configRoot, err := os.UserConfigDir()
	if err != nil {
		return config.UserConfig{}, "", "", "", err
	}
	user, err := config.LoadUser(filepath.Join(configRoot, "dproxy", "config.toml"))
	if err != nil {
		return config.UserConfig{}, "", "", "", fmt.Errorf("load user configuration (set a pinned gateway image): %w", err)
	}
	return user, cacheRoot, stateRoot, dataRoot, nil
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
