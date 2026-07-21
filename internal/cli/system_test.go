package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/i-rocky/dproxy/internal/cache"
	"github.com/i-rocky/dproxy/internal/config"
	"github.com/i-rocky/dproxy/internal/engine"
	"github.com/i-rocky/dproxy/internal/lock"
	"github.com/i-rocky/dproxy/internal/plugin"
	"github.com/i-rocky/dproxy/internal/policy"
	"github.com/i-rocky/dproxy/internal/project"
	commandruntime "github.com/i-rocky/dproxy/internal/runtime"
	"github.com/i-rocky/dproxy/plugins/official"
	"github.com/stretchr/testify/require"
)

func systemEnvironment(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for key, value := range map[string]string{"HOME": filepath.Join(root, "home"), "XDG_CONFIG_HOME": filepath.Join(root, "config"), "XDG_CACHE_HOME": filepath.Join(root, "cache"), "XDG_DATA_HOME": filepath.Join(root, "data"), "XDG_STATE_HOME": filepath.Join(root, "state")} {
		t.Setenv(key, value)
		require.NoError(t, os.MkdirAll(value, 0700))
	}
	// Hermetic PATH: only the managed bin dir. Install must not be influenced by
	// tools that happen to exist on the host (nvm node, system go, etc.).
	t.Setenv("PATH", filepath.Join(root, "home", ".local", "bin"))
	old, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(root))
	t.Cleanup(func() { _ = os.Chdir(old) })
	return root
}

func writeUserConfig(t *testing.T) {
	t.Helper()
	root, err := os.UserConfigDir()
	require.NoError(t, err)
	require.NoError(t, config.WriteUserAtomic(filepath.Join(root, "dproxy", "config.toml"), config.UserConfig{Schema: 1, GatewayImage: "registry.test/dproxy/gateway@sha256:" + strings.Repeat("a", 64)}))
}

func TestSystemAdministrativeProjectAndCacheFlow(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.NoError(t, runner.Command(context.Background(), "init", nil, streams))
	require.Error(t, runner.Command(context.Background(), "init", nil, streams))
	require.NoError(t, runner.Command(context.Background(), "tool", []string{"add", "node", "24"}, streams))
	require.NoError(t, runner.Command(context.Background(), "tool", []string{"remove", "node"}, streams))
	require.Error(t, runner.Command(context.Background(), "tool", []string{"remove", "node"}, streams))
	require.NoError(t, runner.Command(context.Background(), "cache", []string{"list"}, streams))
	require.ErrorContains(t, runner.Command(context.Background(), "cache", []string{"prune"}, streams), "--all")
	require.NoError(t, runner.Command(context.Background(), "cache", []string{"prune", "--all"}, streams))
	require.Error(t, runner.Command(context.Background(), "cache", []string{"clean"}, streams))
}

func TestSystemPluginAdministrationWithoutReleaseMetadata(t *testing.T) {
	systemEnvironment(t)
	runner := systemRunner{}
	var out bytes.Buffer
	streams := Streams{Stdout: &out, Stderr: &out}
	require.NoError(t, runner.Command(context.Background(), "plugin", []string{"list"}, streams))
	require.Equal(t, "[]\n", out.String())
	require.Error(t, runner.Command(context.Background(), "plugin", []string{"inspect", "missing"}, streams))
	require.Error(t, runner.Command(context.Background(), "plugin", []string{"add", "https://example.test/repo"}, streams))
	require.Error(t, runner.Command(context.Background(), "plugin", []string{"add", "--trust", "http://example.test/repo"}, streams))
	require.Error(t, runner.Command(context.Background(), "plugin", []string{"remove", "missing"}, streams))
	require.Error(t, runner.Command(context.Background(), "plugin", []string{"sync", "missing"}, streams))
	require.Error(t, runner.Command(context.Background(), "unknown", nil, streams))
}

func TestSystemLockAndResolveWithImmutableOfficialProvider(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	require.NoError(t, initProject(nil))
	require.NoError(t, toolCommand([]string{"add", "node", "24"}))
	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })
	oldResolve := registryResolve
	registryResolve = func(_ context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
		manifest := manifests["node"]
		return lock.File{Schema: 1, ConfigSHA256: hash, Plugins: map[string]lock.Plugin{manifest.Name: {Repository: manifest.Provenance.Repository, Commit: manifest.Provenance.Commit, ManifestSHA256: manifest.Provenance.ManifestSHA256, Schema: 1}}, Tools: map[string]lock.Tool{"node": {Requested: cfg.Tools["node"], Version: "24.1.0", Image: "registry.test/node", Tag: "24.1.0", Digest: "sha256:" + strings.Repeat("c", 64), Platform: platform}}}, nil
	}
	t.Cleanup(func() { registryResolve = oldResolve })
	require.NoError(t, resolveLock(context.Background(), nil))
	plan, err := (systemRunner{}).Resolve(context.Background(), "node", []string{"--version"})
	require.NoError(t, err)
	require.Equal(t, []string{"node", "--version"}, plan.Command)
	require.Contains(t, plan.Mounts[1].Source, filepath.Join("cache", "dproxy"))
	aliasPlan, err := (systemRunner{}).Resolve(context.Background(), "npm", []string{"ci"})
	require.NoError(t, err)
	require.Equal(t, []string{"npm", "ci"}, aliasPlan.Command)
	_, err = (systemRunner{}).Resolve(context.Background(), "unknown", nil)
	require.Error(t, err)
	require.NoError(t, (systemRunner{}).Command(context.Background(), "update", []string{"node"}, Streams{}))
	var output bytes.Buffer
	require.NoError(t, (systemRunner{}).Command(context.Background(), "setup", nil, Streams{Stdout: &output, Stderr: &output}))
	require.Contains(t, output.String(), "managed tool shims")
	require.NoError(t, (systemRunner{}).Command(context.Background(), "uninstall", nil, Streams{}))
}

func TestProductionExecuteDryRunLeavesFilesystemUnchanged(t *testing.T) {
	root := systemEnvironment(t)
	writeUserConfig(t)
	require.NoError(t, initProject(nil))
	require.NoError(t, toolCommand([]string{"add", "node", "24"}))
	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })
	oldResolve := registryResolve
	registryResolve = func(_ context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
		manifest := manifests["node"]
		return lock.File{Schema: 1, ConfigSHA256: hash, Plugins: map[string]lock.Plugin{manifest.Name: {Repository: manifest.Provenance.Repository, Commit: manifest.Provenance.Commit, ManifestSHA256: manifest.Provenance.ManifestSHA256, Schema: 1}}, Tools: map[string]lock.Tool{"node": {Requested: cfg.Tools["node"], Version: "24.1.0", Image: "registry.test/node", Tag: "24.1.0", Digest: "sha256:" + strings.Repeat("c", 64), Platform: platform}}}, nil
	}
	t.Cleanup(func() { registryResolve = oldResolve })
	require.NoError(t, resolveLock(context.Background(), nil))
	before := filesystemSnapshot(t, root)
	var output bytes.Buffer
	require.Equal(t, 0, Execute(context.Background(), "dproxy", []string{"--dry-run", "node", "--version"}, &output, &output), output.String())
	require.Equal(t, 0, Execute(context.Background(), "dproxy", []string{"--dry-run", "cache", "prune", "--all"}, &output, &output), output.String())
	require.Equal(t, before, filesystemSnapshot(t, root))
}

func filesystemSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	result := map[string]string{}
	require.NoError(t, filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := fmt.Sprintf("%s:%o", info.Mode().Type(), info.Mode().Perm())
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += ":" + string(data)
		}
		result[rel] = value
		return nil
	}))
	return result
}

func TestPlanCommandSupportsReadOnlyCachePlanning(t *testing.T) {
	runner := systemRunner{}
	planned, err := runner.PlanCommand(context.Background(), "cache", []string{"list"})
	require.NoError(t, err)
	require.Contains(t, planned, "cache list")
	planned, err = runner.PlanCommand(context.Background(), "cache", []string{"prune", "--all"})
	require.NoError(t, err)
	require.Contains(t, planned, "prune")
	_, err = runner.PlanCommand(context.Background(), "cache", []string{"bogus"})
	require.Error(t, err)
	_, err = runner.PlanCommand(context.Background(), "cache", nil)
	require.Error(t, err)
	_, err = runner.PlanCommand(context.Background(), "init", nil)
	require.Error(t, err)
}

func TestGlobalAutoLockResolvesThenReuses(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })

	var resolveCalls int
	oldResolve := registryResolve
	registryResolve = func(_ context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
		resolveCalls++
		require.Equal(t, lock.GlobalConfigHash(), hash)
		manifest := manifests["node"]
		return lock.File{Schema: 1, ConfigSHA256: hash, Plugins: map[string]lock.Plugin{manifest.Name: {Repository: manifest.Provenance.Repository, Commit: manifest.Provenance.Commit, ManifestSHA256: manifest.Provenance.ManifestSHA256, Schema: 1}}, Tools: map[string]lock.Tool{"node": {Requested: cfg.Tools["node"], Version: "24.1.0", Image: "registry.test/node", Tag: "24.1.0", Digest: "sha256:" + strings.Repeat("c", 64), Platform: platform}}}, nil
	}
	t.Cleanup(func() { registryResolve = oldResolve })

	runner := systemRunner{}
	plan, err := runner.Resolve(context.Background(), "npm", []string{"ci"})
	require.NoError(t, err)
	require.Equal(t, []string{"npm", "ci"}, plan.Command)
	require.Equal(t, "allowlist", plan.Network.Mode)
	require.Contains(t, plan.Network.Allowlist, "registry.npmjs.org:443")
	require.Equal(t, 1, resolveCalls)

	// Second invocation reuses the persisted per-tool global lock (no resolution).
	_, err = runner.Resolve(context.Background(), "npm", []string{"install"})
	require.NoError(t, err)
	require.Equal(t, 1, resolveCalls)

	_, err = os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "dproxy", "global-project", "node.lock.json"))
	require.NoError(t, err)
}

func TestGlobalAutoLockReadOnlyDoesNotPersist(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })
	var resolveCalls int
	oldResolve := registryResolve
	registryResolve = func(_ context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
		resolveCalls++
		manifest := manifests["node"]
		return lock.File{Schema: 1, ConfigSHA256: hash, Plugins: map[string]lock.Plugin{manifest.Name: {Repository: manifest.Provenance.Repository, Commit: manifest.Provenance.Commit, ManifestSHA256: manifest.Provenance.ManifestSHA256, Schema: 1}}, Tools: map[string]lock.Tool{"node": {Requested: cfg.Tools["node"], Version: "24.1.0", Image: "registry.test/node", Tag: "24.1.0", Digest: "sha256:" + strings.Repeat("c", 64), Platform: platform}}}, nil
	}
	t.Cleanup(func() { registryResolve = oldResolve })

	runner := systemRunner{}
	plan, err := runner.ResolveReadOnly(context.Background(), "npm", []string{"ci"})
	require.NoError(t, err)
	require.Equal(t, "allowlist", plan.Network.Mode)
	require.Equal(t, 1, resolveCalls)
	_, err = os.Stat(filepath.Join(os.Getenv("XDG_DATA_HOME"), "dproxy", "global-project", "node.lock.json"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestResolveGlobalManifest(t *testing.T) {
	_, _, dataRoot, err := userRoots()
	require.NoError(t, err)
	// Dev build: no official provenance and no community plugins -> failure.
	_, err = resolveGlobalManifest("node", dataRoot)
	require.Error(t, err)

	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })

	manifest, err := resolveGlobalManifest("npm", dataRoot)
	require.NoError(t, err)
	require.Equal(t, "node", manifest.Name)
	require.NotEmpty(t, manifest.Egress)

	_, err = resolveGlobalManifest("never-a-tool", dataRoot)
	require.Error(t, err)
}

func TestSystemRunUsesInjectedExecutionBoundary(t *testing.T) {
	old := systemExecute
	t.Cleanup(func() { systemExecute = old })
	systemExecute = func(context.Context, policy.Plan, Streams) (int, error) { return 37, nil }
	code, err := (systemRunner{}).Run(context.Background(), policy.Plan{}, Streams{})
	require.NoError(t, err)
	require.Equal(t, 37, code)
}

func TestExecuteSystemPlanComposesRuntimeAndMapsSandboxFailure(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	oldFactory, oldRun := systemRuntimeFactory, systemRuntimeRun
	t.Cleanup(func() { systemRuntimeFactory, systemRuntimeRun = oldFactory, oldRun })
	systemRuntimeFactory = func(config.UserConfig) (engine.Engine, commandruntime.NetworkManager, error) { return nil, nil, nil }
	called := false
	systemRuntimeRun = func(_ context.Context, deps commandruntime.Dependencies, got policy.Plan, streams commandruntime.IO) (int, error) {
		called = true
		require.Equal(t, "bridge", deps.NetworkRequest.EgressNetworkID)
		require.False(t, streams.TTY)
		require.Equal(t, "image", got.Image)
		return 19, nil
	}
	code, err := executeSystemPlan(context.Background(), policy.Plan{Image: "image"}, Streams{Stdin: bytes.NewReader(nil)})
	require.NoError(t, err)
	require.Equal(t, 19, code)
	require.True(t, called)
	systemRuntimeRun = func(context.Context, commandruntime.Dependencies, policy.Plan, commandruntime.IO) (int, error) {
		return 0, errors.New("create failed")
	}
	_, err = executeSystemPlan(context.Background(), policy.Plan{}, Streams{})
	require.ErrorIs(t, err, ErrSandboxCreation)
	systemRuntimeFactory = func(config.UserConfig) (engine.Engine, commandruntime.NetworkManager, error) {
		return nil, nil, errors.New("factory")
	}
	_, err = executeSystemPlan(context.Background(), policy.Plan{}, Streams{})
	require.Error(t, err)
}

func TestDoctorUsesInjectedEngineVerification(t *testing.T) {
	systemEnvironment(t)
	oldVerify, oldLoad, oldEnsure, oldRefresh := systemDoctorVerify, officialLoad, ensureGatewayImage, refreshManagedShims
	t.Cleanup(func() {
		systemDoctorVerify, officialLoad, ensureGatewayImage, refreshManagedShims = oldVerify, oldLoad, oldEnsure, oldRefresh
	})
	officialLoad = func() (map[string]plugin.Manifest, error) { return map[string]plugin.Manifest{"node": {}}, nil }
	refreshManagedShims = func() (int, error) { return 0, nil }
	configPath := filepath.Join(os.Getenv("XDG_CONFIG_HOME"), "dproxy", "config.toml")

	t.Run("engine unavailable fails fast", func(t *testing.T) {
		systemDoctorVerify = func(context.Context, config.UserConfig) error { return errors.New("offline") }
		require.Error(t, doctorCommand(context.Background(), Streams{Stdout: new(bytes.Buffer)}))
	})
	systemDoctorVerify = func(context.Context, config.UserConfig) error { return nil }

	t.Run("missing config autofix provisions and writes", func(t *testing.T) {
		_ = os.Remove(configPath)
		ensureGatewayImage = func(context.Context) (string, error) {
			return "ghcr.io/i-rocky/dproxy-gateway@sha256:" + strings.Repeat("a", 64), nil
		}
		var out bytes.Buffer
		require.NoError(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.Contains(t, out.String(), "FIXED")
		_, err := config.LoadUser(configPath)
		require.NoError(t, err, "autofix must write a valid configuration")
	})

	t.Run("autofix failure is reported", func(t *testing.T) {
		_ = os.Remove(configPath)
		ensureGatewayImage = func(context.Context) (string, error) { return "", errors.New("no gateway available") }
		var out bytes.Buffer
		require.Error(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.Contains(t, out.String(), "gateway image: FAIL")
	})

	t.Run("valid config passes all checks", func(t *testing.T) {
		writeUserConfig(t)
		var out bytes.Buffer
		require.NoError(t, (systemRunner{}).Command(context.Background(), "doctor", nil, Streams{Stdout: &out}))
		require.Contains(t, out.String(), "all checks passed")
	})
}

func TestCompatibilityModes(t *testing.T) {
	require.Equal(t, "24", compatibility("24.1.2", "major"))
	require.Equal(t, "24.1", compatibility("24.1.2", "minor"))
	require.Equal(t, "24.1.2", compatibility("24.1.2", "exact"))
	require.Equal(t, "", compatibility("", "major"))
	require.Equal(t, "24", compatibility("24", "minor"))
}

func TestCacheCleanRealOwnedTuple(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	require.NoError(t, initProject(nil))
	p, err := project.Find(".")
	require.NoError(t, err)
	cacheRoot, _, _, err := userRoots()
	require.NoError(t, err)
	_, err = (cache.Manager{Root: cacheRoot}).Path(p.ID, "node", "npm", "24", strings.ReplaceAll(runtime.GOOS+"/"+runtime.GOARCH, "/", "-"))
	require.NoError(t, err)
	require.NoError(t, (systemRunner{}).Command(context.Background(), "cache", []string{"clean", "node", "npm", "24"}, Streams{}))
}

func TestProductionFactoriesAndMissingStateFailClosed(t *testing.T) {
	systemEnvironment(t)
	_, err := (systemRunner{}).Resolve(context.Background(), "node", nil)
	require.Error(t, err)
	require.Error(t, setupCommand(Streams{}))
	require.Error(t, resolveLock(context.Background(), []string{"--bad"}))
	require.Error(t, resolveLock(context.Background(), []string{"one", "two"}))
	writeUserConfig(t)
	user, _, _, _, err := loadUserState()
	require.NoError(t, err)
	api, err := dockerAPI(user)
	require.NoError(t, err)
	require.NotNil(t, api)
	ok, _ := terminal(bytes.NewReader(nil))
	require.False(t, ok)
	ok, _ = terminal(os.Stdin)
	require.False(t, ok)
	require.NoError(t, uninstallCommand())
}

func TestUserRootsFallbacks(t *testing.T) {
	root := systemEnvironment(t)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_STATE_HOME", "")
	_, state, data, err := userRoots()
	require.NoError(t, err)
	require.Equal(t, filepath.Join(root, "home", ".local", "state", "dproxy"), state)
	require.Equal(t, filepath.Join(root, "home", ".local", "share", "dproxy"), data)
}

func TestSystemUsageFailures(t *testing.T) {
	systemEnvironment(t)
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	for _, tc := range []struct {
		name string
		args []string
	}{{"init", []string{"extra"}}, {"tool", nil}, {"plugin", nil}, {"cache", nil}, {"uninstall", []string{"extra"}}} {
		require.Error(t, runner.Command(context.Background(), tc.name, tc.args, streams), tc.name)
	}
	for _, args := range [][]string{{"remove"}, {"sync"}, {"list", "extra"}, {"inspect"}, {"wat"}} {
		require.Error(t, pluginCommand(context.Background(), args, streams), args)
	}
	for _, args := range [][]string{{"list", "extra"}, {"prune"}, {"prune", "extra"}, {"wat"}} {
		require.Error(t, cacheCommand(args, streams), args)
	}
}

func TestEnsureRootParentsCreatesMissingXDGParent(t *testing.T) {
	root := t.TempDir()
	cache := filepath.Join(root, "cache", "dproxy") // parent "cache" does not exist yet
	require.NoError(t, ensureRootParents(cache))
	require.DirExists(t, filepath.Dir(cache))
}

func TestShimBinaryIsStaleDetection(t *testing.T) {
	dir := t.TempDir()
	execPath := filepath.Join(dir, "dproxy")
	shimPath := filepath.Join(dir, "dproxy-shim")
	require.NoError(t, os.WriteFile(execPath, []byte("binary-v1"), 0700))

	stale, err := shimBinaryIsStale(execPath, shimPath) // missing shim
	require.NoError(t, err)
	require.True(t, stale, "missing shim must be stale")

	require.NoError(t, os.WriteFile(shimPath, []byte("binary-v0"), 0700))
	stale, err = shimBinaryIsStale(execPath, shimPath) // different content
	require.NoError(t, err)
	require.True(t, stale, "mismatched shim must be stale")

	require.NoError(t, os.WriteFile(shimPath, []byte("binary-v1"), 0700))
	stale, err = shimBinaryIsStale(execPath, shimPath) // identical
	require.NoError(t, err)
	require.False(t, stale, "identical shim must be fresh")

	_, err = shimBinaryIsStale(filepath.Join(dir, "missing"), shimPath) // missing executable
	require.Error(t, err)
}

func TestDoctorShimStalenessAutofix(t *testing.T) {
	systemEnvironment(t)
	oldVerify, oldLoad, oldEnsure, oldRefresh := systemDoctorVerify, officialLoad, ensureGatewayImage, refreshManagedShims
	t.Cleanup(func() {
		systemDoctorVerify, officialLoad, ensureGatewayImage, refreshManagedShims = oldVerify, oldLoad, oldEnsure, oldRefresh
	})
	systemDoctorVerify = func(context.Context, config.UserConfig) error { return nil }
	officialLoad = func() (map[string]plugin.Manifest, error) { return map[string]plugin.Manifest{"node": {}}, nil }
	ensureGatewayImage = func(context.Context) (string, error) {
		return "ghcr.io/i-rocky/dproxy-gateway@sha256:" + strings.Repeat("a", 64), nil
	}
	writeUserConfig(t)

	_, _, dataRoot, err := userRoots()
	require.NoError(t, err)
	shimDir := filepath.Join(dataRoot, "shims")
	require.NoError(t, os.MkdirAll(shimDir, 0700))
	shimPath := filepath.Join(shimDir, genericShimName)
	executable, err := os.Executable()
	require.NoError(t, err)

	t.Run("stale shim is refreshed", func(t *testing.T) {
		require.NoError(t, os.WriteFile(shimPath, []byte("stale"), 0700))
		called := false
		refreshManagedShims = func() (int, error) { called = true; return 1, nil }
		var out bytes.Buffer
		require.NoError(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.True(t, called, "a stale shim must trigger a refresh")
		require.Contains(t, out.String(), "shims: FIXED")
	})

	t.Run("missing shim is refreshed", func(t *testing.T) {
		_ = os.Remove(shimPath)
		called := false
		refreshManagedShims = func() (int, error) { called = true; return 1, nil }
		var out bytes.Buffer
		require.NoError(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.True(t, called, "a missing shim must trigger a refresh")
		require.Contains(t, out.String(), "shims: FIXED")
	})

	t.Run("fresh shim is left alone", func(t *testing.T) {
		src, err := os.Open(executable)
		require.NoError(t, err)
		defer src.Close()
		dst, err := os.OpenFile(shimPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0700)
		require.NoError(t, err)
		_, err = io.Copy(dst, src)
		_ = dst.Close()
		require.NoError(t, err)
		called := false
		refreshManagedShims = func() (int, error) { called = true; return 0, nil }
		var out bytes.Buffer
		require.NoError(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.False(t, called, "a fresh shim must not be refreshed")
		require.Contains(t, out.String(), "shims: OK")
	})

	t.Run("refresh failure fails closed", func(t *testing.T) {
		require.NoError(t, os.WriteFile(shimPath, []byte("stale"), 0700))
		refreshManagedShims = func() (int, error) { return 0, errors.New("disk full") }
		var out bytes.Buffer
		require.Error(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
		require.Contains(t, out.String(), "shims: FAIL")
	})
}

func TestRefreshManagedShimsRealEndToEnd(t *testing.T) {
	systemEnvironment(t)
	// Exercise doctor's real production refresh path (copy the running binary +
	// re-create symlinks via the hardened manager). Only officialLoad is injected
	// (the test binary carries no provenance); refreshManagedShims itself is real.
	oldLoad := officialLoad
	t.Cleanup(func() { officialLoad = oldLoad })
	officialLoad = func() (map[string]plugin.Manifest, error) { return map[string]plugin.Manifest{"node": {}}, nil }

	n, err := refreshManagedShims()
	require.NoError(t, err)
	require.Greater(t, n, 0, "official tools must produce managed shims")

	_, _, dataRoot, err := userRoots()
	require.NoError(t, err)
	shimPath := filepath.Join(dataRoot, "shims", genericShimName)
	require.FileExists(t, shimPath)
	executable, err := os.Executable()
	require.NoError(t, err)
	stale, err := shimBinaryIsStale(executable, shimPath)
	require.NoError(t, err)
	require.False(t, stale, "a freshly refreshed shim must match the running binary")
}

func TestUpdateScopesToNamedToolAndPreservesOthers(t *testing.T) {
	systemEnvironment(t)
	writeUserConfig(t)
	require.NoError(t, initProject(nil))
	require.NoError(t, toolCommand([]string{"add", "node", "24"}))
	require.NoError(t, toolCommand([]string{"add", "python", "3"}))
	oldRepo, oldCommit := official.OfficialRepository, official.Commit
	official.OfficialRepository, official.Commit = "https://github.com/example/dproxy.git", strings.Repeat("b", 40)
	t.Cleanup(func() { official.OfficialRepository, official.Commit = oldRepo, oldCommit })
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}

	resolveAt := func(ver string) func(context.Context, config.Config, map[string]plugin.Manifest, string, string) (lock.File, error) {
		return func(_ context.Context, cfg config.Config, manifests map[string]plugin.Manifest, platform, hash string) (lock.File, error) {
			tools := make(map[string]lock.Tool, len(cfg.Tools))
			plugins := make(map[string]lock.Plugin, len(cfg.Tools))
			for name := range cfg.Tools {
				m := manifests[name]
				plugins[name] = lock.Plugin{Repository: m.Provenance.Repository, Commit: m.Provenance.Commit, ManifestSHA256: m.Provenance.ManifestSHA256, Schema: 1}
				tools[name] = lock.Tool{Requested: cfg.Tools[name], Version: ver, Image: "registry.test/" + name, Tag: ver, Digest: "sha256:" + strings.Repeat("c", 64), Platform: platform}
			}
			return lock.File{Schema: 1, ConfigSHA256: hash, Plugins: plugins, Tools: tools}, nil
		}
	}
	oldResolve := registryResolve
	t.Cleanup(func() { registryResolve = oldResolve })

	registryResolve = resolveAt("1.0.0")
	require.NoError(t, runner.Command(context.Background(), "lock", nil, streams))

	// Unknown tool name is rejected, not silently ignored.
	require.ErrorContains(t, runner.Command(context.Background(), "update", []string{"rust"}, streams), "not configured")

	// update node resolves only node; python's pinned version is preserved.
	registryResolve = resolveAt("99.0.0")
	require.NoError(t, runner.Command(context.Background(), "update", []string{"node"}, streams))

	locked, err := lock.Load(".dproxy.lock")
	require.NoError(t, err)
	require.Equal(t, "99.0.0", locked.Tools["node"].Version, "named tool must be re-resolved")
	require.Equal(t, "1.0.0", locked.Tools["python"].Version, "other tools must be untouched")
}
