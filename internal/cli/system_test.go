package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"dproxy/internal/cache"
	"dproxy/internal/config"
	"dproxy/internal/engine"
	"dproxy/internal/lock"
	"dproxy/internal/plugin"
	"dproxy/internal/policy"
	"dproxy/internal/project"
	commandruntime "dproxy/internal/runtime"
	"dproxy/plugins/official"
	"github.com/stretchr/testify/require"
)

func systemEnvironment(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for key, value := range map[string]string{"HOME": filepath.Join(root, "home"), "XDG_CONFIG_HOME": filepath.Join(root, "config"), "XDG_CACHE_HOME": filepath.Join(root, "cache"), "XDG_DATA_HOME": filepath.Join(root, "data"), "XDG_STATE_HOME": filepath.Join(root, "state")} {
		t.Setenv(key, value)
		require.NoError(t, os.MkdirAll(value, 0700))
	}
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
	writeUserConfig(t)
	require.NoError(t, initProject(nil))
	old := systemDoctorVerify
	t.Cleanup(func() { systemDoctorVerify = old })
	systemDoctorVerify = func(context.Context, config.UserConfig) error { return nil }
	var out bytes.Buffer
	require.NoError(t, (systemRunner{}).Command(context.Background(), "doctor", nil, Streams{Stdout: &out}))
	require.Contains(t, out.String(), "healthy")
	systemDoctorVerify = func(context.Context, config.UserConfig) error { return errors.New("offline") }
	require.Error(t, doctorCommand(context.Background(), Streams{Stdout: &out}))
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
