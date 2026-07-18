package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"dproxy/internal/config"
	"dproxy/internal/lock"
	"dproxy/internal/plugin"
	"github.com/stretchr/testify/require"
)

func validInput(t *testing.T, binary string, args []string) Input {
	t.Helper()
	root := t.TempDir()
	cacheRoot := t.TempDir()
	cache := filepath.Join(cacheRoot, "node-cache")
	require.NoError(t, os.Mkdir(cache, 0700))
	digest := "sha256:" + strings.Repeat("d", 64)
	return Input{InvocationID: "inv", ProjectID: "project", ProjectRoot: root, RelativeWorkdir: ".", CacheRoot: cacheRoot, Platform: "linux/amd64",
		CachePaths: map[string]string{"/home/node/.npm": cache}, Binary: binary, Arguments: args, UID: 1000, GID: 1000,
		Tool:     lock.Tool{Image: "docker.io/library/node", Tag: "24.4.1", Digest: digest, Platform: "linux/amd64", Version: "24.4.1", Requested: "24"},
		Manifest: plugin.Manifest{Name: "node", Commands: map[string][]string{"npm": {"npm"}}, Caches: []plugin.Cache{{Path: "/home/node/.npm"}}, Environment: map[string]string{"NODE_ENV": "production"}},
		Sandbox:  config.Sandbox{Network: "none", Memory: "4GiB", CPUs: 2, PIDs: 128, Environment: map[string]string{"CI": "true"}, Ports: map[string]int{"3000": 3000}}}
}

func TestPlanHasNoHostAuthority(t *testing.T) {
	in := validInput(t, "npm", []string{"install"})
	got, err := Build(in)
	require.NoError(t, err)
	require.True(t, got.ReadOnlyRoot)
	require.True(t, got.NoNewPrivileges)
	require.True(t, got.AutoRemove)
	require.Equal(t, []string{"ALL"}, got.CapDrop)
	require.NotContains(t, got.Environment, "AWS_SECRET_ACCESS_KEY")
	require.Equal(t, []string{"npm", "install"}, got.Command)
	require.Equal(t, in.Tool.Image+"@"+in.Tool.Digest, got.Image)
	require.Len(t, got.Mounts, 2)
	require.Equal(t, "/workspace", got.Mounts[0].Target)
	require.Equal(t, "/workspace", got.Workdir)
	require.Equal(t, []Tmpfs{{Target: "/tmp", Mode: 01777}, {Target: "/home/dproxy", Mode: 0700}}, got.Tmpfs)
}

func TestBuildCopiesCollections(t *testing.T) {
	in := validInput(t, "npm", []string{"install"})
	got, err := Build(in)
	require.NoError(t, err)
	in.Arguments[0] = "changed"
	in.Sandbox.Environment["CI"] = "changed"
	in.Manifest.Commands["npm"][0] = "changed"
	require.Equal(t, []string{"npm", "install"}, got.Command)
	require.Equal(t, "true", got.Environment["CI"])
}

func TestBuildRejectsUnsafeInputs(t *testing.T) {
	cases := map[string]func(*Input){
		"unknown command":     func(i *Input) { i.Binary = "sh" },
		"unlocked image":      func(i *Input) { i.Tool.Digest = "latest" },
		"wrong platform":      func(i *Input) { i.Platform = "linux/arm64" },
		"root project":        func(i *Input) { i.ProjectRoot = "/" },
		"outside workdir":     func(i *Input) { i.RelativeWorkdir = "../escape" },
		"reserved env":        func(i *Input) { i.Sandbox.Environment["HOME"] = "/host" },
		"reserved plugin env": func(i *Input) { i.Manifest.Environment["PATH"] = "/evil" },
		"invalid env":         func(i *Input) { i.Sandbox.Environment["BAD=KEY"] = "x" },
		"unsafe port":         func(i *Input) { i.Sandbox.Ports = map[string]int{"0": 3000} },
		"bad pids":            func(i *Input) { i.Sandbox.PIDs = -1 },
		"bad cpu":             func(i *Input) { i.Sandbox.CPUs = 65 },
		"bad memory":          func(i *Input) { i.Sandbox.Memory = "unlimited" },
		"unknown network":     func(i *Input) { i.Sandbox.Network = "host" },
		"missing cache":       func(i *Input) { i.CachePaths = map[string]string{} },
		"protected cache target": func(i *Input) {
			i.Manifest.Caches[0].Path = "/tmp/cache"
			i.CachePaths["/tmp/cache"] = i.CachePaths["/home/node/.npm"]
		},
		"negative uid": func(i *Input) { i.UID = -1 },
		"nul argument": func(i *Input) { i.Arguments = []string{"bad\x00arg"} },
		"relative cache target": func(i *Input) {
			i.Manifest.Caches[0].Path = "cache"
			i.CachePaths["cache"] = i.CachePaths["/home/node/.npm"]
		},
		"cache outside manager": func(i *Input) { i.CachePaths["/home/node/.npm"] = t.TempDir() },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := validInput(t, "npm", nil)
			mutate(&in)
			_, err := Build(in)
			require.Error(t, err)
		})
	}
}

func TestBuildAppliesFiniteDefaultResourceLimits(t *testing.T) {
	in := validInput(t, "npm", nil)
	in.Sandbox.Memory = ""
	in.Sandbox.CPUs = 0
	in.Sandbox.PIDs = 0
	got, err := Build(in)
	require.NoError(t, err)
	require.Equal(t, int64(4<<30), got.MemoryBytes)
	require.Equal(t, float64(2), got.CPUs)
	require.Equal(t, 512, got.Pids)
}

func TestBuildRejectsSymlinkEscapes(t *testing.T) {
	in := validInput(t, "npm", nil)
	outside := t.TempDir()
	link := filepath.Join(in.CacheRoot, "link")
	require.NoError(t, os.Symlink(outside, link))
	in.CachePaths["/home/node/.npm"] = link
	_, err := Build(in)
	require.Error(t, err)
}

func FuzzBuild(f *testing.F) {
	f.Add("npm", "install", "CI")
	f.Fuzz(func(t *testing.T, binary, arg, key string) {
		in := validInput(t, "npm", []string{arg})
		in.Binary = binary
		in.Sandbox.Environment = map[string]string{key: "x"}
		plan, err := Build(in)
		if err == nil {
			for _, m := range plan.Mounts {
				if m.Source == "/" || m.Target == "/" {
					t.Fatal("root mount")
				}
			}
		}
	})
}
