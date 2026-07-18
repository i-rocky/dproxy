package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"dproxy/internal/config"
	"dproxy/internal/lock"
	"dproxy/internal/plugin"
)

type Mount struct {
	Source, Target string
	ReadOnly       bool
}
type Tmpfs struct {
	Target string
	Mode   os.FileMode
}
type Port struct{ Host, Container int }
type Network struct {
	Mode      string
	Allowlist []string
}
type Plan struct {
	InvocationID, ProjectID, Image, Workdir   string
	Command                                   []string
	Environment                               map[string]string
	Mounts                                    []Mount
	Tmpfs                                     []Tmpfs
	Ports                                     []Port
	UID, GID, Pids                            int
	MemoryBytes                               int64
	CPUs                                      float64
	ReadOnlyRoot, NoNewPrivileges, AutoRemove bool
	CapDrop                                   []string
	Network                                   Network
}
type Input struct {
	InvocationID, ProjectID, ProjectRoot, RelativeWorkdir, CacheRoot, Platform, Binary string
	CachePaths                                                                         map[string]string
	Arguments                                                                          []string
	UID, GID                                                                           int
	Tool                                                                               lock.Tool
	Manifest                                                                           plugin.Manifest
	Sandbox                                                                            config.Sandbox
}

var reserved = map[string]struct{}{"HOME": {}, "PATH": {}, "HOSTNAME": {}, "DOCKER_HOST": {}, "SSH_AUTH_SOCK": {}, "GPG_AGENT_INFO": {}, "XDG_CACHE_HOME": {}, "XDG_CONFIG_HOME": {}, "XDG_DATA_HOME": {}}

func Build(in Input) (Plan, error) {
	if err := plugin.Validate(in.Manifest); err != nil {
		return Plan{}, fmt.Errorf("invalid plugin manifest: %w", err)
	}
	if in.InvocationID == "" || in.ProjectID == "" {
		return Plan{}, errors.New("missing execution identity")
	}
	if !lock.ValidDigest(in.Tool.Digest) || in.Tool.Image == "" || in.Platform == "" || in.Tool.Platform != in.Platform {
		return Plan{}, errors.New("tool image is not immutably locked for this platform")
	}
	prefix, ok := in.Manifest.Command(in.Binary)
	if !ok || len(prefix) == 0 {
		return Plan{}, errors.New("unknown command")
	}
	if in.UID < 0 || in.GID < 0 {
		return Plan{}, errors.New("invalid user identity")
	}
	for _, arg := range in.Arguments {
		if strings.ContainsRune(arg, '\x00') {
			return Plan{}, errors.New("invalid command argument")
		}
	}
	project, err := physicalDirectory(in.ProjectRoot)
	if err != nil || project == string(filepath.Separator) {
		return Plan{}, errors.New("invalid project root")
	}
	rel := filepath.Clean(filepath.FromSlash(in.RelativeWorkdir))
	if rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return Plan{}, errors.New("working directory escapes project")
	}
	workdir := "/workspace"
	if rel != "." {
		workdir += "/" + filepath.ToSlash(rel)
	}
	cacheRoot, err := physicalDirectory(in.CacheRoot)
	if err != nil || cacheRoot == string(filepath.Separator) {
		return Plan{}, errors.New("invalid cache manager root")
	}
	mounts := []Mount{{Source: project, Target: "/workspace"}}
	for _, decl := range in.Manifest.Caches {
		if !filepath.IsAbs(decl.Path) || filepath.Clean(decl.Path) != decl.Path || decl.Path == "/" {
			return Plan{}, errors.New("invalid cache target")
		}
		if decl.Path == "/workspace" || strings.HasPrefix(decl.Path, "/workspace/") || decl.Path == "/tmp" || strings.HasPrefix(decl.Path, "/tmp/") || decl.Path == "/home/dproxy" || strings.HasPrefix(decl.Path, "/home/dproxy/") {
			return Plan{}, errors.New("cache target overlaps protected mount")
		}
		source, exists := in.CachePaths[decl.Path]
		if !exists {
			return Plan{}, fmt.Errorf("missing managed cache for %s", decl.Path)
		}
		physical, e := physicalDirectory(source)
		if e != nil || !within(cacheRoot, physical) || decl.Path == "/" {
			return Plan{}, errors.New("cache path is outside cache manager authority")
		}
		mounts = append(mounts, Mount{Source: physical, Target: decl.Path})
	}
	env := map[string]string{"HOME": "/home/dproxy", "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "XDG_CACHE_HOME": "/home/dproxy/.cache"}
	for k, v := range in.Manifest.Environment {
		if err := addEnvironment(env, k, v, true); err != nil {
			return Plan{}, err
		}
	}
	for k, v := range in.Sandbox.Environment {
		if err := addEnvironment(env, k, v, true); err != nil {
			return Plan{}, err
		}
	}
	memory, err := parseMemory(in.Sandbox.Memory)
	if err != nil {
		return Plan{}, err
	}
	if in.Sandbox.PIDs < 0 || in.Sandbox.PIDs > 1048576 || in.Sandbox.CPUs < 0 || in.Sandbox.CPUs > 64 {
		return Plan{}, errors.New("resource limit out of bounds")
	}
	pids := in.Sandbox.PIDs
	if pids == 0 {
		pids = 512
	}
	cpus := in.Sandbox.CPUs
	if cpus == 0 {
		cpus = 2
	}
	if memory == 0 {
		memory = 4 << 30
	}
	network := in.Sandbox.Network
	if network == "" {
		network = "none"
	}
	if network != "none" && network != "public" && network != "allowlist" {
		return Plan{}, errors.New("invalid network policy")
	}
	if network == "allowlist" && len(in.Sandbox.NetworkAllowlist) == 0 {
		return Plan{}, errors.New("allowlist network requires destinations")
	}
	ports := make([]Port, 0, len(in.Sandbox.Ports))
	for hostRaw, container := range in.Sandbox.Ports {
		host, e := strconv.Atoi(hostRaw)
		if e != nil || host < 1 || host > 65535 || container < 1 || container > 65535 {
			return Plan{}, errors.New("invalid port mapping")
		}
		ports = append(ports, Port{host, container})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Host == ports[j].Host {
			return ports[i].Container < ports[j].Container
		}
		return ports[i].Host < ports[j].Host
	})
	command := append([]string(nil), prefix...)
	command = append(command, in.Arguments...)
	return Plan{InvocationID: in.InvocationID, ProjectID: in.ProjectID, Image: in.Tool.Image + "@" + in.Tool.Digest, Workdir: workdir, Command: command, Environment: env, Mounts: mounts, Tmpfs: []Tmpfs{{"/tmp", 01777}, {"/home/dproxy", 0700}}, Ports: ports, UID: in.UID, GID: in.GID, Pids: pids, MemoryBytes: memory, CPUs: float64(cpus), ReadOnlyRoot: true, NoNewPrivileges: true, AutoRemove: true, CapDrop: []string{"ALL"}, Network: Network{Mode: network, Allowlist: append([]string(nil), in.Sandbox.NetworkAllowlist...)}}, nil
}

func physicalDirectory(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path must be absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.IsDir() {
		return "", errors.New("path must be directory")
	}
	return resolved, nil
}
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !filepath.IsAbs(rel) && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func addEnvironment(env map[string]string, k, v string, rejectReserved bool) error {
	if k == "" || strings.ContainsAny(k, "=\x00") || strings.ContainsRune(v, '\x00') {
		return errors.New("invalid environment entry")
	}
	if _, ok := reserved[k]; rejectReserved && ok {
		return fmt.Errorf("reserved environment key %s", k)
	}
	env[k] = v
	return nil
}
func parseMemory(raw string) (int64, error) {
	if raw == "" {
		return 0, nil
	}
	units := map[string]int64{"MiB": 1 << 20, "GiB": 1 << 30}
	for suffix, mult := range units {
		if strings.HasSuffix(raw, suffix) {
			n, e := strconv.ParseInt(strings.TrimSuffix(raw, suffix), 10, 64)
			if e != nil || n <= 0 || n > 1024 {
				return 0, errors.New("invalid memory limit")
			}
			return n * mult, nil
		}
	}
	return 0, errors.New("invalid memory limit")
}
