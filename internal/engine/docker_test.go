package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"dproxy/internal/policy"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/errdefs"
	specs "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
)

type fakeDockerAPI struct {
	info            system.Info
	version         types.Version
	lastConfig      *container.Config
	lastHost        *container.HostConfig
	lastNet         *network.NetworkingConfig
	pulled          string
	networkOptions  network.CreateOptions
	started         bool
	removed         string
	removeErr       error
	listed          []types.Container
	containerLabels map[string]string
	networkLabels   map[string]string
	resize          container.ResizeOptions
	inspectErr      error
	killedSignal    string
}

func (f *fakeDockerAPI) Info(context.Context) (system.Info, error)            { return f.info, nil }
func (f *fakeDockerAPI) ServerVersion(context.Context) (types.Version, error) { return f.version, nil }
func (f *fakeDockerAPI) ImagePull(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
	f.pulled = "pulled"
	return io.NopCloser(strings.NewReader("")), nil
}
func (f *fakeDockerAPI) ContainerCreate(_ context.Context, c *container.Config, h *container.HostConfig, n *network.NetworkingConfig, _ *specs.Platform, _ string) (container.CreateResponse, error) {
	f.lastConfig, f.lastHost, f.lastNet = c, h, n
	return container.CreateResponse{ID: "command-id"}, nil
}
func (f *fakeDockerAPI) NetworkCreate(_ context.Context, _ string, o network.CreateOptions) (network.CreateResponse, error) {
	f.networkOptions = o
	return network.CreateResponse{ID: "network-id"}, nil
}
func (f *fakeDockerAPI) ContainerStart(context.Context, string, container.StartOptions) error {
	f.started = true
	return nil
}
func (f *fakeDockerAPI) ContainerAttach(context.Context, string, container.AttachOptions) (types.HijackedResponse, error) {
	a, b := net.Pipe()
	go func() { _ = b.Close() }()
	return types.HijackedResponse{Conn: a, Reader: bufio.NewReader(a)}, nil
}
func (f *fakeDockerAPI) ContainerWait(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	s := make(chan container.WaitResponse, 1)
	e := make(chan error, 1)
	s <- container.WaitResponse{StatusCode: 23}
	return s, e
}
func (f *fakeDockerAPI) ContainerKill(_ context.Context, _ string, signal string) error {
	f.killedSignal = signal
	return nil
}
func (f *fakeDockerAPI) ContainerResize(_ context.Context, _ string, o container.ResizeOptions) error {
	f.resize = o
	return nil
}
func (f *fakeDockerAPI) ContainerInspect(context.Context, string) (types.ContainerJSON, error) {
	return types.ContainerJSON{Config: &container.Config{Labels: f.containerLabels}}, f.inspectErr
}
func (f *fakeDockerAPI) NetworkInspect(context.Context, string, network.InspectOptions) (network.Inspect, error) {
	return network.Inspect{Labels: f.networkLabels}, f.inspectErr
}
func (f *fakeDockerAPI) ContainerRemove(_ context.Context, id string, _ container.RemoveOptions) error {
	f.removed = id
	return f.removeErr
}
func (f *fakeDockerAPI) NetworkRemove(_ context.Context, id string) error {
	f.removed = id
	return f.removeErr
}
func (f *fakeDockerAPI) ContainerList(context.Context, container.ListOptions) ([]types.Container, error) {
	return f.listed, nil
}

func lockedDownPlan() policy.Plan {
	return policy.Plan{
		InvocationID: "invocation", ProjectID: "project", Image: "example.test/tool@sha256:" + strings.Repeat("d", 64),
		Workdir: "/workspace/sub", Command: []string{"tool", "arg"}, Environment: map[string]string{"SAFE": "secret"},
		Mounts: []policy.Mount{{Source: "/project", Target: "/workspace"}}, Tmpfs: []policy.Tmpfs{{Target: "/tmp", Mode: 01777}},
		Ports: []policy.Port{{Host: 3000, Container: 8080}}, UID: 1000, GID: 1001, Pids: 32, MemoryBytes: 64 << 20, CPUs: 1.5,
		ReadOnlyRoot: true, NoNewPrivileges: true, AutoRemove: true, CapDrop: []string{"ALL"}, Network: policy.Network{Mode: "none"},
	}
}

func TestDockerMapsIsolationControls(t *testing.T) {
	api := &fakeDockerAPI{}
	_, err := NewDocker(api).StartCommand(context.Background(), lockedDownPlan(), "", false)
	require.NoError(t, err)
	h := api.lastHost
	require.True(t, h.ReadonlyRootfs)
	require.Equal(t, []string{"ALL"}, []string(h.CapDrop))
	require.Equal(t, []string{"no-new-privileges"}, h.SecurityOpt)
	require.False(t, h.Privileged)
	require.Nil(t, h.Devices)
	require.Equal(t, int64(32), *h.PidsLimit)
	require.Equal(t, int64(64<<20), h.Memory)
	require.Equal(t, int64(1500000000), h.NanoCPUs)
	require.Equal(t, "1000:1001", api.lastConfig.User)
	require.Equal(t, []string{"tool", "arg"}, []string(api.lastConfig.Cmd))
	require.Equal(t, "/workspace/sub", api.lastConfig.WorkingDir)
	require.Equal(t, map[string]string{ManagedLabel: "true", ProjectLabel: "project", InvocationLabel: "invocation", RoleLabel: CommandRole}, api.lastConfig.Labels)
	require.Contains(t, api.lastConfig.Env, "SAFE=secret")
	require.Equal(t, "none", h.NetworkMode.NetworkName())
}

func TestDockerRejectsWeakenedOrUnsupportedPlans(t *testing.T) {
	tests := map[string]func(*policy.Plan){
		"digestless image":       func(p *policy.Plan) { p.Image = "example.test/tool:latest" },
		"writable root":          func(p *policy.Plan) { p.ReadOnlyRoot = false },
		"capabilities":           func(p *policy.Plan) { p.CapDrop = nil },
		"privilege escalation":   func(p *policy.Plan) { p.NoNewPrivileges = false },
		"persistent container":   func(p *policy.Plan) { p.AutoRemove = false },
		"unsupported network":    func(p *policy.Plan) { p.Network.Mode = "host" },
		"missing pid control":    func(p *policy.Plan) { p.Pids = 0 },
		"missing memory control": func(p *policy.Plan) { p.MemoryBytes = 0 },
		"missing cpu control":    func(p *policy.Plan) { p.CPUs = 0 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := lockedDownPlan()
			mutate(&p)
			_, err := NewDocker(&fakeDockerAPI{}).StartCommand(context.Background(), p, "", false)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "secret")
		})
	}
}

func TestVerifyRejectsNonLinuxAndOldAPI(t *testing.T) {
	for name, api := range map[string]*fakeDockerAPI{
		"non linux": {info: system.Info{OSType: "windows"}, version: types.Version{APIVersion: MinimumAPIVersion}},
		"old api":   {info: system.Info{OSType: "linux"}, version: types.Version{APIVersion: "1.39"}},
	} {
		t.Run(name, func(t *testing.T) { require.Error(t, NewDocker(api).Verify(context.Background())) })
	}
}

func TestDockerPullNetworkAndOwnedCleanup(t *testing.T) {
	api := &fakeDockerAPI{}
	d := NewDocker(api)
	p := lockedDownPlan()
	p.Network.Mode = "public"
	require.NoError(t, d.PullByDigest(context.Background(), p.Image))
	n, err := d.CreateNetwork(context.Background(), p)
	require.NoError(t, err)
	require.True(t, api.networkOptions.Internal)
	require.Equal(t, "true", api.networkOptions.Labels[ManagedLabel])
	api.networkLabels = resourceLabels(n)
	require.NoError(t, d.RemoveNetwork(context.Background(), n))
	r := Resource{ID: "container", Ownership: Ownership{p.ProjectID, p.InvocationID}, Role: CommandRole}
	api.containerLabels = resourceLabels(r)
	require.NoError(t, d.RemoveContainer(context.Background(), r))
	require.Equal(t, "container", api.removed)
	require.Error(t, d.RemoveContainer(context.Background(), Resource{ID: "unknown"}))
}

func TestDockerAttachStartsOnlyAfterAttachAndPreservesExit(t *testing.T) {
	api := &fakeDockerAPI{}
	a, err := NewDocker(api).Attach(context.Background(), "command", IO{Stdin: strings.NewReader(""), Stdout: io.Discard, Stderr: io.Discard})
	require.NoError(t, err)
	require.True(t, api.started)
	require.NoError(t, a.Wait())
	require.NoError(t, a.Close())
	code, err := NewDocker(api).Wait(context.Background(), "command")
	require.NoError(t, err)
	require.Equal(t, 23, code)
	require.NoError(t, NewDocker(api).Signal(context.Background(), "command", os.Interrupt))
}

func TestListOwnedRechecksLabels(t *testing.T) {
	o := Ownership{"project", "invocation"}
	api := &fakeDockerAPI{listed: []types.Container{{ID: "yes", Labels: map[string]string{ManagedLabel: "true", ProjectLabel: o.ProjectID, InvocationLabel: o.InvocationID, RoleLabel: CommandRole}}, {ID: "no", Labels: map[string]string{ManagedLabel: "true", ProjectLabel: "other", InvocationLabel: o.InvocationID}}}}
	got, err := NewDocker(api).ListOwned(context.Background(), o)
	require.NoError(t, err)
	require.Equal(t, []Resource{{ID: "yes", Ownership: o, Role: CommandRole}}, got)
	_, err = NewDocker(api).ListOwned(context.Background(), Ownership{})
	require.Error(t, err)
}

func TestEngineValidationAndRedactionHelpers(t *testing.T) {
	api := &fakeDockerAPI{info: system.Info{OSType: "linux"}, version: types.Version{APIVersion: MinimumAPIVersion}}
	require.NoError(t, NewDocker(api).Verify(context.Background()))
	require.Error(t, NewDocker(api).PullByDigest(context.Background(), "latest"))
	p := lockedDownPlan()
	_, err := NewDocker(api).CreateNetwork(context.Background(), p)
	require.Error(t, err)
	_, err = NewDocker(api).StartGateway(context.Background(), p, "network")
	require.Error(t, err)
	require.Equal(t, "failure [redacted]", redact(errors.New("failure sensitive"), map[string]string{"TOKEN": "sensitive"}).Error())
	require.Less(t, compareAPIVersion("1.39", "1.40"), 0)
	require.Greater(t, compareAPIVersion("1.41", "1.40"), 0)
	require.False(t, digestReference("repo@sha256:"+strings.Repeat("Z", 64)))
}

func TestCleanupIsIdempotentWhenResourceIsAlreadyGone(t *testing.T) {
	api := &fakeDockerAPI{inspectErr: errdefs.NotFound(errors.New("gone"))}
	r := Resource{ID: "gone", Ownership: Ownership{"project", "invocation"}, Role: CommandRole}
	require.NoError(t, NewDocker(api).RemoveContainer(context.Background(), r))
	require.NoError(t, NewDocker(api).RemoveNetwork(context.Background(), r))
}

func TestCleanupRefusesForgedOrStaleLabels(t *testing.T) {
	r := Resource{ID: "container", Ownership: Ownership{"project", "invocation"}, Role: CommandRole}
	for name, labels := range map[string]map[string]string{
		"forged project":   {ManagedLabel: "true", ProjectLabel: "other", InvocationLabel: "invocation", RoleLabel: CommandRole},
		"stale invocation": {ManagedLabel: "true", ProjectLabel: "project", InvocationLabel: "old", RoleLabel: CommandRole},
		"wrong role":       {ManagedLabel: "true", ProjectLabel: "project", InvocationLabel: "invocation", RoleLabel: GatewayRole},
	} {
		t.Run(name, func(t *testing.T) {
			api := &fakeDockerAPI{containerLabels: labels}
			require.ErrorContains(t, NewDocker(api).RemoveContainer(context.Background(), r), "labels")
			require.Empty(t, api.removed)
		})
	}
	n := Resource{ID: "network", Ownership: r.Ownership, Role: "network"}
	api := &fakeDockerAPI{networkLabels: map[string]string{ManagedLabel: "true", ProjectLabel: "project", InvocationLabel: "old", RoleLabel: "network"}}
	require.ErrorContains(t, NewDocker(api).RemoveNetwork(context.Background(), n), "labels")
	require.Empty(t, api.removed)
}

func TestDockerResizeMapsHeightAndWidth(t *testing.T) {
	api := &fakeDockerAPI{}
	require.NoError(t, NewDocker(api).Resize(context.Background(), "command", 40, 120))
	require.Equal(t, container.ResizeOptions{Height: 40, Width: 120}, api.resize)
}

func TestDockerNeverSendsWINCHThroughContainerKill(t *testing.T) {
	require.ErrorContains(t, NewDocker(&fakeDockerAPI{}).Signal(context.Background(), "command", syscall.SIGWINCH), "resize")
}

func TestDockerMapsOnlySupportedSignalsExplicitly(t *testing.T) {
	for name, tc := range map[string]struct {
		signal os.Signal
		want   string
	}{"interrupt": {syscall.SIGINT, "SIGINT"}, "terminate": {syscall.SIGTERM, "SIGTERM"}} {
		t.Run(name, func(t *testing.T) {
			api := &fakeDockerAPI{}
			require.NoError(t, NewDocker(api).Signal(context.Background(), "command", tc.signal))
			require.Equal(t, tc.want, api.killedSignal)
		})
	}
	api := &fakeDockerAPI{}
	require.ErrorContains(t, NewDocker(api).Signal(context.Background(), "command", syscall.SIGHUP), "unsupported")
	require.Empty(t, api.killedSignal)
}

type closedWaitAPI struct{}

func (closedWaitAPI) ContainerWait(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	status := make(chan container.WaitResponse, 1)
	errs := make(chan error)
	close(errs)
	status <- container.WaitResponse{StatusCode: 29}
	close(status)
	return status, errs
}
func TestWaitIgnoresClosedErrorChannel(t *testing.T) {
	code, err := NewDocker(closedWaitAPI{}).Wait(context.Background(), "command")
	require.NoError(t, err)
	require.Equal(t, 29, code)
}

func resourceLabels(r Resource) map[string]string {
	return map[string]string{ManagedLabel: "true", ProjectLabel: r.Ownership.ProjectID, InvocationLabel: r.Ownership.InvocationID, RoleLabel: r.Role}
}
