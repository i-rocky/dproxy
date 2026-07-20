package engine

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

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
	inspectErrs     []error
	inspectCalls    int
	killedSignal    string
	execOptions     container.ExecOptions
	execExit        int
	networks        []network.Summary
	networkListErr  error
}

func (f *fakeDockerAPI) Info(context.Context) (system.Info, error)            { return f.info, nil }
func (f *fakeDockerAPI) ServerVersion(context.Context) (types.Version, error) { return f.version, nil }
func (f *fakeDockerAPI) ImagePull(context.Context, string, image.PullOptions) (io.ReadCloser, error) {
	f.pulled = "pulled"
	return io.NopCloser(strings.NewReader("")), nil
}
func (f *fakeDockerAPI) ImageInspectWithRaw(context.Context, string) (types.ImageInspect, []byte, error) {
	return types.ImageInspect{}, nil, f.inspectErr
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
	f.inspectCalls++
	err := f.inspectErr
	if len(f.inspectErrs) > 0 {
		err = f.inspectErrs[0]
		f.inspectErrs = f.inspectErrs[1:]
	}
	return types.ContainerJSON{Config: &container.Config{Labels: f.containerLabels}}, err
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
func (f *fakeDockerAPI) NetworkList(context.Context, network.ListOptions) ([]network.Summary, error) {
	return f.networks, f.networkListErr
}
func (f *fakeDockerAPI) ContainerExecCreate(_ context.Context, _ string, o container.ExecOptions) (types.IDResponse, error) {
	f.execOptions = o
	return types.IDResponse{ID: "exec"}, nil
}
func (f *fakeDockerAPI) ContainerExecAttach(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error) {
	a, b := net.Pipe()
	_ = b.Close()
	return types.HijackedResponse{Conn: a, Reader: bufio.NewReader(a)}, nil
}
func (f *fakeDockerAPI) ContainerExecInspect(context.Context, string) (container.ExecInspect, error) {
	return container.ExecInspect{ExitCode: f.execExit}, nil
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

func TestRemoveContainerWaitsForConflictingAutoRemove(t *testing.T) {
	r := Resource{ID: "container", Ownership: Ownership{"project", "invocation"}, Role: CommandRole}
	api := &fakeDockerAPI{
		containerLabels: resourceLabels(r),
		removeErr:       errdefs.Conflict(errors.New("removal already in progress")),
		inspectErrs:     []error{nil, nil, errdefs.NotFound(errors.New("gone"))},
	}
	require.NoError(t, NewDocker(api).RemoveContainer(context.Background(), r))
	require.Equal(t, 3, api.inspectCalls)
}

func TestRemoveContainerConflictingAutoRemoveTimesOut(t *testing.T) {
	r := Resource{ID: "container", Ownership: Ownership{"project", "invocation"}, Role: CommandRole}
	api := &fakeDockerAPI{containerLabels: resourceLabels(r), removeErr: errdefs.Conflict(errors.New("removal already in progress"))}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	err := NewDocker(api).RemoveContainer(ctx, r)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestDockerAcceptsProvisionedLocalContentAddressedImage(t *testing.T) {
	api := &fakeDockerAPI{}
	id := "sha256:" + strings.Repeat("a", 64)
	require.NoError(t, NewDocker(api).PullByDigest(context.Background(), id))
	require.Empty(t, api.pulled)
	require.True(t, digestReference(id))
}

func TestDockerStartsOnlyGatewayWithNarrowNetworkCapability(t *testing.T) {
	dir := t.TempDir()
	policyPath := dir + "/policy.json"
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"mode":"public"}`), 0400))
	api := &fakeDockerAPI{}
	ownership := Ownership{"project", "invocation"}
	r, err := NewDocker(api).StartGateway(context.Background(), GatewaySpec{Image: "repo/gateway@sha256:" + strings.Repeat("a", 64), PolicyPath: policyPath, HealthToken: "token", InternalNetworkID: "internal", EgressNetworkID: "bridge", DNSUpstream: "11.77.0.10:53", Ownership: ownership, Ports: []policy.Port{{Host: 3000, Container: 8080}}})
	require.NoError(t, err)
	require.Equal(t, GatewayRole, r.Role)
	require.True(t, api.started)
	require.Equal(t, []string{"ALL"}, []string(api.lastHost.CapDrop))
	require.Equal(t, []string{"NET_ADMIN"}, []string(api.lastHost.CapAdd))
	require.False(t, api.lastHost.Privileged)
	require.Len(t, api.lastNet.EndpointsConfig, 2)
	require.True(t, api.lastHost.ReadonlyRootfs)
	require.True(t, api.lastHost.Mounts[0].ReadOnly)
	require.Equal(t, "3000", api.lastHost.PortBindings["8080/tcp"][0].HostPort)
	require.Contains(t, api.lastConfig.Env, "DPROXY_DNS_UPSTREAM=11.77.0.10:53")
	api.containerLabels = resourceLabels(r)
	require.NoError(t, NewDocker(api).GatewayHealth(context.Background(), r, "token"))
	require.Equal(t, []string{"/gateway", "health"}, api.execOptions.Cmd)
}

func TestDockerRejectsUnsafeGatewayDNSUpstream(t *testing.T) {
	dir := t.TempDir()
	policyPath := dir + "/policy.json"
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"mode":"public"}`), 0400))
	spec := GatewaySpec{Image: "repo/gateway@sha256:" + strings.Repeat("a", 64), PolicyPath: policyPath, HealthToken: "token", InternalNetworkID: "internal", EgressNetworkID: "bridge", DNSUpstream: "dns.example:53", Ownership: Ownership{"project", "invocation"}}
	_, err := NewDocker(&fakeDockerAPI{}).StartGateway(context.Background(), spec)
	require.ErrorContains(t, err, "DNS upstream")
}

func TestDockerCommandSharesGatewayNetworkNamespaceWithoutCapabilities(t *testing.T) {
	p := lockedDownPlan()
	p.Network.Mode = "public"
	p.Ports = []policy.Port{{Host: 3000, Container: 8080}}
	api := &fakeDockerAPI{}
	_, err := NewDocker(api).StartCommand(context.Background(), p, "gateway-id", false)
	require.NoError(t, err)
	require.Equal(t, container.NetworkMode("container:gateway-id"), api.lastHost.NetworkMode)
	require.Nil(t, api.lastNet)
	require.Empty(t, api.lastHost.CapAdd)
	require.Empty(t, api.lastHost.PortBindings)
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
	_, err = NewDocker(api).StartGateway(context.Background(), GatewaySpec{})
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

type errorWaitAPI struct{}

func (errorWaitAPI) ContainerWait(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	errs := make(chan error, 1)
	errs <- errors.New("container died")
	return nil, errs
}

type blockingWaitAPI struct{}

func (blockingWaitAPI) ContainerWait(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error) {
	return make(chan container.WaitResponse), make(chan error)
}

func TestWaitPropagatesContainerErrorAndCancellation(t *testing.T) {
	_, err := NewDocker(errorWaitAPI{}).Wait(context.Background(), "command")
	require.Error(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err = NewDocker(blockingWaitAPI{}).Wait(ctx, "command")
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestActiveDockerSubnetsMasksActiveNetworks(t *testing.T) {
	api := &fakeDockerAPI{networks: []network.Summary{{IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: "172.20.0.0/16"}}}}}}
	got, err := NewDocker(api).ActiveDockerSubnets(context.Background())
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{netip.MustParsePrefix("172.20.0.0/16")}, got)

	_, err = NewDocker(&fakeDockerAPI{networks: []network.Summary{{IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: "not-a-subnet"}}}}}}).ActiveDockerSubnets(context.Background())
	require.Error(t, err)

	got, err = NewDocker(&fakeDockerAPI{networks: []network.Summary{{IPAM: network.IPAM{Config: []network.IPAMConfig{{Subnet: ""}}}}}}).ActiveDockerSubnets(context.Background())
	require.NoError(t, err)
	require.Empty(t, got)

	_, err = NewDocker(&fakeDockerAPI{networkListErr: errors.New("boom")}).ActiveDockerSubnets(context.Background())
	require.Error(t, err)
}

func TestResizeRejectsInvalidTerminal(t *testing.T) {
	d := NewDocker(&fakeDockerAPI{})
	require.Error(t, d.Resize(context.Background(), "", 40, 120))
	require.Error(t, d.Resize(context.Background(), "command", 0, 120))
	require.Error(t, d.Resize(context.Background(), "command", 40, 0))
}

func TestGatewayHealthRejectsInvalidRequests(t *testing.T) {
	r := Resource{ID: "gateway", Ownership: Ownership{"project", "invocation"}, Role: GatewayRole}
	d := NewDocker(&fakeDockerAPI{})
	require.Error(t, d.GatewayHealth(context.Background(), r, ""))                                                                       // empty token
	require.Error(t, d.GatewayHealth(context.Background(), Resource{ID: "gateway", Ownership: r.Ownership, Role: CommandRole}, "token")) // wrong role

	require.Error(t, NewDocker(&fakeDockerAPI{inspectErr: errors.New("unreachable"), containerLabels: resourceLabels(r)}).GatewayHealth(context.Background(), r, "token")) // inspect failure

	forged := &fakeDockerAPI{containerLabels: map[string]string{ManagedLabel: "true", ProjectLabel: "other", InvocationLabel: "invocation", RoleLabel: GatewayRole}}
	require.Error(t, NewDocker(forged).GatewayHealth(context.Background(), r, "token")) // label mismatch
}

func resourceLabels(r Resource) map[string]string {
	return map[string]string{ManagedLabel: "true", ProjectLabel: r.Ownership.ProjectID, InvocationLabel: r.Ownership.InvocationID, RoleLabel: r.Role}
}
