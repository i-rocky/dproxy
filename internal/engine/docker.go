package engine

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"dproxy/internal/policy"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/api/types/system"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const MinimumAPIVersion = "1.40"

type Docker struct{ api any }

func NewDocker(api any) *Docker { return &Docker{api: api} }

type verifyAPI interface {
	Info(context.Context) (system.Info, error)
	ServerVersion(context.Context) (types.Version, error)
}

func (d *Docker) Verify(ctx context.Context) error {
	a, ok := d.api.(verifyAPI)
	if !ok {
		return errors.New("engine does not provide verification API")
	}
	info, err := a.Info(ctx)
	if err != nil {
		return fmt.Errorf("verify engine platform: %w", err)
	}
	if info.OSType != "linux" {
		return errors.New("unsupported engine platform")
	}
	v, err := a.ServerVersion(ctx)
	if err != nil {
		return fmt.Errorf("verify engine API: %w", err)
	}
	if compareAPIVersion(v.APIVersion, MinimumAPIVersion) < 0 {
		return errors.New("unsupported engine API version")
	}
	return nil
}

type pullAPI interface {
	ImagePull(context.Context, string, image.PullOptions) (io.ReadCloser, error)
}

func (d *Docker) PullByDigest(ctx context.Context, ref string) error {
	if !digestReference(ref) {
		return errors.New("image is not pinned by digest")
	}
	if localImageID(ref) {
		a, ok := d.api.(interface {
			ImageInspectWithRaw(context.Context, string) (types.ImageInspect, []byte, error)
		})
		if !ok {
			return errors.New("engine does not provide local image inspection API")
		}
		if _, _, err := a.ImageInspectWithRaw(ctx, ref); err != nil {
			return fmt.Errorf("inspect provisioned local image: %w", err)
		}
		return nil
	}
	a, ok := d.api.(pullAPI)
	if !ok {
		return errors.New("engine does not provide image pull API")
	}
	r, err := a.ImagePull(ctx, ref, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("pull image by digest: %w", err)
	}
	defer r.Close()
	if _, err = io.Copy(io.Discard, r); err != nil {
		return fmt.Errorf("read image pull response: %w", err)
	}
	return nil
}

type createAPI interface {
	ContainerCreate(context.Context, *container.Config, *container.HostConfig, *network.NetworkingConfig, *ocispec.Platform, string) (container.CreateResponse, error)
}

func (d *Docker) StartCommand(ctx context.Context, p policy.Plan, networkID string, tty bool) (Resource, error) {
	if err := validatePlan(p, networkID); err != nil {
		return Resource{}, err
	}
	a, ok := d.api.(createAPI)
	if !ok {
		return Resource{}, errors.New("engine does not provide container create API")
	}
	env := make([]string, 0, len(p.Environment))
	for key, value := range p.Environment {
		env = append(env, key+"="+value)
	}
	sort.Strings(env)
	labels := ownershipLabels(p, CommandRole)
	cfg := &container.Config{User: fmt.Sprintf("%d:%d", p.UID, p.GID), AttachStdin: true, AttachStdout: true, AttachStderr: true, Tty: tty, OpenStdin: true, StdinOnce: true, Env: env, Cmd: append([]string(nil), p.Command...), Image: p.Image, WorkingDir: p.Workdir, Labels: labels}
	pids := int64(p.Pids)
	host := &container.HostConfig{NetworkMode: container.NetworkMode("none"), AutoRemove: p.AutoRemove, CapDrop: append([]string(nil), p.CapDrop...), ReadonlyRootfs: p.ReadOnlyRoot, SecurityOpt: []string{"no-new-privileges"}, Resources: container.Resources{PidsLimit: &pids, Memory: p.MemoryBytes, NanoCPUs: int64(p.CPUs * 1e9)}}
	for _, m := range p.Mounts {
		host.Mounts = append(host.Mounts, mount.Mount{Type: mount.TypeBind, Source: m.Source, Target: m.Target, ReadOnly: m.ReadOnly})
	}
	if len(p.Tmpfs) > 0 {
		host.Tmpfs = make(map[string]string)
	}
	for _, tmp := range p.Tmpfs {
		host.Tmpfs[tmp.Target] = fmt.Sprintf("rw,nosuid,nodev,mode=%04o", tmp.Mode.Perm())
	}
	var netCfg *network.NetworkingConfig
	if networkID != "" {
		host.NetworkMode = container.NetworkMode("container:" + networkID)
	}
	created, err := a.ContainerCreate(ctx, cfg, host, netCfg, nil, "")
	if err != nil {
		return Resource{}, fmt.Errorf("create command container: %w", redact(err, p.Environment))
	}
	return Resource{ID: created.ID, Ownership: Ownership{p.ProjectID, p.InvocationID}, Role: CommandRole}, nil
}

func validatePlan(p policy.Plan, networkID string) error {
	if !digestReference(p.Image) {
		return errors.New("image is not pinned by digest")
	}
	if p.InvocationID == "" || p.ProjectID == "" {
		return errors.New("missing resource ownership")
	}
	if !p.ReadOnlyRoot || !p.NoNewPrivileges || !p.AutoRemove || len(p.CapDrop) != 1 || p.CapDrop[0] != "ALL" {
		return errors.New("required isolation control is missing")
	}
	if p.Pids <= 0 || p.MemoryBytes <= 0 || p.CPUs <= 0 {
		return errors.New("required resource control is missing")
	}
	if p.Network.Mode != "none" && p.Network.Mode != "public" && p.Network.Mode != "allowlist" {
		return errors.New("unsupported network policy")
	}
	if p.Network.Mode == "none" && networkID != "" || p.Network.Mode != "none" && networkID == "" {
		return errors.New("network isolation state does not match policy")
	}
	return nil
}

func digestReference(ref string) bool {
	if localImageID(ref) {
		return true
	}
	parts := strings.Split(ref, "@sha256:")
	return len(parts) == 2 && parts[0] != "" && len(parts[1]) == 64 && allHex(parts[1])
}
func localImageID(ref string) bool {
	return strings.HasPrefix(ref, "sha256:") && len(ref) == 71 && allHex(ref[7:])
}
func allHex(s string) bool {
	for _, r := range s {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
func ownershipLabels(p policy.Plan, role string) map[string]string {
	return map[string]string{ManagedLabel: "true", ProjectLabel: p.ProjectID, InvocationLabel: p.InvocationID, RoleLabel: role}
}

type networkAPI interface {
	NetworkCreate(context.Context, string, network.CreateOptions) (network.CreateResponse, error)
}
type activeNetworkAPI interface {
	NetworkList(context.Context, network.ListOptions) ([]network.Summary, error)
}

func (d *Docker) ActiveDockerSubnets(ctx context.Context) ([]netip.Prefix, error) {
	a, ok := d.api.(activeNetworkAPI)
	if !ok {
		return nil, errors.New("engine does not provide active network discovery")
	}
	items, err := a.NetworkList(ctx, network.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list active Docker networks: %w", err)
	}
	var out []netip.Prefix
	for _, item := range items {
		for _, cfg := range item.IPAM.Config {
			if cfg.Subnet == "" {
				continue
			}
			p, e := netip.ParsePrefix(cfg.Subnet)
			if e != nil {
				return nil, errors.New("Docker reported an invalid active subnet")
			}
			out = append(out, p.Masked())
		}
	}
	return out, nil
}

func (d *Docker) CreateNetwork(ctx context.Context, p policy.Plan) (Resource, error) {
	if p.ProjectID == "" || p.InvocationID == "" || p.Network.Mode == "none" {
		return Resource{}, errors.New("invalid owned network plan")
	}
	a, ok := d.api.(networkAPI)
	if !ok {
		return Resource{}, errors.New("engine does not provide network create API")
	}
	labels := ownershipLabels(p, "network")
	r, err := a.NetworkCreate(ctx, "dproxy-"+p.InvocationID, network.CreateOptions{Internal: true, Labels: labels})
	if err != nil {
		return Resource{}, fmt.Errorf("create internal network: %w", err)
	}
	return Resource{ID: r.ID, Ownership: Ownership{p.ProjectID, p.InvocationID}, Role: "network"}, nil
}

type gatewayAPI interface {
	createAPI
	ContainerStart(context.Context, string, container.StartOptions) error
}

func (d *Docker) StartGateway(ctx context.Context, s GatewaySpec) (Resource, error) {
	if !digestReference(s.Image) || s.HealthToken == "" || s.InternalNetworkID == "" || s.EgressNetworkID == "" || s.InternalNetworkID == s.EgressNetworkID {
		return Resource{}, errors.New("invalid gateway specification")
	}
	if s.Ownership.ProjectID == "" || s.Ownership.InvocationID == "" {
		return Resource{}, errors.New("missing gateway ownership")
	}
	upstream := s.DNSUpstream
	if upstream == "" {
		upstream = "127.0.0.11:53"
	}
	dnsHost, port, splitErr := net.SplitHostPort(upstream)
	if splitErr != nil || net.ParseIP(dnsHost) == nil || port != "53" {
		return Resource{}, errors.New("invalid gateway DNS upstream")
	}
	info, err := os.Lstat(s.PolicyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0222 != 0 {
		return Resource{}, errors.New("gateway policy is not a read-only regular file")
	}
	a, ok := d.api.(gatewayAPI)
	if !ok {
		return Resource{}, errors.New("engine does not provide gateway create API")
	}
	labels := map[string]string{ManagedLabel: "true", ProjectLabel: s.Ownership.ProjectID, InvocationLabel: s.Ownership.InvocationID, RoleLabel: GatewayRole}
	cfg := &container.Config{Image: s.Image, Cmd: []string{"serve", "--policy", "/etc/dproxy/policy.json"}, Env: []string{"DPROXY_HEALTH_TOKEN=" + s.HealthToken, "DPROXY_DNS_UPSTREAM=" + upstream}, Labels: labels}
	host := &container.HostConfig{NetworkMode: container.NetworkMode(s.InternalNetworkID), AutoRemove: true, ReadonlyRootfs: true, CapDrop: []string{"ALL"}, CapAdd: []string{"NET_ADMIN"}, SecurityOpt: []string{"no-new-privileges"}, Sysctls: map[string]string{"net.ipv4.ip_forward": "1", "net.ipv6.conf.all.forwarding": "1"}, Mounts: []mount.Mount{{Type: mount.TypeBind, Source: filepath.Clean(s.PolicyPath), Target: "/etc/dproxy/policy.json", ReadOnly: true}}, Tmpfs: map[string]string{"/run": "rw,nosuid,nodev,noexec,mode=0700"}}
	ports := make(nat.PortSet)
	bindings := make(nat.PortMap)
	for _, port := range s.Ports {
		if port.Host < 1 || port.Host > 65535 || port.Container < 1 || port.Container > 65535 {
			return Resource{}, errors.New("invalid gateway published port")
		}
		cp := nat.Port(strconv.Itoa(port.Container) + "/tcp")
		ports[cp] = struct{}{}
		bindings[cp] = []nat.PortBinding{{HostIP: "127.0.0.1", HostPort: strconv.Itoa(port.Host)}}
	}
	cfg.ExposedPorts, host.PortBindings = ports, bindings
	netCfg := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{s.InternalNetworkID: {NetworkID: s.InternalNetworkID}, s.EgressNetworkID: {NetworkID: s.EgressNetworkID}}}
	created, err := a.ContainerCreate(ctx, cfg, host, netCfg, nil, "")
	if err != nil {
		return Resource{}, fmt.Errorf("create gateway container: %w", err)
	}
	r := Resource{ID: created.ID, Ownership: s.Ownership, Role: GatewayRole}
	if err = a.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		return r, fmt.Errorf("start gateway container: %w", err)
	}
	return r, nil
}

type gatewayHealthAPI interface {
	ContainerInspect(context.Context, string) (types.ContainerJSON, error)
	ContainerExecCreate(context.Context, string, container.ExecOptions) (types.IDResponse, error)
	ContainerExecAttach(context.Context, string, container.ExecAttachOptions) (types.HijackedResponse, error)
	ContainerExecInspect(context.Context, string) (container.ExecInspect, error)
}

func (d *Docker) GatewayHealth(ctx context.Context, r Resource, token string) error {
	if err := validateResource(r); err != nil || r.Role != GatewayRole || token == "" {
		return errors.New("invalid gateway health request")
	}
	a, ok := d.api.(gatewayHealthAPI)
	if !ok {
		return errors.New("engine does not provide gateway health API")
	}
	inspected, err := a.ContainerInspect(ctx, r.ID)
	if err != nil {
		return fmt.Errorf("inspect gateway health target: %w", err)
	}
	if inspected.Config == nil || !labelsMatch(inspected.Config.Labels, r) {
		return errors.New("gateway health target ownership mismatch")
	}
	exec, err := a.ContainerExecCreate(ctx, r.ID, container.ExecOptions{AttachStdout: true, AttachStderr: true, Cmd: []string{"/gateway", "health"}, Env: []string{"DPROXY_HEALTH_PROBE=" + token}})
	if err != nil {
		return fmt.Errorf("create gateway health probe: %w", err)
	}
	// ContainerExecAttach POSTs to the hijacked /exec/{id}/start endpoint, which
	// both starts the process and streams its IO. Calling ContainerExecStart too
	// would hit /start a second time and the daemon rejects that ("exec command …
	// is already running"), leaving the probe detached and unreadable. Draining
	// the reader blocks until the process exits, so the inspect that follows
	// observes the real exit status rather than a transiently-running exec.
	attach, attachErr := a.ContainerExecAttach(ctx, exec.ID, container.ExecAttachOptions{Detach: false, Tty: false})
	if attachErr != nil {
		return fmt.Errorf("attach gateway health probe: %w", attachErr)
	}
	var probeStdout, probeStderr bytes.Buffer
	_, _ = stdcopy.StdCopy(&probeStdout, &probeStderr, attach.Reader)
	attach.Close()
	status, err := a.ContainerExecInspect(ctx, exec.ID)
	if err != nil {
		return fmt.Errorf("inspect gateway health probe: %w", err)
	}
	if status.Running || status.ExitCode != 0 {
		return fmt.Errorf("gateway health probe failed (exit=%d running=%v): %s", status.ExitCode, status.Running, strings.TrimSpace(probeStderr.String()))
	}
	return nil
}

type attachAPI interface {
	ContainerAttach(context.Context, string, container.AttachOptions) (types.HijackedResponse, error)
	ContainerStart(context.Context, string, container.StartOptions) error
}
type dockerAttachment struct {
	response types.HijackedResponse
	done     chan error
	once     sync.Once
}

func (a *dockerAttachment) Wait() error { return <-a.done }
func (a *dockerAttachment) Close() error {
	a.once.Do(func() { a.response.Close() })
	return nil
}
func (d *Docker) Attach(ctx context.Context, id string, streams IO) (Attachment, error) {
	a, ok := d.api.(attachAPI)
	if !ok {
		return nil, errors.New("engine does not provide attach API")
	}
	r, err := a.ContainerAttach(ctx, id, container.AttachOptions{Stream: true, Stdin: true, Stdout: true, Stderr: true})
	if err != nil {
		return nil, fmt.Errorf("attach command container: %w", err)
	}
	result := &dockerAttachment{response: r, done: make(chan error, 1)}
	go func() {
		if streams.Stdin != nil {
			_, _ = io.Copy(r.Conn, streams.Stdin)
			_ = r.CloseWrite()
		}
	}()
	go func() {
		var e error
		if streams.TTY {
			_, e = io.Copy(streams.Stdout, r.Reader)
		} else {
			_, e = stdcopy.StdCopy(streams.Stdout, streams.Stderr, r.Reader)
		}
		result.done <- e
	}()
	if err = a.ContainerStart(ctx, id, container.StartOptions{}); err != nil {
		_ = result.Close()
		return nil, fmt.Errorf("start attached command container: %w", err)
	}
	return result, nil
}

type waitAPI interface {
	ContainerWait(context.Context, string, container.WaitCondition) (<-chan container.WaitResponse, <-chan error)
}

func (d *Docker) Wait(ctx context.Context, id string) (int, error) {
	a, ok := d.api.(waitAPI)
	if !ok {
		return 0, errors.New("engine does not provide wait API")
	}
	status, errs := a.ContainerWait(ctx, id, container.WaitConditionNotRunning)
	for status != nil || errs != nil {
		select {
		case err, ok := <-errs:
			if !ok {
				errs = nil
				continue
			}
			if err == nil {
				return 0, errors.New("wait for command container returned an empty error")
			}
			return 0, fmt.Errorf("wait for command container: %w", err)
		case s, ok := <-status:
			if !ok {
				status = nil
				continue
			}
			if s.Error != nil {
				return int(s.StatusCode), errors.New("command wait failed")
			}
			return int(s.StatusCode), nil
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return 0, errors.New("wait for command container closed without status")
}

type resizeAPI interface {
	ContainerResize(context.Context, string, container.ResizeOptions) error
}

func (d *Docker) Resize(ctx context.Context, id ContainerID, height, width uint) error {
	if id == "" || height == 0 || width == 0 {
		return errors.New("invalid terminal resize")
	}
	a, ok := d.api.(resizeAPI)
	if !ok {
		return errors.New("engine does not provide resize API")
	}
	if err := a.ContainerResize(ctx, string(id), container.ResizeOptions{Height: height, Width: width}); err != nil {
		return fmt.Errorf("resize command terminal: %w", err)
	}
	return nil
}

type signalAPI interface {
	ContainerKill(context.Context, string, string) error
}

func (d *Docker) Signal(ctx context.Context, id string, s os.Signal) error {
	if s == syscall.SIGWINCH {
		return errors.New("SIGWINCH requires terminal resize")
	}
	var dockerSignal string
	switch s {
	case syscall.SIGINT:
		dockerSignal = "SIGINT"
	case syscall.SIGTERM:
		dockerSignal = "SIGTERM"
	default:
		return errors.New("unsupported command signal")
	}
	a, ok := d.api.(signalAPI)
	if !ok {
		return errors.New("engine does not provide signal API")
	}
	return a.ContainerKill(ctx, id, dockerSignal)
}

type removeAPI interface {
	ContainerInspect(context.Context, string) (types.ContainerJSON, error)
	ContainerRemove(context.Context, string, container.RemoveOptions) error
}

func (d *Docker) RemoveContainer(ctx context.Context, r Resource) error {
	if err := validateResource(r); err != nil {
		return err
	}
	a, ok := d.api.(removeAPI)
	if !ok {
		return errors.New("engine does not provide container removal API")
	}
	inspected, err := a.ContainerInspect(ctx, r.ID)
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned container: %w", err)
	}
	if inspected.Config == nil || !labelsMatch(inspected.Config.Labels, r) {
		return errors.New("refusing to remove container with mismatched ownership labels")
	}
	err = a.ContainerRemove(ctx, r.ID, container.RemoveOptions{Force: true, RemoveVolumes: true})
	if errdefs.IsNotFound(err) {
		return nil
	}
	if errdefs.IsConflict(err) {
		return waitContainerAbsent(ctx, a, r.ID)
	}
	return err
}

func waitContainerAbsent(ctx context.Context, a removeAPI, id string) error {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := a.ContainerInspect(ctx, id)
		if errdefs.IsNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect container removal in progress: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

type removeNetworkAPI interface {
	NetworkInspect(context.Context, string, network.InspectOptions) (network.Inspect, error)
	NetworkRemove(context.Context, string) error
}

func (d *Docker) RemoveNetwork(ctx context.Context, r Resource) error {
	if err := validateResource(r); err != nil {
		return err
	}
	a, ok := d.api.(removeNetworkAPI)
	if !ok {
		return errors.New("engine does not provide network removal API")
	}
	inspected, err := a.NetworkInspect(ctx, r.ID, network.InspectOptions{})
	if errdefs.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect owned network: %w", err)
	}
	if !labelsMatch(inspected.Labels, r) {
		return errors.New("refusing to remove network with mismatched ownership labels")
	}
	err = a.NetworkRemove(ctx, r.ID)
	if errdefs.IsNotFound(err) {
		return nil
	}
	return err
}
func labelsMatch(labels map[string]string, r Resource) bool {
	return labels[ManagedLabel] == "true" && labels[ProjectLabel] == r.Ownership.ProjectID && labels[InvocationLabel] == r.Ownership.InvocationID && labels[RoleLabel] == r.Role
}
func validateResource(r Resource) error {
	if r.ID == "" || r.Ownership.ProjectID == "" || r.Ownership.InvocationID == "" {
		return errors.New("refusing to remove unowned resource")
	}
	return nil
}

type listAPI interface {
	ContainerList(context.Context, container.ListOptions) ([]types.Container, error)
}

func (d *Docker) ListOwned(ctx context.Context, o Ownership) ([]Resource, error) {
	if o.ProjectID == "" || o.InvocationID == "" {
		return nil, errors.New("missing ownership query")
	}
	a, ok := d.api.(listAPI)
	if !ok {
		return nil, errors.New("engine does not provide container list API")
	}
	f := filters.NewArgs(filters.Arg("label", ManagedLabel+"=true"), filters.Arg("label", ProjectLabel+"="+o.ProjectID), filters.Arg("label", InvocationLabel+"="+o.InvocationID))
	items, err := a.ContainerList(ctx, container.ListOptions{All: true, Filters: f})
	if err != nil {
		return nil, err
	}
	out := make([]Resource, 0, len(items))
	for _, item := range items {
		if item.Labels[ManagedLabel] != "true" || item.Labels[ProjectLabel] != o.ProjectID || item.Labels[InvocationLabel] != o.InvocationID {
			continue
		}
		out = append(out, Resource{ID: item.ID, Ownership: o, Role: item.Labels[RoleLabel]})
	}
	return out, nil
}

func compareAPIVersion(a, b string) int {
	parse := func(s string) (int, int) { var x, y int; fmt.Sscanf(s, "%d.%d", &x, &y); return x, y }
	ax, ay := parse(a)
	bx, by := parse(b)
	if ax < bx || ax == bx && ay < by {
		return -1
	}
	if ax == bx && ay == by {
		return 0
	}
	return 1
}
func redact(err error, env map[string]string) error {
	message := err.Error()
	for _, value := range env {
		if value != "" {
			message = strings.ReplaceAll(message, value, "[redacted]")
		}
	}
	return errors.New(message)
}
