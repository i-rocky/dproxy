//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/i-rocky/dproxy/internal/engine"
	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/i-rocky/dproxy/internal/policy"
	"github.com/i-rocky/dproxy/internal/testimage"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

func testServerImage(ctx context.Context, api *client.Client) (string, error) {
	return testimage.Scratch(ctx, api, "test/fixtures/servers", "servers")
}

func TestGatewayLiveDataplaneAllowsControlledPublicAndDeniesPrivate(t *testing.T) {
	api, attackerImage, gatewayImage := fixtures(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	serverImage, err := testServerImage(ctx, api)
	require.NoError(t, err)
	publicNet := createFixtureNetwork(t, ctx, api, "11.77.0.0/24")
	privateNet := createFixtureNetwork(t, ctx, api, "10.77.0.0/24")
	metadataNet := createFixtureNetwork(t, ctx, api, "169.254.77.0/24")
	internalNet := createFixtureNetwork(t, ctx, api, "172.29.77.0/24")
	server := startFixtureServer(t, ctx, api, serverImage, publicNet)
	require.NoError(t, api.NetworkConnect(ctx, privateNet, server, &network.EndpointSettings{IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: "10.77.0.10"}}))
	require.NoError(t, api.NetworkConnect(ctx, metadataNet, server, &network.EndpointSettings{}))
	// IPv6 dataplane is best-effort. Some hosts (notably GitHub Actions runners)
	// block IPv6 neighbor discovery inside Docker network namespaces, so the
	// network attach fails with "sendmsg: operation not permitted". Detect that
	// and skip the IPv6 assertions cleanly; the IPv4 dataplane is still fully
	// exercised.
	ipv6Net, ipv6, haveIPv6 := setupIPv6(t, ctx, api, server)
	inspect, err := api.ContainerInspect(ctx, server)
	require.NoError(t, err)
	privateIP := inspect.NetworkSettings.Networks[privateNet].IPAddress
	metadataIP := inspect.NetworkSettings.Networks[metadataNet].IPAddress

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	gatewayPolicy, err := networkpolicy.Allowlist([]string{"one.test:8080", "two.test:8081", "rebind.test:8080"})
	require.NoError(t, err)
	raw, err := json.Marshal(gatewayPolicy)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(policyPath, raw, 0444))
	de := engine.NewDocker(api)
	ownership := engine.Ownership{ProjectID: "gateway-dataplane", InvocationID: fmt.Sprintf("gateway-%d", time.Now().UnixNano())}
	gateway, err := de.StartGateway(ctx, engine.GatewaySpec{Image: gatewayImage, PolicyPath: policyPath, HealthToken: "integration-health", InternalNetworkID: internalNet, EgressNetworkID: publicNet, DNSUpstream: "11.77.0.10:53", Ownership: ownership})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, de.RemoveContainer(context.Background(), gateway)) })
	require.NoError(t, api.NetworkConnect(ctx, privateNet, gateway.ID, &network.EndpointSettings{}))
	require.NoError(t, api.NetworkConnect(ctx, metadataNet, gateway.ID, &network.EndpointSettings{}))
	if haveIPv6 {
		if err := api.NetworkConnect(ctx, ipv6Net, gateway.ID, &network.EndpointSettings{}); err != nil {
			haveIPv6 = false
		}
	}
	require.Eventually(t, func() bool { return de.GatewayHealth(ctx, gateway, "integration-health") == nil }, 10*time.Second, 100*time.Millisecond)

	env := map[string]string{
		"ATTACK_PUBLIC":      "http://one.test:8080",
		"ATTACK_ALLOWED_TWO": "http://two.test:8081",
		"ATTACK_CROSS":       "http://one.test:8081",
		"ATTACK_PRIVATE":     "http://" + privateIP + ":8080",
		"ATTACK_METADATA":    "http://" + metadataIP + ":8080",
		"ATTACK_ALT_DNS":     "8.8.8.8:53",
		"ATTACK_REBIND":      "http://rebind.test:8080",
	}
	if haveIPv6 {
		env["ATTACK_IPV6"] = "http://[" + ipv6 + "]:8080"
	}
	plan := policy.Plan{InvocationID: ownership.InvocationID, ProjectID: ownership.ProjectID, Image: attackerImage, Workdir: "/workspace", Command: []string{"gateway-probe"}, Environment: env, Mounts: []policy.Mount{{Source: t.TempDir(), Target: "/workspace"}}, Tmpfs: []policy.Tmpfs{{Target: "/tmp", Mode: 01777}, {Target: "/home/dproxy", Mode: 0700}}, UID: os.Getuid(), GID: os.Getgid(), Pids: 32, MemoryBytes: 64 << 20, CPUs: 1, ReadOnlyRoot: true, NoNewPrivileges: true, AutoRemove: true, CapDrop: []string{"ALL"}, Network: policy.Network{Mode: "public"}}
	command, err := de.StartCommand(ctx, plan, gateway.ID, false)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, de.RemoveContainer(context.Background(), command)) })
	var output bytes.Buffer
	attachment, err := de.Attach(ctx, command.ID, engine.IO{Stdout: &output, Stderr: &output})
	require.NoError(t, err)
	code, err := de.Wait(ctx, command.ID)
	require.NoError(t, err)
	require.Zero(t, code, output.String())
	require.NoError(t, attachment.Wait())
	require.NoError(t, attachment.Close())
	var result attackResult
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result), output.String())
	require.True(t, result.Probes["PUBLIC"])
	require.True(t, result.Probes["ALLOWED_TWO"])
	require.False(t, result.Probes["CROSS"])
	require.False(t, result.Probes["PRIVATE"])
	require.False(t, result.Probes["METADATA"])
	if haveIPv6 {
		require.False(t, result.Probes["IPV6"])
	}
	require.True(t, result.Probes["ALT_DNS"])
	require.False(t, result.Probes["REBIND"])
}

// setupIPv6 creates the IPv6 fixture network and attaches the server, returning
// the network name, the server's IPv6 address, and whether the host provides an
// IPv6 dataplane. Network creation or attach can fail on hosts that block IPv6
// neighbor discovery in Docker network namespaces (sendmsg EPERM); in that case
// the caller skips the IPv6 assertions instead of failing the whole test.
func setupIPv6(t *testing.T, ctx context.Context, api *client.Client, server string) (string, string, bool) {
	t.Helper()
	enabled := true
	name := fmt.Sprintf("dproxy-fixture-v6-%d", time.Now().UnixNano())
	created, err := api.NetworkCreate(ctx, name, network.CreateOptions{EnableIPv6: &enabled, IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: "fd77::/64"}}}})
	if err != nil {
		return "", "", false
	}
	t.Cleanup(func() { _ = api.NetworkRemove(context.Background(), created.ID) })
	if err := api.NetworkConnect(ctx, name, server, &network.EndpointSettings{}); err != nil {
		return "", "", false
	}
	inspect, err := api.ContainerInspect(ctx, server)
	if err != nil {
		return name, "", false
	}
	return name, inspect.NetworkSettings.Networks[name].GlobalIPv6Address, true
}

func createFixtureNetwork(t *testing.T, ctx context.Context, api *client.Client, subnet string) string {
	t.Helper()
	name := fmt.Sprintf("dproxy-fixture-%d", time.Now().UnixNano())
	created, err := api.NetworkCreate(ctx, name, network.CreateOptions{IPAM: &network.IPAM{Config: []network.IPAMConfig{{Subnet: subnet}}}})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, api.NetworkRemove(context.Background(), created.ID)) })
	return name
}

func startFixtureServer(t *testing.T, ctx context.Context, api *client.Client, image, networkID string) string {
	t.Helper()
	networking := &network.NetworkingConfig{EndpointsConfig: map[string]*network.EndpointSettings{networkID: {NetworkID: networkID, IPAMConfig: &network.EndpointIPAMConfig{IPv4Address: "11.77.0.10"}, Aliases: []string{"one.test", "two.test", "rebind.test"}}}}
	created, err := api.ContainerCreate(ctx, &container.Config{Image: image, Env: []string{"FIXTURE_PUBLIC_IP=11.77.0.10"}}, &container.HostConfig{NetworkMode: container.NetworkMode(networkID), AutoRemove: true}, networking, nil, "")
	require.NoError(t, err)
	require.NoError(t, api.ContainerStart(ctx, created.ID, container.StartOptions{}))
	t.Cleanup(func() {
		_ = api.ContainerRemove(context.Background(), created.ID, container.RemoveOptions{Force: true})
	})
	return created.ID
}
