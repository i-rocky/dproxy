package network

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"dproxy/internal/engine"
	corepolicy "dproxy/internal/policy"
	"github.com/stretchr/testify/require"
)

type fakeEngine struct {
	mu            sync.Mutex
	healthErr     error
	subnetErr     error
	invocations   []string
	rollbackCalls []string
}

func (f *fakeEngine) ActiveDockerSubnets(context.Context) ([]netip.Prefix, error) {
	return []netip.Prefix{netip.MustParsePrefix("198.18.0.0/15")}, f.subnetErr
}

func (f *fakeEngine) CreateNetwork(_ context.Context, p corepolicy.Plan) (engine.Resource, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.invocations = append(f.invocations, p.InvocationID)
	return engine.Resource{ID: "network-" + p.InvocationID, Ownership: engine.Ownership{ProjectID: p.ProjectID, InvocationID: p.InvocationID}, Role: "network"}, nil
}
func (f *fakeEngine) StartGateway(_ context.Context, s engine.GatewaySpec) (engine.Resource, error) {
	return engine.Resource{ID: "gateway-" + s.Ownership.InvocationID, Ownership: s.Ownership, Role: engine.GatewayRole}, nil
}
func (f *fakeEngine) GatewayHealth(context.Context, engine.Resource, string) error {
	return f.healthErr
}
func (f *fakeEngine) RemoveContainer(context.Context, engine.Resource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbackCalls = append(f.rollbackCalls, "remove-gateway")
	return nil
}
func (f *fakeEngine) RemoveNetwork(context.Context, engine.Resource) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rollbackCalls = append(f.rollbackCalls, "remove-network")
	return nil
}

func publicRequest() Request {
	return Request{Plan: corepolicy.Plan{ProjectID: "project", Network: corepolicy.Network{Mode: "public"}}, Policy: Public(), GatewayImage: "ghcr.io/dproxy/gateway@sha256:" + strings.Repeat("a", 64), EgressNetworkID: "bridge"}
}

func TestStartRollsBackOnGatewayHealthFailure(t *testing.T) {
	e := &fakeEngine{healthErr: errors.New("bad")}
	_, err := NewOrchestrator(e).Start(context.Background(), publicRequest())
	require.Error(t, err)
	require.Equal(t, []string{"remove-gateway", "remove-network"}, e.rollbackCalls)
}

func TestSessionCloseIsIdempotentAndReverseOrder(t *testing.T) {
	e := &fakeEngine{}
	s, err := NewOrchestrator(e).Start(context.Background(), publicRequest())
	require.NoError(t, err)
	require.NotEmpty(t, s.InvocationID())
	require.NotEmpty(t, s.NetworkID())
	require.NotEmpty(t, s.GatewayID())
	require.NoError(t, s.Close(context.Background()))
	require.NoError(t, s.Close(context.Background()))
	require.Equal(t, []string{"remove-gateway", "remove-network"}, e.rollbackCalls)
}
func TestStartFailsClosedWhenDockerSubnetDiscoveryFails(t *testing.T) {
	_, err := NewOrchestrator(&fakeEngine{subnetErr: errors.New("inspect")}).Start(context.Background(), publicRequest())
	require.ErrorContains(t, err, "Docker")
}

func TestConcurrentStartsUseUniqueInvocationIDs(t *testing.T) {
	e := &fakeEngine{}
	o := NewOrchestrator(e)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := o.Start(context.Background(), publicRequest())
			require.NoError(t, err)
			require.NoError(t, s.Close(context.Background()))
		}()
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, id := range e.invocations {
		require.False(t, seen[id])
		seen[id] = true
	}
	require.Len(t, seen, 32)
}

func TestNoneCreatesNoGatewayResources(t *testing.T) {
	e := &fakeEngine{}
	r := publicRequest()
	r.Plan.Network.Mode = "none"
	r.GatewayImage = ""
	r.EgressNetworkID = ""
	s, err := NewOrchestrator(e).Start(context.Background(), r)
	require.NoError(t, err)
	require.NoError(t, s.Close(context.Background()))
	require.Empty(t, e.invocations)
	require.Empty(t, e.rollbackCalls)
}

func TestStartRejectsUnpinnedGatewayAndMissingHealthAuthentication(t *testing.T) {
	for _, mutate := range []func(*Request){func(r *Request) { r.GatewayImage = "gateway:latest" }, func(r *Request) { r.EgressNetworkID = "" }} {
		r := publicRequest()
		mutate(&r)
		_, err := NewOrchestrator(&fakeEngine{}).Start(context.Background(), r)
		require.Error(t, err)
	}
}

func TestStartRejectsInvalidIdentityAndMode(t *testing.T) {
	for _, r := range []Request{{Plan: corepolicy.Plan{Network: corepolicy.Network{Mode: "public"}}}, {Plan: corepolicy.Plan{ProjectID: "p", Network: corepolicy.Network{Mode: "host"}}}} {
		_, err := NewOrchestrator(&fakeEngine{}).Start(context.Background(), r)
		require.Error(t, err)
	}
	_, err := NewOrchestrator(nil).Start(context.Background(), publicRequest())
	require.Error(t, err)
}
