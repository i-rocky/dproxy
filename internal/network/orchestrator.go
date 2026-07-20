package network

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"dproxy/internal/engine"
	corepolicy "dproxy/internal/policy"
)

type GatewayEngine interface {
	CreateNetwork(context.Context, corepolicy.Plan) (engine.Resource, error)
	StartGateway(context.Context, engine.GatewaySpec) (engine.Resource, error)
	GatewayHealth(context.Context, engine.Resource, string) error
	RemoveContainer(context.Context, engine.Resource) error
	RemoveNetwork(context.Context, engine.Resource) error
}

type Request struct {
	Plan            corepolicy.Plan
	GatewayImage    string
	EgressNetworkID string
	StateDir        string
}

type Orchestrator struct{ engine GatewayEngine }
type RuntimeSession interface {
	InvocationID() string
	GatewayID() string
	Close(context.Context) error
}

func NewOrchestrator(e GatewayEngine) *Orchestrator { return &Orchestrator{engine: e} }
func (o *Orchestrator) Begin(ctx context.Context, r Request) (RuntimeSession, error) {
	return o.Start(ctx, r)
}

type Session struct {
	engine     GatewayEngine
	id         string
	resources  []engine.Resource
	policyPath string
	once       sync.Once
	closeErr   error
}

func (s *Session) InvocationID() string {
	if s == nil {
		return ""
	}
	return s.id
}
func (s *Session) NetworkID() string {
	if s == nil {
		return ""
	}
	for _, r := range s.resources {
		if r.Role == "network" {
			return r.ID
		}
	}
	return ""
}
func (s *Session) GatewayID() string {
	if s == nil {
		return ""
	}
	for _, r := range s.resources {
		if r.Role == engine.GatewayRole {
			return r.ID
		}
	}
	return ""
}

func (s *Session) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.once.Do(func() {
		var errs []error
		for i := len(s.resources) - 1; i >= 0; i-- {
			r := s.resources[i]
			var err error
			if r.Role == "network" {
				err = s.engine.RemoveNetwork(ctx, r)
			} else {
				err = s.engine.RemoveContainer(ctx, r)
			}
			if err != nil {
				errs = append(errs, err)
			}
		}
		if len(errs) > 0 {
			s.closeErr = errors.Join(errs...)
		}
		if s.policyPath != "" {
			if err := os.Remove(s.policyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.closeErr = errors.Join(s.closeErr, err)
			}
		}
	})
	return s.closeErr
}

func (o *Orchestrator) Start(ctx context.Context, req Request) (_ *Session, err error) {
	if o == nil || o.engine == nil {
		return nil, errors.New("network engine is required")
	}
	if req.Plan.ProjectID == "" {
		return nil, errors.New("project identity is required")
	}
	if req.Plan.Network.Mode != "none" && req.Plan.Network.Mode != "public" && req.Plan.Network.Mode != "allowlist" {
		return nil, errors.New("unsupported network mode")
	}
	id, err := invocationID()
	if err != nil {
		return nil, err
	}
	req.Plan.InvocationID = id
	s := &Session{engine: o.engine, id: id}
	if req.Plan.Network.Mode == "none" {
		return s, nil
	}
	if !digestReference(req.GatewayImage) {
		return nil, errors.New("gateway image is not pinned by digest")
	}
	if req.EgressNetworkID == "" {
		return nil, errors.New("explicit gateway egress network is required")
	}
	if req.StateDir == "" {
		req.StateDir = os.TempDir()
	}
	source, ok := o.engine.(interface {
		ActiveDockerSubnets(context.Context) ([]netip.Prefix, error)
	})
	if !ok {
		return nil, errors.New("engine does not provide protected subnet discovery")
	}
	subnets, e := source.ActiveDockerSubnets(ctx)
	if e != nil {
		return nil, fmt.Errorf("discover protected Docker networks: %w", e)
	}
	var gatewayPolicy Policy
	if req.Plan.Network.Mode == "public" {
		gatewayPolicy = Public(subnets...)
	} else {
		gatewayPolicy, e = Allowlist(req.Plan.Network.Allowlist, subnets...)
		if e != nil {
			return nil, fmt.Errorf("build canonical gateway allowlist: %w", e)
		}
	}
	policyPath, err := writePolicy(req.StateDir, id, gatewayPolicy)
	if err != nil {
		return nil, err
	}
	s.policyPath = policyPath
	defer func() {
		if err != nil {
			_ = s.Close(context.WithoutCancel(ctx))
		}
	}()
	token, err := invocationID()
	if err != nil {
		_ = s.Close(context.Background())
		return nil, err
	}
	network, err := o.engine.CreateNetwork(ctx, req.Plan)
	if err != nil {
		return nil, fmt.Errorf("create invocation network: %w", err)
	}
	s.resources = append(s.resources, network)
	gateway, err := o.engine.StartGateway(ctx, engine.GatewaySpec{Image: req.GatewayImage, PolicyPath: policyPath, HealthToken: token, InternalNetworkID: network.ID, EgressNetworkID: req.EgressNetworkID, Ownership: engine.Ownership{ProjectID: req.Plan.ProjectID, InvocationID: id}, Ports: append([]corepolicy.Port(nil), req.Plan.Ports...)})
	if gateway.ID != "" {
		s.resources = append(s.resources, gateway)
	}
	if err != nil {
		return nil, fmt.Errorf("start gateway: %w", err)
	}
	if err = o.engine.GatewayHealth(ctx, gateway, token); err != nil {
		return nil, fmt.Errorf("authenticate gateway health: %w", err)
	}
	return s, nil
}

func invocationID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate invocation identity: %w", err)
	}
	return hex.EncodeToString(b), nil
}
func writePolicy(dir, id string, p Policy) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("create policy directory: %w", err)
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("encode gateway policy: %w", err)
	}
	path := filepath.Join(dir, "gateway-policy-"+id+".json")
	// 0444 (not 0400): the gateway runs with cap-drop ALL and therefore lacks
	// CAP_DAC_OVERRIDE, so it cannot read an owner-only file owned by the host
	// user. World-readable + no write bits + a read-only bind mount keep the
	// policy tamper-proof while letting the gateway read it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return "", fmt.Errorf("create gateway policy: %w", err)
	}
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("write gateway policy: %w", err)
	}
	return path, nil
}
func digestReference(ref string) bool {
	if strings.HasPrefix(ref, "sha256:") && len(ref) == 71 {
		return allHex(ref[7:])
	}
	parts := strings.Split(ref, "@sha256:")
	if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 {
		return false
	}
	for _, r := range parts[1] {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}

func allHex(value string) bool {
	for _, r := range value {
		if !strings.ContainsRune("0123456789abcdef", r) {
			return false
		}
	}
	return true
}
