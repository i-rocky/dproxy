package engine

import (
	"context"
	"io"
	"os"

	"dproxy/internal/policy"
)

const (
	ManagedLabel    = "dev.dproxy.managed"
	ProjectLabel    = "dev.dproxy.project"
	InvocationLabel = "dev.dproxy.invocation"
	RoleLabel       = "dev.dproxy.role"
	CommandRole     = "command"
	GatewayRole     = "gateway"
)

type Resource struct {
	ID        string
	Ownership Ownership
	Role      string
}
type GatewaySpec struct {
	Image, PolicyPath, HealthToken     string
	InternalNetworkID, EgressNetworkID string
	DNSUpstream                        string
	Ownership                          Ownership
	Ports                              []policy.Port
}
type ContainerID string

type Ownership struct {
	ProjectID, InvocationID string
}

type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	TTY            bool
}

type Attachment interface {
	Wait() error
	Close() error
}

// Engine is the Docker-free execution boundary consumed by runtime and network policy.
type Engine interface {
	Verify(context.Context) error
	PullByDigest(context.Context, string) error
	CreateNetwork(context.Context, policy.Plan) (Resource, error)
	StartGateway(context.Context, GatewaySpec) (Resource, error)
	GatewayHealth(context.Context, Resource, string) error
	StartCommand(context.Context, policy.Plan, string, bool) (Resource, error)
	Attach(context.Context, string, IO) (Attachment, error)
	Wait(context.Context, string) (int, error)
	Resize(context.Context, ContainerID, uint, uint) error
	Signal(context.Context, string, os.Signal) error
	RemoveContainer(context.Context, Resource) error
	RemoveNetwork(context.Context, Resource) error
	ListOwned(context.Context, Ownership) ([]Resource, error)
}
