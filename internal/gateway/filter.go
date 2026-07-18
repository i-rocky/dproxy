package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	networkpolicy "dproxy/internal/network"
)

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Filter struct {
	policy   networkpolicy.Policy
	resolver Resolver
}

func NewFilter(policy networkpolicy.Policy, resolver Resolver) *Filter {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Filter{policy: policy, resolver: resolver}
}

// ResolveAndAuthorize authorizes the name and every answer as one operation.
// The returned immutable copy is the address set a caller must dial directly;
// resolving the name again at connect time would reintroduce DNS rebinding.
func (f *Filter) ResolveAndAuthorize(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	if f == nil || f.resolver == nil {
		return nil, errors.New("filter is not configured")
	}
	if !f.policy.AllowsDomain(host) {
		return nil, errors.New("destination domain is not allowed")
	}
	if !f.policy.AllowsPort(port) {
		return nil, errors.New("destination port is not allowed")
	}
	answers, err := f.resolver.LookupNetIP(ctx, "ip", strings.TrimSuffix(host, "."))
	if err != nil {
		return nil, fmt.Errorf("resolve destination: %w", err)
	}
	if len(answers) == 0 {
		return nil, errors.New("resolve destination: no addresses")
	}
	pinned := make([]netip.Addr, 0, len(answers))
	seen := make(map[netip.Addr]bool)
	for _, answer := range answers {
		answer = answer.Unmap()
		if !f.policy.AllowsIP(answer) {
			return nil, errors.New("DNS answer resolves to a protected address")
		}
		if !seen[answer] {
			pinned = append(pinned, answer)
			seen[answer] = true
		}
	}
	return pinned, nil
}

func (f *Filter) AuthorizeRedirect(ctx context.Context, location string) error {
	u, err := url.Parse(location)
	if err != nil || u.Hostname() == "" {
		return errors.New("invalid redirect destination")
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil {
			return errors.New("invalid redirect port")
		}
	}
	_, err = f.ResolveAndAuthorize(ctx, u.Hostname(), port)
	return err
}
