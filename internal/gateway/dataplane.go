package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
)

const ControlMark = 0xd707

type RuleKind string

const (
	RuleControl     RuleKind = "control-mark"
	RuleEstablished RuleKind = "established-related"
	RuleDNSRedirect RuleKind = "dns-redirect"
	RuleProtected   RuleKind = "protected-drop"
	RulePinned      RuleKind = "pinned-allow"
	RulePublic      RuleKind = "public-allow"
	RuleDefaultDrop RuleKind = "default-drop"
)

type RuleSpec struct {
	Kind   RuleKind
	Family string
	Prefix string
	Ports  []uint16
}

// BuildRulePlan is the audited semantic ordering used by the nft backend.
func BuildRulePlan(p networkpolicy.Policy) ([]RuleSpec, error) {
	if p.Mode != "public" && p.Mode != "allowlist" {
		return nil, errors.New("unsupported policy mode")
	}
	r := []RuleSpec{{Kind: RuleControl}, {Kind: RuleEstablished}, {Kind: RuleDNSRedirect}}
	for _, raw := range p.DeniedPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, errors.New("invalid protected prefix")
		}
		family := "ip6"
		if prefix.Addr().Is4() {
			family = "ip"
		}
		r = append(r, RuleSpec{Kind: RuleProtected, Family: family, Prefix: prefix.Masked().String()})
	}
	if p.Mode == "public" {
		r = append(r, RuleSpec{Kind: RulePublic})
	} else {
		r = append(r, RuleSpec{Kind: RulePinned, Family: "ip"}, RuleSpec{Kind: RulePinned, Family: "ip6"})
	}
	return append(r, RuleSpec{Kind: RuleDefaultDrop}), nil
}

type Pinner interface {
	Pin(context.Context, []PinnedEndpoint, time.Duration) error
}
type PinnedEndpoint struct {
	Addr netip.Addr
	Port uint16
}
type DNSExchanger interface {
	ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type DNSProxy struct {
	Policy   networkpolicy.Policy
	Upstream string
	Exchange DNSExchanger
	Pinner   Pinner
	MaxTTL   time.Duration
}

func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, q *dns.Msg) {
	if len(q.Question) == 1 && q.Question[0].Name == "_health.dproxy." {
		m := new(dns.Msg)
		m.SetReply(q)
		_ = w.WriteMsg(m)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := p.resolve(ctx, q)
	if err != nil {
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeRefused)
		_ = w.WriteMsg(m)
		return
	}
	_ = w.WriteMsg(response)
}
func (p *DNSProxy) resolve(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if p == nil || len(q.Question) != 1 {
		return nil, errors.New("invalid DNS question")
	}
	host := q.Question[0].Name
	if !p.Policy.AllowsDomain(host) {
		return nil, errors.New("domain denied")
	}
	ex := p.Exchange
	if ex == nil {
		d := &net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var e error
			if err := c.Control(func(fd uintptr) { e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, ControlMark) }); err != nil {
				return err
			}
			return e
		}}
		ex = &dns.Client{Net: "udp", Dialer: d}
	}
	resp, _, err := ex.ExchangeContext(ctx, q, p.Upstream)
	if err != nil {
		return nil, fmt.Errorf("upstream DNS: %w", err)
	}
	var addrs []netip.Addr
	ttl := p.MaxTTL
	if ttl <= 0 || ttl > 5*time.Minute {
		ttl = 5 * time.Minute
	}
	for _, rr := range resp.Answer {
		var a netip.Addr
		var seconds uint32
		switch v := rr.(type) {
		case *dns.A:
			a, _ = netip.AddrFromSlice(v.A)
			seconds = v.Hdr.Ttl
		case *dns.AAAA:
			a, _ = netip.AddrFromSlice(v.AAAA)
			seconds = v.Hdr.Ttl
		default:
			continue
		}
		a = a.Unmap()
		if !p.Policy.AllowsIP(a) {
			return nil, errors.New("protected DNS answer")
		}
		addrs = append(addrs, a)
		if d := time.Duration(seconds) * time.Second; d < ttl {
			ttl = d
		}
	}
	if len(addrs) > 0 && p.Policy.Mode == "allowlist" {
		if p.Pinner == nil {
			return nil, errors.New("pinning unavailable")
		}
		if ttl <= 0 {
			ttl = time.Second
		}
		ports := p.Policy.PortsForDomain(host)
		if len(ports) == 0 {
			return nil, errors.New("domain has no allowed ports")
		}
		pins := make([]PinnedEndpoint, 0, len(addrs)*len(ports))
		for _, a := range addrs {
			for _, port := range ports {
				pins = append(pins, PinnedEndpoint{Addr: a, Port: port})
			}
		}
		if err = p.Pinner.Pin(ctx, pins, ttl); err != nil {
			return nil, fmt.Errorf("pin DNS answers: %w", err)
		}
	}
	// Clamp the returned answers to the pin lifetime so a client that caches the
	// resolution does not outlive the pinned endpoint and dial fail-closed when
	// the pin expires.
	if len(addrs) > 0 {
		clamp := uint32(ttl / time.Second)
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				v.Hdr.Ttl = clamp
			case *dns.AAAA:
				v.Hdr.Ttl = clamp
			}
		}
	}
	return resp, nil
}
