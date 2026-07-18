// Package network defines the deny-first policy shared by the host and gateway.
package network

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Policy is intentionally data-only so the exact policy can be JSON encoded for
// the gateway. DeniedPrefixes includes the host's active Docker networks.
type Policy struct {
	Mode           string            `json:"mode"`
	Endpoints      []AllowedEndpoint `json:"endpoints,omitempty"`
	DeniedPrefixes []string          `json:"denied_prefixes"`
}
type AllowedEndpoint struct {
	Domain string   `json:"domain"`
	Ports  []uint16 `json:"ports"`
}

// The deny list is based on the IANA IPv4 and IPv6 special-purpose registries.
// It is deliberately broader than RFC1918: any non-global or exceptional range
// is unavailable to untrusted commands.
var specialPrefixes = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
	"169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
	"192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
	"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
	"224.0.0.0/4", "240.0.0.0/4",
	"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
	"2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

func Public(dockerSubnets ...netip.Prefix) Policy {
	p := Policy{Mode: "public", DeniedPrefixes: append([]string(nil), specialPrefixes...)}
	for _, prefix := range dockerSubnets {
		if prefix.IsValid() {
			p.DeniedPrefixes = append(p.DeniedPrefixes, prefix.Masked().String())
		}
	}
	return p
}
func (p Policy) ValidateBaseline() error {
	denied := make([]netip.Prefix, 0, len(p.DeniedPrefixes))
	for _, raw := range p.DeniedPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return errors.New("invalid denied prefix")
		}
		denied = append(denied, prefix.Masked())
	}
	for _, raw := range specialPrefixes {
		mandatory := netip.MustParsePrefix(raw).Masked()
		covered := false
		for _, candidate := range denied {
			if candidate.Addr().BitLen() == mandatory.Addr().BitLen() && candidate.Bits() <= mandatory.Bits() && candidate.Contains(mandatory.Addr()) {
				covered = true
				break
			}
		}
		if !covered {
			return errors.New("policy omits mandatory deny baseline")
		}
	}
	return nil
}

// Allowlist accepts host:port entries. Requiring the port avoids a domain entry
// silently granting every service on that host.
func Allowlist(entries []string, dockerSubnets ...netip.Prefix) (Policy, error) {
	p := Public(dockerSubnets...)
	p.Mode = "allowlist"
	index := map[string]int{}
	for _, entry := range entries {
		host, rawPort, err := net.SplitHostPort(entry)
		if err != nil || host == "" {
			return Policy{}, errors.New("allowlist entry must be domain:port")
		}
		host, err = canonicalDomain(host)
		if err != nil {
			return Policy{}, err
		}
		port, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || port == 0 {
			return Policy{}, errors.New("invalid allowlist port")
		}
		i, ok := index[host]
		if !ok {
			i = len(p.Endpoints)
			index[host] = i
			p.Endpoints = append(p.Endpoints, AllowedEndpoint{Domain: host})
		}
		found := false
		for _, existing := range p.Endpoints[i].Ports {
			if existing == uint16(port) {
				found = true
			}
		}
		if !found {
			p.Endpoints[i].Ports = append(p.Endpoints[i].Ports, uint16(port))
		}
	}
	if len(p.Endpoints) == 0 {
		return Policy{}, errors.New("allowlist is empty")
	}
	return p, nil
}

func (p Policy) AllowsIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, raw := range p.DeniedPrefixes {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return false
		} // corrupt policy fails closed
		if prefix.Contains(addr) {
			return false
		}
	}
	return addr.IsGlobalUnicast()
}

func (p Policy) AllowsDomain(raw string) bool {
	host, err := canonicalDomain(raw)
	if err != nil {
		return false
	}
	if p.Mode == "public" {
		return true
	}
	if p.Mode != "allowlist" {
		return false
	}
	for _, allowed := range p.Endpoints {
		if host == allowed.Domain {
			return true
		}
	}
	return false
}

func (p Policy) AllowsPort(port int) bool {
	if port < 1 || port > 65535 {
		return false
	}
	if p.Mode == "public" {
		return true
	}
	if p.Mode != "allowlist" {
		return false
	}
	for _, endpoint := range p.Endpoints {
		for _, allowed := range endpoint.Ports {
			if int(allowed) == port {
				return true
			}
		}
	}
	return false
}
func (p Policy) PortsForDomain(raw string) []uint16 {
	host, err := canonicalDomain(raw)
	if err != nil {
		return nil
	}
	for _, e := range p.Endpoints {
		if e.Domain == host {
			return append([]uint16(nil), e.Ports...)
		}
	}
	return nil
}
func (p Policy) AllowsEndpoint(domain string, port int) bool {
	if p.Mode == "public" {
		return p.AllowsDomain(domain) && p.AllowsPort(port)
	}
	for _, allowed := range p.PortsForDomain(domain) {
		if int(allowed) == port {
			return true
		}
	}
	return false
}

func canonicalDomain(raw string) (string, error) {
	raw = strings.TrimSuffix(strings.TrimSpace(raw), ".")
	if raw == "" || strings.Contains(raw, "..") || strings.ContainsAny(raw, "[]:%/\\\x00") {
		return "", errors.New("invalid domain")
	}
	// ParseAddr catches canonical IPs; this catches legacy inet_aton forms such
	// as 127.1, octal/hex, and a single integer address.
	if _, err := netip.ParseAddr(raw); err == nil || ambiguousNumeric(raw) {
		return "", errors.New("numeric hosts are not allowed")
	}
	host, err := idna.Lookup.ToASCII(raw)
	if err != nil || len(host) > 253 || !strings.Contains(host, ".") {
		return "", errors.New("invalid domain")
	}
	return strings.ToLower(host), nil
}

func ambiguousNumeric(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.ParseUint(part, 0, 32); err != nil {
			if _, err = strconv.ParseUint(part, 10, 32); err != nil {
				return false
			}
		}
	}
	return true
}
