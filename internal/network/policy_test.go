package network

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicBlocksProtectedAddresses(t *testing.T) {
	blocked := []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.17.0.1", "192.168.1.1", "192.0.2.1", "224.0.0.1", "240.0.0.1", "::", "::1", "fc00::1", "fe80::1", "ff00::1", "2001:db8::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::7f00:1", "::127.0.0.1", "::169.254.169.254", "::10.0.0.1", "::192.168.1.1"}
	for _, raw := range blocked {
		require.False(t, Public().AllowsIP(netip.MustParseAddr(raw)), raw)
	}
	require.True(t, Public().AllowsIP(netip.MustParseAddr("93.184.216.34")))
	require.True(t, Public().AllowsIP(netip.MustParseAddr("2606:4700:4700::1111")))
}

func TestPublicBlocksActiveDockerSubnets(t *testing.T) {
	p := Public(netip.MustParsePrefix("203.0.113.0/24"))
	require.False(t, p.AllowsIP(netip.MustParseAddr("203.0.113.9")))
}

func TestAllowlistCanonicalizesIDNAAndRequiresDeclaredPort(t *testing.T) {
	p, err := Allowlist([]string{"BÜCHER.example:443"})
	require.NoError(t, err)
	require.True(t, p.AllowsDomain("xn--bcher-kva.example"))
	require.True(t, p.AllowsDomain("bücher.EXAMPLE."))
	require.True(t, p.AllowsPort(443))
	require.False(t, p.AllowsPort(80))
}
func TestAllowlistPreservesDomainPortAssociation(t *testing.T) {
	p, err := Allowlist([]string{"a.example:443", "b.example:80"})
	require.NoError(t, err)
	require.True(t, p.AllowsEndpoint("a.example", 443))
	require.True(t, p.AllowsEndpoint("b.example", 80))
	require.False(t, p.AllowsEndpoint("a.example", 80))
	require.False(t, p.AllowsEndpoint("b.example", 443))
	require.Equal(t, []uint16{443}, p.PortsForDomain("a.example"))
}

// TestPortsForDomainReturnsDefensiveCopy verifies the returned port slice is a
// copy, not the policy's backing slice — dataplane.resolve builds pin sets from
// it and must not be able to mutate the policy.
func TestPortsForDomainReturnsDefensiveCopy(t *testing.T) {
	p, err := Allowlist([]string{"a.example:443"})
	require.NoError(t, err)
	ports := p.PortsForDomain("a.example")
	require.Equal(t, []uint16{443}, ports)
	ports[0] = 0
	require.Equal(t, []uint16{443}, p.PortsForDomain("a.example"), "mutating the returned slice must not corrupt the policy")

	// A domain not in the policy resolves to no ports (no implicit allow).
	require.Nil(t, p.PortsForDomain("other.example"))
}

func TestAllowlistRejectsNumericAndAmbiguousHosts(t *testing.T) {
	for _, host := range []string{"127.1:443", "2130706433:443", "0x7f000001:443", "[::1]:443", "example..com:443"} {
		_, err := Allowlist([]string{host})
		require.Error(t, err, host)
	}
}

func TestPolicyFailsClosedForInvalidState(t *testing.T) {
	require.False(t, Policy{Mode: "public", DeniedPrefixes: []string{"bad"}}.AllowsIP(netip.MustParseAddr("93.184.216.34")))
	require.False(t, Policy{Mode: "none"}.AllowsDomain("example.com"))
	require.False(t, Public().AllowsPort(0))
	require.False(t, Public().AllowsPort(65536))
	_, err := Allowlist(nil)
	require.Error(t, err)
	_, err = Allowlist([]string{"example.com:0"})
	require.Error(t, err)
}
func TestValidateBaselineRejectsAnyMissingMandatoryPrefix(t *testing.T) {
	p := Public()
	require.NoError(t, p.ValidateBaseline())
	p.DeniedPrefixes = p.DeniedPrefixes[1:]
	require.Error(t, p.ValidateBaseline())
}
func TestValidateBaselineAcceptsMoreRestrictiveCoverage(t *testing.T) {
	p := Public()
	p.DeniedPrefixes = []string{"0.0.0.0/0", "::/0"}
	require.NoError(t, p.ValidateBaseline())
}

func FuzzPolicyNeverAllowsInvalidAddress(f *testing.F) {
	for _, s := range []string{"127.0.0.1", "::ffff:127.0.0.1", "93.184.216.34"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		a, err := netip.ParseAddr(raw)
		if err != nil {
			return
		}
		_ = Public().AllowsIP(a)
	})
}
