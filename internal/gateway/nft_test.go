package gateway

import (
	"net/netip"
	"testing"
	"time"

	networkpolicy "dproxy/internal/network"
	"github.com/google/nftables"
	"github.com/stretchr/testify/require"
)

type fakeNFTConn struct {
	tables   []*nftables.Table
	chains   []*nftables.Chain
	sets     []*nftables.Set
	rules    []*nftables.Rule
	elements map[string][]nftables.SetElement
	flushes  int
	err      error
}

func (f *fakeNFTConn) AddTable(t *nftables.Table) *nftables.Table {
	f.tables = append(f.tables, t)
	return t
}
func (f *fakeNFTConn) AddChain(c *nftables.Chain) *nftables.Chain {
	f.chains = append(f.chains, c)
	return c
}
func (f *fakeNFTConn) AddSet(s *nftables.Set, e []nftables.SetElement) error {
	if f.err != nil {
		return f.err
	}
	f.sets = append(f.sets, s)
	if f.elements == nil {
		f.elements = map[string][]nftables.SetElement{}
	}
	f.elements[s.Name] = append([]nftables.SetElement(nil), e...)
	return nil
}
func (f *fakeNFTConn) AddRule(r *nftables.Rule) *nftables.Rule {
	f.rules = append(f.rules, r)
	return r
}
func (f *fakeNFTConn) Flush() error { f.flushes++; return f.err }
func (f *fakeNFTConn) SetAddElements(s *nftables.Set, e []nftables.SetElement) error {
	if f.err != nil {
		return f.err
	}
	f.elements[s.Name] = append(f.elements[s.Name], e...)
	return nil
}

func TestNFTInstallBuildsRequiredChainsSetsAndOrderedRules(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"example.com:443"})
	require.NoError(t, err)
	c := &fakeNFTConn{}
	n := &NFT{Conn: c, Policy: p, DNSPort: 1053}
	require.NoError(t, n.Install())
	require.Equal(t, nftTableName, c.tables[0].Name)
	require.Equal(t, []string{"output", "dns_redirect"}, []string{c.chains[0].Name, c.chains[1].Name})
	require.Equal(t, []string{"allowed4_endpoints", "allowed6_endpoints"}, []string{c.sets[0].Name, c.sets[1].Name})
	require.True(t, c.sets[0].Concatenation)
	require.True(t, c.sets[1].Concatenation)
	require.NotEmpty(t, c.rules)
	require.Equal(t, 1, c.flushes)
}
func TestNFTInstallFailsClosedForMissingDNSAndBackendErrors(t *testing.T) {
	require.Error(t, (&NFT{Conn: &fakeNFTConn{}, Policy: networkpolicy.Public()}).Install())
	require.Error(t, (&NFT{Conn: &fakeNFTConn{err: assertErr{}}, Policy: networkpolicy.Public(), DNSPort: 1053}).Install())
}

type assertErr struct{}

func (assertErr) Error() string { return "failure" }
func TestNFTPinNormalizesFamiliesAndPreservesExpiry(t *testing.T) {
	c := &fakeNFTConn{}
	n := &NFT{Conn: c, Policy: networkpolicy.Public(), DNSPort: 1053}
	require.NoError(t, n.Install())
	ttl := 37 * time.Second
	require.NoError(t, n.Pin(t.Context(), []PinnedEndpoint{{netip.MustParseAddr("93.184.216.34"), 443}, {netip.MustParseAddr("2606:4700:4700::1111"), 80}, {netip.MustParseAddr("::ffff:93.184.216.34"), 443}}, ttl))
	require.Len(t, c.elements["allowed4_endpoints"], 2)
	require.Len(t, c.elements["allowed6_endpoints"], 1)
	require.Equal(t, ttl, c.elements["allowed4_endpoints"][0].Timeout)
	require.Equal(t, []byte{93, 184, 216, 34, 1, 187, 0, 0}, c.elements["allowed4_endpoints"][0].Key)
	require.Error(t, (&NFT{}).Pin(t.Context(), nil, ttl))
	c.err = assertErr{}
	require.Error(t, n.Pin(t.Context(), []PinnedEndpoint{{netip.MustParseAddr("93.184.216.34"), 443}}, ttl))
}
func TestNFTPinRejectsInvalidTupleOrExpiry(t *testing.T) {
	c := &fakeNFTConn{}
	n := &NFT{Conn: c, Policy: networkpolicy.Public(), DNSPort: 1053}
	require.NoError(t, n.Install())
	require.Error(t, n.Pin(t.Context(), []PinnedEndpoint{{Addr: netip.MustParseAddr("93.184.216.34"), Port: 0}}, time.Second))
	require.Error(t, n.Pin(t.Context(), []PinnedEndpoint{{Addr: netip.MustParseAddr("93.184.216.34"), Port: 443}}, 0))
}
func TestPrefixExpressionHelpers(t *testing.T) {
	require.Equal(t, []byte{255, 255, 240, 0}, prefixMask(20, 4))
	require.Equal(t, []byte{0xa0}, andBytes([]byte{0xab}, []byte{0xf0}))
}
