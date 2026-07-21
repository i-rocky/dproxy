package gateway

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	networkpolicy "github.com/i-rocky/dproxy/internal/network"
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

func TestNFTInstallDropsInboundExceptEstablishedAndLoopback(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"example.com:443"})
	require.NoError(t, err)
	c := &fakeNFTConn{}
	require.NoError(t, (&NFT{Conn: c, Policy: p, DNSPort: 1053}).Install())
	var input *nftables.Chain
	for _, ch := range c.chains {
		if ch.Name == "input" {
			input = ch
		}
	}
	require.NotNil(t, input, "an input chain must harden the gateway")
	require.NotNil(t, input.Policy)
	require.Equal(t, nftables.ChainPolicyDrop, *input.Policy, "inbound is default-deny")
	var hasEstablished, loopbackRules int
	for _, r := range c.rules {
		if r.Chain == nil || r.Chain.Name != "input" {
			continue
		}
		var hasCt, hasLoopbackIP, hasPortMatch bool
		for _, e := range r.Exprs {
			p, ok := e.(*expr.Payload)
			if !ok {
				if _, ok := e.(*expr.Ct); ok {
					hasCt = true
				}
				continue
			}
			if p.Base == expr.PayloadBaseNetworkHeader && (p.Offset == 16 || p.Offset == 24) {
				hasLoopbackIP = true
			}
			if p.Base == expr.PayloadBaseTransportHeader && p.Offset == 2 {
				hasPortMatch = true
			}
		}
		if hasCt {
			hasEstablished++
		}
		if hasLoopbackIP {
			loopbackRules++
			require.True(t, hasPortMatch, "input loopback accept must scope to the resolver port, not a bare dst-IP match")
		}
	}
	require.Greater(t, hasEstablished, 0, "input must accept established/related return traffic")
	require.GreaterOrEqual(t, loopbackRules, 4, "input must accept loopback DNS for IPv4+IPv6 × TCP+UDP")
}

type concurrencyTrackingConn struct {
	*fakeNFTConn
	inflight int32
	maxSeen  int32
}

func (c *concurrencyTrackingConn) SetAddElements(s *nftables.Set, e []nftables.SetElement) error {
	cur := atomic.AddInt32(&c.inflight, 1)
	defer atomic.AddInt32(&c.inflight, -1)
	for {
		m := atomic.LoadInt32(&c.maxSeen)
		if cur <= m || atomic.CompareAndSwapInt32(&c.maxSeen, m, cur) {
			break
		}
	}
	time.Sleep(3 * time.Millisecond) // widen the window so a missing lock would overlap
	if c.fakeNFTConn != nil {
		_ = c.fakeNFTConn.SetAddElements(s, e)
	}
	return nil
}

func TestNFTPinSerializesConcurrentSetAddElements(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443", "b.example:443"})
	require.NoError(t, err)
	c := &concurrencyTrackingConn{fakeNFTConn: &fakeNFTConn{}}
	n := &NFT{Conn: c, Policy: p, DNSPort: 1053}
	require.NoError(t, n.Install())
	addr := netip.MustParseAddr("93.184.216.34")
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = n.Pin(context.Background(), []PinnedEndpoint{{Addr: addr, Port: 443}}, time.Minute)
		}()
	}
	wg.Wait()
	require.EqualValues(t, 1, atomic.LoadInt32(&c.maxSeen), "Pin must serialize Conn mutation across concurrent DNS queries")
}
