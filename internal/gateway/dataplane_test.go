package gateway

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type fakeExchange struct{ response *dns.Msg }

func (f fakeExchange) ExchangeContext(context.Context, *dns.Msg, string) (*dns.Msg, time.Duration, error) {
	return f.response, 0, nil
}

type fakePinner struct {
	pins []PinnedEndpoint
	ttl  time.Duration
}
type captureDNSWriter struct{ msg *dns.Msg }

func (w *captureDNSWriter) LocalAddr() net.Addr       { return dummyAddr("local") }
func (w *captureDNSWriter) RemoteAddr() net.Addr      { return dummyAddr("remote") }
func (w *captureDNSWriter) WriteMsg(m *dns.Msg) error { w.msg = m; return nil }
func (w *captureDNSWriter) Write([]byte) (int, error) { return 0, nil }
func (w *captureDNSWriter) Close() error              { return nil }
func (w *captureDNSWriter) TsigStatus() error         { return nil }
func (w *captureDNSWriter) TsigTimersOnly(bool)       {}
func (w *captureDNSWriter) Hijack()                   {}
func TestDNSHandlerHealthAndDeniedResponses(t *testing.T) {
	p := &DNSProxy{Policy: networkpolicy.Public()}
	w := &captureDNSWriter{}
	q := new(dns.Msg)
	q.SetQuestion("_health.dproxy.", dns.TypeA)
	p.ServeDNS(w, q)
	require.Equal(t, dns.RcodeSuccess, w.msg.Rcode)
	w = &captureDNSWriter{}
	q.SetQuestion("127.0.0.1.", dns.TypeA)
	p.ServeDNS(w, q)
	require.Equal(t, dns.RcodeRefused, w.msg.Rcode)
}

func (f *fakePinner) Pin(_ context.Context, a []PinnedEndpoint, d time.Duration) error {
	f.pins = append([]PinnedEndpoint(nil), a...)
	f.ttl = d
	return nil
}

func TestRulePlanDenyFirstAndAllowlistEndsDefaultDrop(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"example.com:443"})
	require.NoError(t, err)
	rules, err := BuildRulePlan(p)
	require.NoError(t, err)
	require.Equal(t, RuleControl, rules[0].Kind)
	require.Equal(t, RuleDNSRedirect, rules[2].Kind)
	require.Equal(t, RuleDefaultDrop, rules[len(rules)-1].Kind)
	protected, pinned := -1, -1
	for i, r := range rules {
		if r.Kind == RuleProtected && protected < 0 {
			protected = i
		}
		if r.Kind == RulePinned && pinned < 0 {
			pinned = i
		}
	}
	require.Less(t, protected, pinned)
}
func TestDNSRejectsMixedProtectedAnswersWithoutPinning(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"example.com:443"})
	require.NoError(t, err)
	pin := &fakePinner{}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Ttl: 60}, A: netip.MustParseAddr("93.184.216.34").AsSlice()}, &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Ttl: 60}, A: netip.MustParseAddr("127.0.0.1").AsSlice()}}
	proxy := &DNSProxy{Policy: p, Upstream: "dns:53", Exchange: fakeExchange{m}, Pinner: pin}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	_, err = proxy.resolve(context.Background(), q)
	require.Error(t, err)
	require.Empty(t, pin.pins)
}
func TestDNSPinsAuthorizedAnswersWithBoundedTTL(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"example.com:443"})
	require.NoError(t, err)
	pin := &fakePinner{}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Ttl: 3600}, A: netip.MustParseAddr("93.184.216.34").AsSlice()}}
	proxy := &DNSProxy{Policy: p, Upstream: "dns:53", Exchange: fakeExchange{m}, Pinner: pin, MaxTTL: 2 * time.Minute}
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	resp, err := proxy.resolve(context.Background(), q)
	require.NoError(t, err)
	require.Equal(t, 2*time.Minute, pin.ttl)
	require.Equal(t, []PinnedEndpoint{{Addr: netip.MustParseAddr("93.184.216.34"), Port: 443}}, pin.pins)
	// The returned answer TTL is clamped to the pin lifetime so a caching client
	// cannot outlive the pinned endpoint.
	require.Equal(t, uint32(120), resp.Answer[0].(*dns.A).Hdr.Ttl, "answer TTL must be clamped to the pin lifetime")
}
func TestDNSPinsOnlyAssociatedPortsForSharedIP(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443", "b.example:80"})
	require.NoError(t, err)
	pin := &fakePinner{}
	m := new(dns.Msg)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Ttl: 30}, A: netip.MustParseAddr("93.184.216.34").AsSlice()}}
	proxy := &DNSProxy{Policy: p, Upstream: "dns:53", Exchange: fakeExchange{m}, Pinner: pin}
	q := new(dns.Msg)
	q.SetQuestion("a.example.", dns.TypeA)
	_, err = proxy.resolve(context.Background(), q)
	require.NoError(t, err)
	require.Equal(t, []PinnedEndpoint{{Addr: netip.MustParseAddr("93.184.216.34"), Port: 443}}, pin.pins)
}
