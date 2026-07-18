package gateway

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	networkpolicy "dproxy/internal/network"
	"github.com/stretchr/testify/require"
)

type sequenceResolver struct {
	answers [][]netip.Addr
	err     error
	calls   int
}

func (r *sequenceResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if r.err != nil {
		return nil, r.err
	}
	i := r.calls
	r.calls++
	if i >= len(r.answers) {
		i = len(r.answers) - 1
	}
	return append([]netip.Addr(nil), r.answers[i]...), nil
}

func TestResolveAndAuthorizePinsOnlyWhenEveryAnswerAllowed(t *testing.T) {
	r := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("127.0.0.1")}}}
	f := NewFilter(networkpolicy.Public(), r)
	_, err := f.ResolveAndAuthorize(context.Background(), "example.com", 443)
	require.ErrorContains(t, err, "protected")
}

func TestResolveAndAuthorizeRejectsRebindingAndRedirects(t *testing.T) {
	r := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}, {netip.MustParseAddr("169.254.169.254")}}}
	f := NewFilter(networkpolicy.Public(), r)
	pinned, err := f.ResolveAndAuthorize(context.Background(), "example.com", 443)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("93.184.216.34")}, pinned)
	_, err = f.ResolveAndAuthorize(context.Background(), "example.com", 443)
	require.Error(t, err)
	require.Error(t, f.AuthorizeRedirect(context.Background(), "http://169.254.169.254/latest"))
}

func TestResolveRejectsNumericHostsAndResolverFailures(t *testing.T) {
	f := NewFilter(networkpolicy.Public(), &sequenceResolver{err: errors.New("dns down")})
	for _, host := range []string{"127.0.0.1", "2130706433", "0x7f000001"} {
		_, err := f.ResolveAndAuthorize(context.Background(), host, 443)
		require.Error(t, err)
	}
	_, err := f.ResolveAndAuthorize(context.Background(), "example.com", 443)
	require.ErrorContains(t, err, "resolve")
	_, err = NewFilter(networkpolicy.Public(), net.DefaultResolver).ResolveAndAuthorize(context.Background(), "example.com", 0)
	require.Error(t, err)
}
func TestRedirectParsesDefaultAndExplicitPorts(t *testing.T) {
	r := &sequenceResolver{answers: [][]netip.Addr{{netip.MustParseAddr("93.184.216.34")}}}
	f := NewFilter(networkpolicy.Public(), r)
	require.NoError(t, f.AuthorizeRedirect(context.Background(), "https://example.com/path"))
	require.NoError(t, f.AuthorizeRedirect(context.Background(), "http://example.com:8080/path"))
	require.Error(t, f.AuthorizeRedirect(context.Background(), "http://example.com:bad"))
	require.Error(t, f.AuthorizeRedirect(context.Background(), ":"))
}
