package gateway

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/stretchr/testify/require"
)

type dummyAddr string

func (a dummyAddr) Network() string { return "test" }
func (a dummyAddr) String() string  { return string(a) }

type dummyPacket struct {
	once   sync.Once
	closed chan struct{}
}

func newDummyPacket() *dummyPacket                            { return &dummyPacket{closed: make(chan struct{})} }
func (d *dummyPacket) ReadFrom([]byte) (int, net.Addr, error) { <-d.closed; return 0, nil, io.EOF }
func (d *dummyPacket) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (d *dummyPacket) Close() error                           { d.once.Do(func() { close(d.closed) }); return nil }
func (d *dummyPacket) LocalAddr() net.Addr                    { return dummyAddr("udp") }
func (d *dummyPacket) SetDeadline(time.Time) error            { return nil }
func (d *dummyPacket) SetReadDeadline(t time.Time) error {
	if !t.IsZero() && time.Until(t) < time.Second {
		_ = d.Close()
	}
	return nil
}
func (d *dummyPacket) SetWriteDeadline(time.Time) error { return nil }

type dummyListener struct {
	once   sync.Once
	closed chan struct{}
}

func newDummyListener() *dummyListener             { return &dummyListener{closed: make(chan struct{})} }
func (d *dummyListener) Accept() (net.Conn, error) { <-d.closed; return nil, io.EOF }
func (d *dummyListener) Close() error              { d.once.Do(func() { close(d.closed) }); return nil }
func (d *dummyListener) Addr() net.Addr            { return dummyAddr("tcp") }
func TestRuntimeControlsBindBothDNSProtocolsAndShutdown(t *testing.T) {
	r := &RuntimeControls{Policy: networkpolicy.Public(), Upstream: "127.0.0.1:53", ListenPacket: func(string, string) (net.PacketConn, error) { return newDummyPacket(), nil }, Listen: func(string, string) (net.Listener, error) { return newDummyListener(), nil }}
	require.NoError(t, r.InstallDNS(context.Background()))
	require.False(t, r.Ready())
	time.Sleep(10 * time.Millisecond)
	require.NoError(t, r.Close())
	require.False(t, r.dnsTCP)
	require.False(t, r.dnsUDP)
}
func TestRuntimeControlsFailClosedOnDNSBindFailures(t *testing.T) {
	r := &RuntimeControls{Policy: networkpolicy.Public(), DNSAddress: "127.0.0.1:1"}
	require.Error(t, r.InstallDNS(context.Background()))
	r.Upstream = "dns:53"
	r.ListenPacket = func(string, string) (net.PacketConn, error) { return nil, errors.New("udp") }
	require.ErrorContains(t, r.InstallDNS(context.Background()), "udp")
	r.ListenPacket = func(string, string) (net.PacketConn, error) { return newDummyPacket(), nil }
	r.Listen = func(string, string) (net.Listener, error) { return nil, errors.New("tcp") }
	require.ErrorContains(t, r.InstallDNS(context.Background()), "tcp")
}
func TestRuntimeControlsRequireForwardingAndFirewall(t *testing.T) {
	r := &RuntimeControls{ReadFile: func(string) ([]byte, error) { return []byte("0"), nil }}
	require.Error(t, r.InstallTCP(context.Background()))
	require.Error(t, r.InstallUDP(context.Background()))
	require.Error(t, r.InstallFirewall(context.Background()))
	r.ReadFile = func(string) ([]byte, error) { return []byte("1\n"), nil }
	require.NoError(t, r.InstallTCP(context.Background()))
	require.NoError(t, r.InstallUDP(context.Background()))
	c := &fakeNFTConn{}
	r.NFT = &NFT{Conn: c, Policy: networkpolicy.Public(), DNSPort: 1053}
	require.NoError(t, r.InstallFirewall(context.Background()))
	r.dnsTCP = true
	r.dnsUDP = true
	require.True(t, r.Ready())
	c.err = assertErr{}
	r.NFT = &NFT{Conn: c, Policy: networkpolicy.Public(), DNSPort: 1053}
	require.Error(t, r.InstallFirewall(context.Background()))
}

// If a later control fails, InstallControls must tear down the controls
// already installed this bring-up — notably the DNS listener, which is bound
// and serving before the firewall lands. A partially configured gateway is
// never published ready, so leaving it live would leak a bound port and a
// resolver reachable without its firewall.
type closeRecordingControls struct {
	*RuntimeControls
	closed chan struct{}
	once   sync.Once
}

func (c *closeRecordingControls) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.RuntimeControls.Close()
}

func TestInstallControlsTearsDownPartialInstallOnFailure(t *testing.T) {
	base := &RuntimeControls{
		Policy:       networkpolicy.Public(),
		Upstream:     "127.0.0.1:53",
		ReadFile:     func(string) ([]byte, error) { return []byte("1\n"), nil },
		ListenPacket: func(string, string) (net.PacketConn, error) { return newDummyPacket(), nil },
		Listen:       func(string, string) (net.Listener, error) { return newDummyListener(), nil },
		// NFT left nil so DNS+TCP+UDP install, then InstallFirewall fails.
	}
	r := &closeRecordingControls{RuntimeControls: base, closed: make(chan struct{})}
	require.ErrorContains(t, InstallControls(context.Background(), r), "firewall")
	select {
	case <-r.closed:
	case <-time.After(time.Second):
		t.Fatal("Close was not invoked on the partially installed controls")
	}
}
func TestForwardingReaderErrorsFailClosed(t *testing.T) {
	require.Error(t, forwardingEnabledWith(func(string) ([]byte, error) { return nil, errors.New("read") }, "x"))
	require.Error(t, forwardingEnabledWith(func(string) ([]byte, error) { return nil, nil }, "x"))
}
