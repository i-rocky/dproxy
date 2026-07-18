package gateway

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	networkpolicy "dproxy/internal/network"
	"github.com/miekg/dns"
)

type RuntimeControls struct {
	Policy                             networkpolicy.Policy
	Upstream, DNSAddress               string
	NFT                                *NFT
	ReadFile                           func(string) ([]byte, error)
	ListenPacket                       func(string, string) (net.PacketConn, error)
	Listen                             func(string, string) (net.Listener, error)
	mu                                 sync.Mutex
	dnsTCP, dnsUDP, tcp, udp, firewall bool
	servers                            []*dns.Server
}

func (r *RuntimeControls) InstallDNS(context.Context) error {
	if r.DNSAddress == "" {
		r.DNSAddress = ":1053"
	}
	if r.Upstream == "" {
		return errors.New("explicit DNS upstream is required")
	}
	proxy := &DNSProxy{Policy: r.Policy, Upstream: r.Upstream, Pinner: r.NFT}
	listenPacket := r.ListenPacket
	if listenPacket == nil {
		listenPacket = net.ListenPacket
	}
	listen := r.Listen
	if listen == nil {
		listen = net.Listen
	}
	pc, err := listenPacket("udp", r.DNSAddress)
	if err != nil {
		return err
	}
	ln, err := listen("tcp", r.DNSAddress)
	if err != nil {
		_ = pc.Close()
		return err
	}
	udp := &dns.Server{PacketConn: pc, Handler: proxy}
	tcp := &dns.Server{Listener: ln, Handler: proxy}
	r.servers = []*dns.Server{udp, tcp}
	go func() { _ = udp.ActivateAndServe() }()
	go func() { _ = tcp.ActivateAndServe() }()
	r.mu.Lock()
	r.dnsUDP = true
	r.dnsTCP = true
	r.mu.Unlock()
	return nil
}
func (r *RuntimeControls) InstallTCP(context.Context) error {
	if err := forwardingEnabledWith(r.ReadFile, "/proc/sys/net/ipv4/ip_forward"); err != nil {
		return err
	}
	r.mu.Lock()
	r.tcp = true
	r.mu.Unlock()
	return nil
}
func (r *RuntimeControls) InstallUDP(context.Context) error {
	if err := forwardingEnabledWith(r.ReadFile, "/proc/sys/net/ipv6/conf/all/forwarding"); err != nil {
		return err
	}
	r.mu.Lock()
	r.udp = true
	r.mu.Unlock()
	return nil
}
func (r *RuntimeControls) InstallFirewall(context.Context) error {
	if r.NFT == nil {
		return errors.New("nft backend required")
	}
	if err := r.NFT.Install(); err != nil {
		return err
	}
	r.mu.Lock()
	r.firewall = true
	r.mu.Unlock()
	return nil
}
func (r *RuntimeControls) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.dnsTCP && r.dnsUDP && r.tcp && r.udp && r.firewall
}
func forwardingEnabled(path string) error {
	return forwardingEnabledWith(os.ReadFile, path)
}
func forwardingEnabledWith(read func(string) ([]byte, error), path string) error {
	if read == nil {
		read = os.ReadFile
	}
	b, err := read(path)
	if err != nil {
		return err
	}
	if len(b) == 0 || b[0] != '1' {
		return errors.New("kernel forwarding is disabled")
	}
	return nil
}
func (r *RuntimeControls) Close() error {
	r.mu.Lock()
	servers := append([]*dns.Server(nil), r.servers...)
	r.servers = nil
	r.dnsTCP = false
	r.dnsUDP = false
	r.mu.Unlock()
	var result error
	for i := len(servers) - 1; i >= 0; i-- {
		if err := servers[i].Shutdown(); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}
