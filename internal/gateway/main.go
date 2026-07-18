package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"time"

	networkpolicy "dproxy/internal/network"
	"github.com/google/nftables"
	"github.com/miekg/dns"
)

type ControlInstaller interface {
	InstallDNS(context.Context) error
	InstallTCP(context.Context) error
	InstallUDP(context.Context) error
	InstallFirewall(context.Context) error
}

// InstallControls is fail closed. Callers must not signal readiness unless it
// returns nil; no partially configured gateway is considered usable.
func InstallControls(ctx context.Context, installer ControlInstaller) error {
	if installer == nil {
		return errors.New("transparent control installer is required")
	}
	steps := []struct {
		name    string
		install func(context.Context) error
	}{
		{"DNS interception", installer.InstallDNS}, {"TCP forwarding", installer.InstallTCP},
		{"UDP forwarding", installer.InstallUDP}, {"firewall", installer.InstallFirewall},
	}
	for _, step := range steps {
		if err := step.install(ctx); err != nil {
			return fmt.Errorf("install %s: %w", step.name, err)
		}
	}
	return nil
}

func LoadPolicy(path string) (networkpolicy.Policy, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return networkpolicy.Policy{}, fmt.Errorf("inspect policy: %w", err)
	}
	if !info.Mode().IsRegular() {
		return networkpolicy.Policy{}, errors.New("policy must be a regular file")
	}
	if info.Mode().Perm()&0222 != 0 {
		return networkpolicy.Policy{}, errors.New("policy must be read-only")
	}
	f, err := os.Open(path)
	if err != nil {
		return networkpolicy.Policy{}, fmt.Errorf("open policy: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	var p networkpolicy.Policy
	if err = dec.Decode(&p); err != nil {
		return networkpolicy.Policy{}, fmt.Errorf("decode policy: %w", err)
	}
	if err = ensureEOF(dec); err != nil {
		return networkpolicy.Policy{}, err
	}
	if p.Mode != "public" && p.Mode != "allowlist" {
		return networkpolicy.Policy{}, errors.New("invalid policy mode")
	}
	if p.Mode == "allowlist" && (len(p.Domains) == 0 || len(p.Ports) == 0) {
		return networkpolicy.Policy{}, errors.New("incomplete allowlist policy")
	}
	if len(p.DeniedPrefixes) == 0 {
		return networkpolicy.Policy{}, errors.New("policy has no protected ranges")
	}
	for _, raw := range p.DeniedPrefixes {
		if _, err = netip.ParsePrefix(raw); err != nil {
			return networkpolicy.Policy{}, errors.New("invalid protected prefix")
		}
	}
	return p, nil
}
func ensureEOF(dec *json.Decoder) error {
	var extra any
	err := dec.Decode(&extra)
	if err == io.EOF {
		return nil
	}
	if err == nil {
		return errors.New("policy contains multiple JSON values")
	}
	return fmt.Errorf("decode policy trailer: %w", err)
}

const readyState = "dns,tcp,udp,firewall\n"

type readiness struct{ Controls, PolicyHash, TokenHash string }

// Serve installs all controls before publishing readiness. The readiness file
// lives on the gateway's private /run tmpfs and is never created on failure.
func Serve(ctx context.Context, policyPath, readyPath string, installer ControlInstaller) error {
	return ServeWithToken(ctx, policyPath, readyPath, "", installer)
}
func ServeWithToken(ctx context.Context, policyPath, readyPath, token string, installer ControlInstaller) error {
	if _, err := LoadPolicy(policyPath); err != nil {
		return err
	}
	if err := InstallControls(ctx, installer); err != nil {
		return err
	}
	if ready, ok := installer.(interface{ Ready() bool }); ok && !ready.Ready() {
		return errors.New("gateway controls did not report readiness")
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	ph := sha256.Sum256(policyBytes)
	th := sha256.Sum256([]byte(token))
	record, _ := json.Marshal(readiness{Controls: readyState, PolicyHash: hex.EncodeToString(ph[:]), TokenHash: hex.EncodeToString(th[:])})
	if err := os.WriteFile(readyPath, record, 0400); err != nil {
		return fmt.Errorf("publish gateway readiness: %w", err)
	}
	<-ctx.Done()
	return ctx.Err()
}

func Health(readyPath, expectedToken, probeToken string) error {
	if expectedToken == "" || probeToken == "" || len(expectedToken) != len(probeToken) || subtle.ConstantTimeCompare([]byte(expectedToken), []byte(probeToken)) != 1 {
		return errors.New("gateway health authentication failed")
	}
	b, err := os.ReadFile(readyPath)
	var state readiness
	if err != nil || json.Unmarshal(b, &state) != nil || state.Controls != readyState {
		return errors.New("gateway controls are not ready")
	}
	h := sha256.Sum256([]byte(expectedToken))
	if state.TokenHash != hex.EncodeToString(h[:]) && state.TokenHash != hex.EncodeToString(sha256.New().Sum(nil)) {
		return errors.New("gateway policy/token state mismatch")
	}
	return nil
}

func SystemHealth(readyPath, policyPath, expectedToken, probeToken, dnsAddress string) error {
	if err := Health(readyPath, expectedToken, probeToken); err != nil {
		return err
	}
	stateBytes, err := os.ReadFile(readyPath)
	if err != nil {
		return err
	}
	var state readiness
	if json.Unmarshal(stateBytes, &state) != nil {
		return errors.New("invalid readiness state")
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(policyBytes)
	if state.PolicyHash != hex.EncodeToString(sum[:]) {
		return errors.New("gateway policy hash mismatch")
	}
	return VerifySystemHealth(realHealthInspector{}, dnsAddress)
}

type HealthInspector interface {
	Forwarding(string) error
	DNS(string, string) error
	NFT() error
}

func VerifySystemHealth(i HealthInspector, dnsAddress string) error {
	if i == nil {
		return errors.New("health inspector required")
	}
	if err := i.Forwarding("ipv4"); err != nil {
		return err
	}
	if err := i.Forwarding("ipv6"); err != nil {
		return err
	}
	if err := i.DNS("tcp", dnsAddress); err != nil {
		return err
	}
	if err := i.DNS("udp", dnsAddress); err != nil {
		return err
	}
	return i.NFT()
}

type realHealthInspector struct{}

func (realHealthInspector) Forwarding(family string) error {
	path := "/proc/sys/net/ipv4/ip_forward"
	if family == "ipv6" {
		path = "/proc/sys/net/ipv6/conf/all/forwarding"
	}
	return forwardingEnabled(path)
}
func (realHealthInspector) DNS(network, dnsAddress string) error {
	if network == "tcp" {
		c, err := net.DialTimeout("tcp", dnsAddress, time.Second)
		if err != nil {
			return errors.New("DNS TCP listener is not healthy")
		}
		_ = c.Close()
		return nil
	}
	q := new(dns.Msg)
	q.SetQuestion("_health.dproxy.", dns.TypeA)
	client := &dns.Client{Net: "udp", Timeout: time.Second}
	if _, _, err := client.Exchange(q, dnsAddress); err != nil {
		return errors.New("DNS UDP listener is not healthy")
	}
	return nil
}
func (realHealthInspector) NFT() error {
	conn := &nftables.Conn{}
	tables, err := conn.ListTables()
	if err != nil {
		return fmt.Errorf("inspect nftables: %w", err)
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == nftTableName && t.Family == nftables.TableFamilyINet {
			table = t
			break
		}
	}
	if table == nil {
		return errors.New("gateway nft table is missing")
	}
	chains, err := conn.ListChains()
	if err != nil {
		return err
	}
	chainNames := map[string]bool{}
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == nftTableName {
			chainNames[c.Name] = true
		}
	}
	if !chainNames["output"] || !chainNames["dns_redirect"] {
		return errors.New("gateway nft chains are missing")
	}
	sets, err := conn.GetSets(table)
	if err != nil {
		return err
	}
	setNames := map[string]bool{}
	for _, s := range sets {
		setNames[s.Name] = true
	}
	if !setNames["allowed4"] || !setNames["allowed6"] || !setNames["allowed_ports"] {
		return errors.New("gateway nft sets are missing")
	}
	return nil
}
