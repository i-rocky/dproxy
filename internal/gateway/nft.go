package gateway

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"golang.org/x/sys/unix"
)

const nftTableName = "dproxy"
const MaxPinnedEndpoints uint32 = 4096

type nftConn interface {
	AddTable(*nftables.Table) *nftables.Table
	AddChain(*nftables.Chain) *nftables.Chain
	AddSet(*nftables.Set, []nftables.SetElement) error
	AddRule(*nftables.Rule) *nftables.Rule
	Flush() error
	SetAddElements(*nftables.Set, []nftables.SetElement) error
}
type NFT struct {
	Conn               nftConn
	Policy             networkpolicy.Policy
	DNSPort            uint16
	table              *nftables.Table
	allowed4, allowed6 *nftables.Set
}

func (n *NFT) Install() error {
	if n.Conn == nil {
		n.Conn = &nftables.Conn{}
	}
	if n.DNSPort == 0 {
		return errors.New("DNS listener is not configured")
	}
	plan, err := BuildRulePlan(n.Policy)
	if err != nil {
		return err
	}
	t := n.Conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: nftTableName})
	n.table = t
	drop := nftables.ChainPolicyDrop
	out := n.Conn.AddChain(&nftables.Chain{Name: "output", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	nat := n.Conn.AddChain(&nftables.Chain{Name: "dns_redirect", Table: t, Type: nftables.ChainTypeNAT, Hooknum: nftables.ChainHookOutput, Priority: nftables.ChainPriorityNATDest})
	input := n.Conn.AddChain(&nftables.Chain{Name: "input", Table: t, Type: nftables.ChainTypeFilter, Hooknum: nftables.ChainHookInput, Priority: nftables.ChainPriorityFilter, Policy: &drop})
	n.allowed4 = &nftables.Set{Table: t, Name: "allowed4_endpoints", KeyType: nftables.MustConcatSetType(nftables.TypeIPAddr, nftables.TypeInetService), Concatenation: true, HasTimeout: true, Timeout: 5 * time.Minute, Size: MaxPinnedEndpoints}
	n.allowed6 = &nftables.Set{Table: t, Name: "allowed6_endpoints", KeyType: nftables.MustConcatSetType(nftables.TypeIP6Addr, nftables.TypeInetService), Concatenation: true, HasTimeout: true, Timeout: 5 * time.Minute, Size: MaxPinnedEndpoints}
	if err = n.Conn.AddSet(n.allowed4, nil); err != nil {
		return err
	}
	if err = n.Conn.AddSet(n.allowed6, nil); err != nil {
		return err
	}
	// Marked gateway control traffic is the only bypass.
	n.Conn.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(ControlMark)}, &expr.Verdict{Kind: expr.VerdictAccept}}})
	stateMask := binaryutil.NativeEndian.PutUint32((1 << 1) | (1 << 2))
	n.Conn.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: stateMask, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, &expr.Verdict{Kind: expr.VerdictAccept}}})
	// Permit only redirected local DNS on loopback; other loopback remains denied.
	for _, target := range []struct {
		family    byte
		offset, l uint32
		addr      []byte
	}{{unix.NFPROTO_IPV4, 16, 4, netip.MustParseAddr("127.0.0.1").AsSlice()}, {unix.NFPROTO_IPV6, 24, 16, netip.MustParseAddr("::1").AsSlice()}} {
		for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			n.Conn.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{target.family}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: target.offset, Len: target.l}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: target.addr}, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(n.DNSPort)}, &expr.Verdict{Kind: expr.VerdictAccept}}})
		}
	}
	// Input hardening: the gateway shares its network namespace with the command
	// container, so legitimate inbound is only return traffic (established or
	// related) and the redirected DNS query delivered to the local resolver on
	// 127.0.0.1:DNSPort. The loopback accept is scoped to that exact
	// destination+port — mirroring the OUTPUT rule — so an external packet with a
	// spoofed dst=127.0.0.1 (deliverable when a runtime disables martian
	// filtering) cannot reach any other loopback listener. The drop policy denies
	// everything else, so peers on the egress network cannot reach the resolver.
	n.Conn.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{&expr.Ct{Key: expr.CtKeySTATE, Register: 1}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: stateMask, Xor: make([]byte, 4)}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: make([]byte, 4)}, &expr.Verdict{Kind: expr.VerdictAccept}}})
	for _, target := range []struct {
		family    byte
		offset, l uint32
		addr      []byte
	}{{unix.NFPROTO_IPV4, 16, 4, netip.MustParseAddr("127.0.0.1").AsSlice()}, {unix.NFPROTO_IPV6, 24, 16, netip.MustParseAddr("::1").AsSlice()}} {
		for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
			n.Conn.AddRule(&nftables.Rule{Table: t, Chain: input, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{target.family}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: target.offset, Len: target.l}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: target.addr}, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(n.DNSPort)}, &expr.Verdict{Kind: expr.VerdictAccept}}})
		}
	}
	// Redirect every unmarked TCP/UDP DNS attempt to the local validated resolver.
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		n.Conn.AddRule(&nftables.Rule{Table: t, Chain: nat, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyMARK, Register: 1}, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: binaryutil.NativeEndian.PutUint32(ControlMark)}, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)}, &expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(n.DNSPort)}, &expr.Redir{RegisterProtoMin: 1}}})
	}
	// The semantic plan is also encoded as userdata-order rules; protected drops
	// always precede the terminal public/pinned acceptance.
	for _, spec := range plan {
		switch spec.Kind {
		case RuleProtected:
			addPrefixRule(n.Conn, t, out, spec, true)
		case RulePublic:
			for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
				n.Conn.AddRule(&nftables.Rule{Table: t, Chain: out, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Verdict{Kind: expr.VerdictAccept}}})
			}
		case RulePinned:
			addLookupRule(n.Conn, t, out, n.allowed4, 4)
			addLookupRule(n.Conn, t, out, n.allowed6, 6)
		}
	}
	return n.Conn.Flush()
}
func addPrefixRule(c nftConn, t *nftables.Table, ch *nftables.Chain, s RuleSpec, drop bool) {
	p, _ := netip.ParsePrefix(s.Prefix)
	a := p.Addr()
	offset := uint32(24)
	family := byte(unix.NFPROTO_IPV6)
	raw := a.AsSlice()
	if a.Is4() {
		offset = 16
		family = unix.NFPROTO_IPV4
		raw = a.AsSlice()
	}
	mask := prefixMask(p.Bits(), len(raw))
	verdict := expr.VerdictDrop
	if !drop {
		verdict = expr.VerdictAccept
	}
	c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}, &expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: uint32(len(raw))}, &expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: uint32(len(raw)), Mask: mask, Xor: make([]byte, len(raw))}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: andBytes(raw, mask)}, &expr.Verdict{Kind: verdict}}})
}
func addLookupRule(c nftConn, t *nftables.Table, ch *nftables.Chain, set *nftables.Set, v int) {
	offset := uint32(24)
	ipLen := uint32(16)
	family := byte(unix.NFPROTO_IPV6)
	if v == 4 {
		offset = 16
		ipLen = 4
		family = unix.NFPROTO_IPV4
	}
	// Keep the concatenated (address, port) key entirely within the 32-bit
	// register file so the kernel can read it contiguously: IPv4 address (4B)
	// in register 8 with the port in register 9; IPv6 address (16B) in
	// registers 8..11 with the port in register 12. Splitting the key across
	// the legacy NFT_REG_1 (16-byte) area and the 32-bit area is rejected.
	const ipReg = 8
	portReg := ipReg + ipLen/4
	for _, proto := range []byte{unix.IPPROTO_TCP, unix.IPPROTO_UDP} {
		c.AddRule(&nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{family}}, &expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}, &expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}}, &expr.Payload{DestRegister: ipReg, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: ipLen}, &expr.Payload{DestRegister: portReg, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2}, &expr.Lookup{SourceRegister: ipReg, SetName: set.Name, SetID: set.ID}, &expr.Verdict{Kind: expr.VerdictAccept}}})
	}
}
func (n *NFT) Pin(_ context.Context, pins []PinnedEndpoint, ttl time.Duration) error {
	if n.Conn == nil || n.allowed4 == nil {
		return errors.New("nft pin sets unavailable")
	}
	if ttl <= 0 || ttl > 5*time.Minute {
		return errors.New("invalid pin expiry")
	}
	var v4, v6 []nftables.SetElement
	for _, pin := range pins {
		if pin.Port == 0 || !pin.Addr.IsValid() || !n.Policy.AllowsIP(pin.Addr) {
			return errors.New("invalid pinned endpoint")
		}
		a := pin.Addr.Unmap()
		key := append([]byte(nil), a.AsSlice()...)
		key = append(key, binaryutil.BigEndian.PutUint16(pin.Port)...)
		key = append(key, 0, 0)
		e := nftables.SetElement{Key: key, Timeout: ttl}
		if a.Is4() {
			v4 = append(v4, e)
		} else {
			v6 = append(v6, e)
		}
	}
	if len(v4) > 0 {
		if err := n.Conn.SetAddElements(n.allowed4, v4); err != nil {
			return err
		}
	}
	if len(v6) > 0 {
		if err := n.Conn.SetAddElements(n.allowed6, v6); err != nil {
			return err
		}
	}
	return n.Conn.Flush()
}
func prefixMask(bits, size int) []byte {
	m := make([]byte, size)
	for i := 0; i < bits; i++ {
		m[i/8] |= 1 << uint(7-i%8)
	}
	return m
}
func andBytes(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range a {
		r[i] = a[i] & b[i]
	}
	return r
}
