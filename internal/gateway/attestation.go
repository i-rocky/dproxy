package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	networkpolicy "dproxy/internal/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

type NFTQuery interface {
	ListTables() ([]*nftables.Table, error)
	ListChains() ([]*nftables.Chain, error)
	GetSets(*nftables.Table) ([]*nftables.Set, error)
	GetRules(*nftables.Table, *nftables.Chain) ([]*nftables.Rule, error)
}
type ChainAttestation struct {
	Name, Type             string
	Hook, Priority, Policy int64
	Rules                  []string
}
type SetAttestation struct {
	Name, KeyName                                          string
	KeyBytes, Size                                         uint32
	Concatenation, HasTimeout, Constant, Interval, Dynamic bool
	Timeout                                                time.Duration
}
type NFTAttestation struct {
	Family byte
	Table  string
	Chains []ChainAttestation
	Sets   []SetAttestation
}

func ExpectedNFTAttestation(p networkpolicy.Policy, dnsPort uint16) (NFTAttestation, error) {
	r := &recordNFT{}
	n := &NFT{Conn: r, Policy: p, DNSPort: dnsPort}
	if err := n.Install(); err != nil {
		return NFTAttestation{}, err
	}
	return attestObjects(r.tables, r.chains, r.sets, r.rules)
}
func InspectNFTAttestation(q NFTQuery) (NFTAttestation, error) {
	if q == nil {
		return NFTAttestation{}, errors.New("nft query required")
	}
	tables, err := q.ListTables()
	if err != nil {
		return NFTAttestation{}, err
	}
	var table *nftables.Table
	for _, t := range tables {
		if t.Name == nftTableName {
			if table != nil {
				return NFTAttestation{}, errors.New("duplicate gateway nft table")
			}
			table = t
		}
	}
	if table == nil {
		return NFTAttestation{}, errors.New("gateway nft table missing")
	}
	chains, err := q.ListChains()
	if err != nil {
		return NFTAttestation{}, err
	}
	var own []*nftables.Chain
	var rules []*nftables.Rule
	for _, c := range chains {
		if c.Table != nil && c.Table.Name == nftTableName {
			own = append(own, c)
			rs, e := q.GetRules(table, c)
			if e != nil {
				return NFTAttestation{}, e
			}
			rules = append(rules, rs...)
		}
	}
	sets, err := q.GetSets(table)
	if err != nil {
		return NFTAttestation{}, err
	}
	return attestObjects([]*nftables.Table{table}, own, sets, rules)
}
func VerifyNFTAttestation(p networkpolicy.Policy, dnsPort uint16, q NFTQuery) error {
	want, err := ExpectedNFTAttestation(p, dnsPort)
	if err != nil {
		return err
	}
	got, err := InspectNFTAttestation(q)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(want, got) {
		return fmt.Errorf("gateway nft attestation mismatch")
	}
	return nil
}

func attestObjects(tables []*nftables.Table, chains []*nftables.Chain, sets []*nftables.Set, rules []*nftables.Rule) (NFTAttestation, error) {
	if len(tables) != 1 {
		return NFTAttestation{}, errors.New("unexpected gateway table count")
	}
	a := NFTAttestation{Family: byte(tables[0].Family), Table: tables[0].Name}
	for _, c := range chains {
		if c.Table == nil || c.Table.Name != a.Table {
			continue
		}
		policy := pointerInt(c.Policy)
		if policy != 0 {
			// The kernel reports a default accept policy for base chains that were
			// created without one; the only semantically meaningful value is drop(0).
			policy = -1
		}
		ca := ChainAttestation{Name: c.Name, Type: string(c.Type), Hook: pointerInt(c.Hooknum), Priority: pointerInt(c.Priority), Policy: policy}
		for _, r := range rules {
			if r.Chain != nil && r.Chain.Name == c.Name {
				b, err := canonicalExprs(r.Exprs)
				if err != nil {
					return NFTAttestation{}, err
				}
				ca.Rules = append(ca.Rules, string(b))
			}
		}
		a.Chains = append(a.Chains, ca)
	}
	sort.Slice(a.Chains, func(i, j int) bool { return a.Chains[i].Name < a.Chains[j].Name })
	for _, s := range sets {
		if s.Table == nil || s.Table.Name != a.Table {
			continue
		}
		a.Sets = append(a.Sets, SetAttestation{Name: s.Name, KeyName: s.KeyType.Name, KeyBytes: s.KeyType.Bytes, Size: s.Size, Concatenation: s.Concatenation, HasTimeout: s.HasTimeout, Constant: s.Constant, Interval: s.Interval, Dynamic: s.Dynamic, Timeout: s.Timeout})
	}
	sort.Slice(a.Sets, func(i, j int) bool { return a.Sets[i].Name < a.Sets[j].Name })
	return a, nil
}
func pointerInt(v any) int64 {
	rv := reflect.ValueOf(v)
	if !rv.IsValid() || rv.IsNil() {
		return -1
	}
	e := rv.Elem()
	if e.Kind() >= reflect.Uint && e.Kind() <= reflect.Uint64 {
		return int64(e.Uint())
	}
	return e.Int()
}
func canonicalExprs(in []expr.Any) ([]byte, error) {
	items := make([]any, 0, len(in))
	for _, e := range in {
		if redir, ok := e.(*expr.Redir); ok {
			// The kernel sets NF_NAT_RANGE_PROTO_SPECIFIED (flags=2) for a
			// single-port redirect on read-back; normalize before registers are
			// zeroed (the decision depends on the original proto register).
			c := *redir
			if c.RegisterProtoMin > 0 {
				c.Flags = 2
			} else {
				c.Flags = 0
			}
			e = &c
		}
		e = zeroRegisters(e)
		items = append(items, struct {
			Type  string
			Value any
		}{fmt.Sprintf("%T", e), e})
	}
	return json.Marshal(items)
}

// zeroRegisters returns a copy of e with register-number fields and set IDs
// zeroed. The kernel reassigns registers (and fills derived fields) when a rule
// is read back from netlink, so comparing absolute register numbers between a
// created rule and its read-back form never matches. The attestation instead
// compares the rule's durable semantics: expression types, payload offsets,
// matched data (address families, protocols, prefixes, ports), and verdicts.
func zeroRegisters(e expr.Any) expr.Any {
	v := reflect.ValueOf(e)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return e
	}
	cp := reflect.New(v.Elem().Type())
	cp.Elem().Set(v.Elem())
	el := cp.Elem()
	for i := 0; i < el.NumField(); i++ {
		f := el.Field(i)
		name := el.Type().Field(i).Name
		if f.CanSet() && f.Kind() >= reflect.Uint && f.Kind() <= reflect.Uint64 && isRegisterField(name) {
			f.SetUint(0)
		}
	}
	return cp.Interface().(expr.Any)
}

func isRegisterField(name string) bool {
	return strings.HasSuffix(name, "Register") || name == "RegisterProtoMin" || name == "RegisterProtoMax" || name == "SetID"
}

type recordNFT struct {
	tables []*nftables.Table
	chains []*nftables.Chain
	sets   []*nftables.Set
	rules  []*nftables.Rule
}

func (r *recordNFT) AddTable(t *nftables.Table) *nftables.Table {
	r.tables = append(r.tables, t)
	return t
}
func (r *recordNFT) AddChain(c *nftables.Chain) *nftables.Chain {
	r.chains = append(r.chains, c)
	return c
}
func (r *recordNFT) AddSet(s *nftables.Set, _ []nftables.SetElement) error {
	r.sets = append(r.sets, s)
	return nil
}
func (r *recordNFT) AddRule(rule *nftables.Rule) *nftables.Rule {
	r.rules = append(r.rules, rule)
	return rule
}
func (*recordNFT) Flush() error                                              { return nil }
func (*recordNFT) SetAddElements(*nftables.Set, []nftables.SetElement) error { return nil }
