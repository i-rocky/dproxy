package gateway

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	networkpolicy "github.com/i-rocky/dproxy/internal/network"
	"github.com/stretchr/testify/require"
)

type snapshotQuery struct {
	tables []*nftables.Table
	chains []*nftables.Chain
	sets   []*nftables.Set
	rules  []*nftables.Rule
	err    error
}

func (q *snapshotQuery) ListTables() ([]*nftables.Table, error)           { return q.tables, q.err }
func (q *snapshotQuery) ListChains() ([]*nftables.Chain, error)           { return q.chains, q.err }
func (q *snapshotQuery) GetSets(*nftables.Table) ([]*nftables.Set, error) { return q.sets, q.err }
func (q *snapshotQuery) GetRules(_ *nftables.Table, c *nftables.Chain) ([]*nftables.Rule, error) {
	if q.err != nil {
		return nil, q.err
	}
	var out []*nftables.Rule
	for _, r := range q.rules {
		if r.Chain.Name == c.Name {
			out = append(out, r)
		}
	}
	return out, nil
}
func installedSnapshot(t *testing.T, p networkpolicy.Policy) *snapshotQuery {
	r := &recordNFT{}
	require.NoError(t, (&NFT{Conn: r, Policy: p, DNSPort: 1053}).Install())
	return &snapshotQuery{tables: r.tables, chains: r.chains, sets: r.sets, rules: r.rules}
}
func TestExactNFTAttestationAcceptsOnlyCanonicalPolicyRules(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443", "b.example:80"})
	require.NoError(t, err)
	q := installedSnapshot(t, p)
	require.NoError(t, VerifyNFTAttestation(p, 1053, q))
	q.rules = append(q.rules, q.rules[len(q.rules)-1])
	require.Error(t, VerifyNFTAttestation(p, 1053, q))
}
func TestNFTAttestationRejectsMissingWeakenedAndMalformedState(t *testing.T) {
	p := networkpolicy.Public()
	tests := map[string]func(*snapshotQuery){"missing rule": func(q *snapshotQuery) { q.rules = q.rules[:len(q.rules)-1] }, "wrong family": func(q *snapshotQuery) { q.tables[0].Family = nftables.TableFamilyIPv4 }, "wrong hook": func(q *snapshotQuery) { q.chains[0].Hooknum = nftables.ChainHookInput }, "wrong priority": func(q *snapshotQuery) { q.chains[0].Priority = nftables.ChainPriorityLast }, "wrong policy": func(q *snapshotQuery) { accept := nftables.ChainPolicyAccept; q.chains[0].Policy = &accept }, "wrong set timeout": func(q *snapshotQuery) { q.sets[0].Timeout = time.Second }, "wrong set type": func(q *snapshotQuery) { q.sets[0].KeyType = nftables.TypeIPAddr }, "extra chain": func(q *snapshotQuery) {
		q.chains = append(q.chains, &nftables.Chain{Name: "extra", Table: q.tables[0]})
	}}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			q := installedSnapshot(t, p)
			mutate(q)
			require.Error(t, VerifyNFTAttestation(p, 1053, q))
		})
	}
}
func TestNFTAttestationFailsClosedOnQueryErrorsAndDuplicates(t *testing.T) {
	p := networkpolicy.Public()
	require.Error(t, VerifyNFTAttestation(p, 1053, nil))
	q := installedSnapshot(t, p)
	q.err = errors.New("kernel")
	require.Error(t, VerifyNFTAttestation(p, 1053, q))
	q = installedSnapshot(t, p)
	q.tables = append(q.tables, q.tables[0])
	require.Error(t, VerifyNFTAttestation(p, 1053, q))
}

func TestNFTAttestationCanonicalizesRedirFlagsFromKernelReadback(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443"})
	require.NoError(t, err)
	q := installedSnapshot(t, p)
	// The created NAT redirect rule has Redir with Flags=0; the kernel sets
	// Flags=2 on read-back when RegisterProtoMin>0. canonicalExprs must treat the
	// two as equal — without it this snapshot would fail to attest.
	for _, r := range q.rules {
		for _, e := range r.Exprs {
			if redir, ok := e.(*expr.Redir); ok && redir.RegisterProtoMin > 0 {
				redir.Flags = 2
			}
		}
	}
	require.NoError(t, VerifyNFTAttestation(p, 1053, q), "kernel-read Flags=2 must attest equal to created Flags=0")
}

// Rule order within a chain is semantically meaningful in nftables, so the
// attestation must detect a reorder rather than treating rules as a set.
func TestNFTAttestationDetectsRuleReorderWithinChain(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443", "b.example:80"})
	require.NoError(t, err)
	q := installedSnapshot(t, p)
	i, j, ok := distinctRulePair(q.rules)
	require.True(t, ok, "fixture has no chain with two distinguishable rules")
	q.rules[i], q.rules[j] = q.rules[j], q.rules[i]
	require.Error(t, VerifyNFTAttestation(p, 1053, q), "reordered rules within a chain must be detected as a mismatch")
}

// The kernel reassigns registers and set IDs when a rule is read back over
// netlink. zeroRegisters normalizes those fields so a created rule and its
// read-back form attest equal; drift in any of them must not cause a mismatch.
func TestNFTAttestationNormalizesKernelRegisterAndSetIDDrift(t *testing.T) {
	p, err := networkpolicy.Allowlist([]string{"a.example:443", "b.example:80"})
	require.NoError(t, err)
	q := installedSnapshot(t, p)
	n := mutateKernelAssignedFields(q.rules)
	require.NotZero(t, n, "fixture exposes no register/SetID fields to normalize")
	require.NoError(t, VerifyNFTAttestation(p, 1053, q), "kernel-reassigned registers/SetIDs must attest equal to the created ruleset")
}

func distinctRulePair(rules []*nftables.Rule) (int, int, bool) {
	byChain := make(map[string][]int)
	for i, r := range rules {
		if r.Chain == nil {
			continue
		}
		byChain[r.Chain.Name] = append(byChain[r.Chain.Name], i)
	}
	for _, idxs := range byChain {
		if len(idxs) < 2 {
			continue
		}
		canon := make([][]byte, len(idxs))
		for k, idx := range idxs {
			canon[k], _ = canonicalExprs(rules[idx].Exprs)
		}
		for a := 0; a < len(idxs); a++ {
			for b := a + 1; b < len(idxs); b++ {
				if !bytes.Equal(canon[a], canon[b]) {
					return idxs[a], idxs[b], true
				}
			}
		}
	}
	return 0, 0, false
}

// mutateKernelAssignedFields bumps every register-number / SetID field on the
// snapshot's rule expressions, simulating the kernel reassigning them on
// read-back. It returns the count of fields mutated so the test can confirm it
// exercised real fields.
func mutateKernelAssignedFields(rules []*nftables.Rule) int {
	var n int
	for r := range rules {
		for k := range rules[r].Exprs {
			mutateExprRegisterFields(&rules[r].Exprs[k], &n)
		}
	}
	return n
}

func mutateExprRegisterFields(e *expr.Any, n *int) {
	v := reflect.ValueOf(*e)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return
	}
	el := v.Elem()
	for i := 0; i < el.NumField(); i++ {
		f := el.Field(i)
		name := el.Type().Field(i).Name
		if !f.CanSet() || f.Kind() < reflect.Uint || f.Kind() > reflect.Uint64 || !isRegisterField(name) {
			continue
		}
		if cur := f.Uint(); cur == 0 {
			f.SetUint(7)
		} else {
			f.SetUint(cur + 7)
		}
		*n++
	}
}
