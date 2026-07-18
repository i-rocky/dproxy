package gateway

import (
	"context"
	"crypto/sha256"
	networkpolicy "dproxy/internal/network"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type fakeControls struct {
	calls []string
	fail  string
}

func writePublicPolicy(t *testing.T, path string) {
	t.Helper()
	b, err := json.Marshal(networkpolicy.Public())
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, b, 0400))
}

func TestServePublishesAuthenticatedReadinessOnlyAfterControls(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	ready := filepath.Join(dir, "ready")
	writePublicPolicy(t, policyPath)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeWithToken(ctx, policyPath, ready, "token", &fakeControls{}) }()
	require.Eventually(t, func() bool { return Health(ready, "token", "token") == nil }, time.Second, time.Millisecond)
	require.Error(t, Health(ready, "token", "wrong"))
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
}

func TestServeDoesNotPublishReadinessOnSetupFailure(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	ready := filepath.Join(dir, "ready")
	writePublicPolicy(t, policyPath)
	require.Error(t, ServeWithToken(context.Background(), policyPath, ready, "token", &fakeControls{fail: "udp"}))
	_, err := os.Stat(ready)
	require.ErrorIs(t, err, os.ErrNotExist)
}
func TestServeAndHealthRejectEmptyOrMismatchedTokens(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	ready := filepath.Join(dir, "ready")
	writePublicPolicy(t, policy)
	require.ErrorContains(t, ServeWithToken(context.Background(), policy, ready, "", &fakeControls{}), "nonempty")
	empty := sha256.Sum256(nil)
	record, _ := json.Marshal(readiness{Controls: readyState, TokenHash: hex.EncodeToString(empty[:])})
	require.NoError(t, os.WriteFile(ready, record, 0400))
	require.Error(t, Health(ready, "token", "token"))
	require.Error(t, Health(ready, "", ""))
}
func TestHealthRejectsWritableReadinessState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	h := sha256.Sum256([]byte("token"))
	record, _ := json.Marshal(readiness{Controls: readyState, TokenHash: hex.EncodeToString(h[:])})
	require.NoError(t, os.WriteFile(path, record, 0600))
	require.ErrorContains(t, Health(path, "token", "token"), "mode")
}

type fakeInspector struct {
	fail  string
	calls []string
}

func (f *fakeInspector) Forwarding(s string) error {
	f.calls = append(f.calls, s)
	if f.fail == s {
		return errors.New("bad")
	}
	return nil
}
func (f *fakeInspector) DNS(n, _ string) error {
	f.calls = append(f.calls, n)
	if f.fail == n {
		return errors.New("bad")
	}
	return nil
}
func (f *fakeInspector) NFT(networkpolicy.Policy) error {
	f.calls = append(f.calls, "nft")
	if f.fail == "nft" {
		return errors.New("bad")
	}
	return nil
}
func TestSystemHealthRequiresEveryIndependentControl(t *testing.T) {
	for _, fail := range []string{"ipv4", "ipv6", "tcp", "udp", "nft"} {
		f := &fakeInspector{fail: fail}
		require.Error(t, VerifySystemHealth(f, "dns"), fail)
	}
	f := &fakeInspector{}
	require.NoError(t, VerifySystemHealth(f, "dns"))
	require.Equal(t, []string{"ipv4", "ipv6", "tcp", "udp", "nft"}, f.calls)
	require.Error(t, VerifySystemHealth(nil, "dns"))
}
func TestRealHealthAdaptersFailClosedWithoutControls(t *testing.T) {
	i := realHealthInspector{}
	_ = i.Forwarding("ipv4")
	_ = i.Forwarding("ipv6")
	require.Error(t, i.DNS("tcp", "127.0.0.1:1"))
	require.Error(t, i.DNS("udp", "127.0.0.1:1"))
	require.Error(t, i.NFT(networkpolicy.Public()))
}
func TestSystemHealthChecksPolicyHashBeforeKernel(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "policy")
	ready := filepath.Join(dir, "ready")
	writePublicPolicy(t, policy)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- ServeWithToken(ctx, policy, ready, "token", &fakeControls{}) }()
	require.Eventually(t, func() bool { _, e := os.Stat(ready); return e == nil }, time.Second, time.Millisecond)
	require.NoError(t, os.Chmod(policy, 0600))
	changed := networkpolicy.Public()
	changed.DeniedPrefixes = append(changed.DeniedPrefixes, "203.0.113.0/25")
	changedBytes, marshalErr := json.Marshal(changed)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(policy, changedBytes, 0600))
	require.NoError(t, os.Chmod(policy, 0400))
	require.ErrorContains(t, SystemHealth(ready, policy, "token", "token", "127.0.0.1:1"), "hash")
	cancel()
	<-done
}

func (f *fakeControls) InstallDNS(context.Context) error {
	f.calls = append(f.calls, "dns")
	if f.fail == "dns" {
		return errors.New("bad")
	}
	return nil
}
func (f *fakeControls) InstallTCP(context.Context) error {
	f.calls = append(f.calls, "tcp")
	if f.fail == "tcp" {
		return errors.New("bad")
	}
	return nil
}
func (f *fakeControls) InstallUDP(context.Context) error {
	f.calls = append(f.calls, "udp")
	if f.fail == "udp" {
		return errors.New("bad")
	}
	return nil
}
func (f *fakeControls) InstallFirewall(context.Context) error {
	f.calls = append(f.calls, "firewall")
	if f.fail == "firewall" {
		return errors.New("bad")
	}
	return nil
}

func TestSetupFailsUnlessEveryTransparentControlIsInstalled(t *testing.T) {
	for _, control := range []string{"dns", "tcp", "udp", "firewall"} {
		f := &fakeControls{fail: control}
		err := InstallControls(context.Background(), f)
		require.Error(t, err, control)
	}
	f := &fakeControls{}
	require.NoError(t, InstallControls(context.Background(), f))
	require.Equal(t, []string{"dns", "tcp", "udp", "firewall"}, f.calls)
}

func TestLoadPolicyRequiresReadOnlyRegularJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writePublicPolicy(t, path)
	p, err := LoadPolicy(path)
	require.NoError(t, err)
	require.Equal(t, "public", p.Mode)
	require.NoError(t, os.Chmod(path, 0600))
	_, err = LoadPolicy(path)
	require.ErrorContains(t, err, "read-only")
	require.NoError(t, os.WriteFile(path, []byte(`{"mode":"public","unknown":true}`), 0600))
	require.NoError(t, os.Chmod(path, 0400))
	_, err = LoadPolicy(path)
	require.Error(t, err)
}
func TestLoadPolicyRejectsEveryIncompleteState(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadPolicy(filepath.Join(dir, "missing"))
	require.Error(t, err)
	_, err = LoadPolicy(dir)
	require.Error(t, err)
	for _, body := range []string{`{"mode":"none","denied_prefixes":["127.0.0.0/8"]}`, `{"mode":"allowlist","denied_prefixes":["127.0.0.0/8"]}`, `{"mode":"public"}`, `{"mode":"public","denied_prefixes":["bad"]}`, `{"mode":"public","denied_prefixes":["127.0.0.0/8"]} {}`} {
		path := filepath.Join(dir, "p")
		require.NoError(t, os.WriteFile(path, []byte(body), 0600))
		require.NoError(t, os.Chmod(path, 0400))
		_, err = LoadPolicy(path)
		require.Error(t, err)
		require.NoError(t, os.Chmod(path, 0600))
	}
}
func TestLoadPolicyRejectsSyntacticallyValidWeakenedBaseline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy")
	require.NoError(t, os.WriteFile(path, []byte(`{"mode":"public","denied_prefixes":["127.0.0.0/8"]}`), 0400))
	_, err := LoadPolicy(path)
	require.ErrorContains(t, err, "baseline")
}
