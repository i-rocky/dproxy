package cli

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"dproxy/internal/policy"
	"github.com/stretchr/testify/require"
)

type fakeRunner struct {
	resolvedBinary string
	resolvedArgs   []string
	plan           policy.Plan
	runCode        int
	runErr         error
	mutations      int
}

func (f *fakeRunner) Resolve(_ context.Context, binary string, args []string) (policy.Plan, error) {
	f.resolvedBinary, f.resolvedArgs = binary, append([]string(nil), args...)
	f.plan.Command = append([]string{binary}, args...)
	return f.plan, nil
}
func (f *fakeRunner) Run(context.Context, policy.Plan, Streams) (int, error) {
	f.mutations++
	return f.runCode, f.runErr
}
func (f *fakeRunner) Command(context.Context, string, []string, Streams) error {
	f.mutations++
	return nil
}

func TestShimDispatchesBinary(t *testing.T) {
	f := &fakeRunner{}
	code := ExecuteWithDeps(context.Background(), "/managed/npm", []string{"install"}, Dependencies{Runner: f})
	require.Equal(t, 0, code)
	require.Equal(t, "npm", f.resolvedBinary)
	require.Equal(t, []string{"install"}, f.resolvedArgs)
	require.Equal(t, []string{"npm", "install"}, f.plan.Command)
}

func TestDirectAndShimDispatchUseSameResolutionPath(t *testing.T) {
	for _, tc := range []struct {
		argv0 string
		args  []string
	}{{"dproxy", []string{"npm", "ci"}}, {"npm", []string{"ci"}}} {
		f := &fakeRunner{}
		require.Equal(t, 0, ExecuteWithDeps(context.Background(), tc.argv0, tc.args, Dependencies{Runner: f}))
		require.Equal(t, "npm", f.resolvedBinary)
		require.Equal(t, []string{"ci"}, f.resolvedArgs)
	}
}

func TestDryRunExplainsWithoutMutation(t *testing.T) {
	f := &fakeRunner{plan: policy.Plan{Image: "repo/image@sha256:" + string(bytes.Repeat([]byte("a"), 64))}}
	var out bytes.Buffer
	code := ExecuteWithDeps(context.Background(), "dproxy", []string{"--dry-run", "npm", "ci"}, Dependencies{Runner: f, Stdout: &out})
	require.Equal(t, 0, code)
	require.Zero(t, f.mutations)
	require.Contains(t, out.String(), "command=npm ci")
}

func TestExitCodeMapping(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner *fakeRunner
		want   int
	}{
		{"command status", &fakeRunner{runCode: 42}, 42},
		{"sandbox creation", &fakeRunner{runErr: ErrSandboxCreation}, 125},
		{"setup error", &fakeRunner{runErr: errors.New("boom")}, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := ExecuteWithDeps(context.Background(), "dproxy", []string{"npm"}, Dependencies{Runner: tc.runner})
			require.Equal(t, tc.want, code)
		})
	}
}

func TestEveryDesignedAdministrativeCommandIsWired(t *testing.T) {
	commands := [][]string{{"init"}, {"lock"}, {"update", "npm"}, {"tool", "add", "npm"}, {"plugin", "list"}, {"setup"}, {"doctor"}, {"cache", "list"}, {"uninstall"}}
	for _, args := range commands {
		f := &fakeRunner{}
		require.Equal(t, 0, ExecuteWithDeps(context.Background(), "dproxy", args, Dependencies{Runner: f}), args)
		require.Equal(t, 1, f.mutations, args)
	}
}

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), "dproxy", []string{"version"}, &out, &errOut)
	require.Equal(t, 0, code)
	require.Equal(t, "dproxy dev\n", out.String())
	require.Empty(t, errOut.String())
}

func TestCommandErrorUsesStderrAndStatusTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), "dproxy", []string{"not-a-command"}, &out, &errOut)
	require.Equal(t, 2, code)
	require.Empty(t, out.String())
	require.Contains(t, errOut.String(), "project")
}

func TestUsageAndPlanningFlagValidation(t *testing.T) {
	for _, args := range [][]string{nil, {"version", "extra"}, {"--dry-run", "version"}, {"--explain", "doctor"}} {
		f := &fakeRunner{}
		var stderr bytes.Buffer
		require.Equal(t, 2, ExecuteWithDeps(context.Background(), "dproxy", args, Dependencies{Runner: f, Stderr: &stderr}), args)
		require.NotEmpty(t, stderr.String())
	}
	var stderr bytes.Buffer
	require.Equal(t, 2, ExecuteWithDeps(context.Background(), "dproxy", []string{"npm"}, Dependencies{Stderr: &stderr}))
	require.Contains(t, stderr.String(), "dependencies")
	require.Equal(t, 2, ExecuteWithDeps(context.Background(), "/", nil, Dependencies{Runner: &fakeRunner{}}))
}
