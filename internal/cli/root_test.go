package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/i-rocky/dproxy/internal/policy"
	commandruntime "github.com/i-rocky/dproxy/internal/runtime"
	"github.com/i-rocky/dproxy/internal/shim"
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

func TestKnownPostStartWarningReturnsExactCommandStatus(t *testing.T) {
	f := &fakeRunner{runCode: 37, runErr: &commandruntime.PostStartError{Status: 37, StatusKnown: true, Err: errors.New("cleanup failed")}}
	var stderr bytes.Buffer
	code := ExecuteWithDeps(context.Background(), "dproxy", []string{"npm"}, Dependencies{Runner: f, Stderr: &stderr})
	require.Equal(t, 37, code)
	require.Contains(t, stderr.String(), "warning")
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

func TestHelpRequestPrintsUsageToStdout(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		var out, errOut bytes.Buffer
		code := Execute(context.Background(), "dproxy", []string{arg}, &out, &errOut)
		require.Equal(t, 0, code, arg)
		require.Empty(t, errOut.String(), arg)
		require.Contains(t, out.String(), "Usage: dproxy")
		require.Contains(t, out.String(), "Commands:")
	}
}

func TestCommandErrorUsesStderrAndStatusTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), "dproxy", []string{"not-a-command"}, &out, &errOut)
	require.Equal(t, 2, code)
	require.Empty(t, out.String())
	// An unrecognized tool name outside any project fails fast at provider
	// resolution (the global path no longer treats "no project" as an error).
	require.Contains(t, errOut.String(), "not-a-command")
}

func TestUnsupportedOSFailsClosed(t *testing.T) {
	require.NoError(t, assertSupportedRuntime("linux"))
	require.Error(t, assertSupportedRuntime("darwin"))
	old := currentOS
	currentOS = "darwin"
	t.Cleanup(func() { currentOS = old })
	var out, errOut bytes.Buffer
	code := ExecuteWithDeps(context.Background(), "dproxy", []string{"version"}, Dependencies{Runner: &fakeRunner{}, Stdout: &out, Stderr: &errOut})
	require.Equal(t, 2, code)
	require.Empty(t, out.String())
	require.Contains(t, errOut.String(), "linux")
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

func TestRealBinaryTargetDecision(t *testing.T) {
	dir := t.TempDir()
	shimPath := filepath.Join(dir, genericShimName)
	require.NoError(t, os.WriteFile(shimPath, []byte("stale-shim"), 0700))
	execPath := filepath.Join(dir, "real-dproxy")
	require.NoError(t, os.WriteFile(execPath, []byte("fresh"), 0700))
	record := filepath.Join(dir, shim.TargetRecordName)

	// No record → no re-exec.
	t.Run("missing record", func(t *testing.T) {
		_, ok := realBinaryTarget(shimPath)
		require.False(t, ok)
	})

	// Record points to a distinct executable → re-exec target.
	t.Run("distinct executable", func(t *testing.T) {
		require.NoError(t, os.WriteFile(record, []byte(execPath), 0600))
		got, ok := realBinaryTarget(shimPath)
		require.True(t, ok)
		require.Equal(t, execPath, got)
	})

	// Record points back at the shim itself → no re-exec (avoids a loop).
	t.Run("self reference", func(t *testing.T) {
		require.NoError(t, os.WriteFile(record, []byte(shimPath), 0600))
		_, ok := realBinaryTarget(shimPath)
		require.False(t, ok)
	})

	// Record points at a non-existent path → no re-exec (falls through).
	t.Run("missing target", func(t *testing.T) {
		require.NoError(t, os.WriteFile(record, []byte(filepath.Join(dir, "nope")), 0600))
		_, ok := realBinaryTarget(shimPath)
		require.False(t, ok)
	})

	// Record points at a directory → no re-exec.
	t.Run("directory target", func(t *testing.T) {
		require.NoError(t, os.WriteFile(record, []byte(t.TempDir()), 0600))
		_, ok := realBinaryTarget(shimPath)
		require.False(t, ok)
	})

	// Record points at a symlink back to the shim → no re-exec (loop guard must
	// compare resolved inodes, not path strings).
	t.Run("symlink loop back to shim", func(t *testing.T) {
		loop := filepath.Join(dir, "dproxy-loop")
		require.NoError(t, os.Symlink(shimPath, loop))
		require.NoError(t, os.WriteFile(record, []byte(loop), 0600))
		_, ok := realBinaryTarget(shimPath)
		require.False(t, ok, "a record resolving back to the shim must not re-exec")
	})
}

func TestMaybeReexecFallsThroughWhenNotShim(t *testing.T) {
	// The test binary's basename is not the generic shim, so the preflight must
	// return immediately without touching the filesystem or exec'ing.
	require.NotPanics(t, func() { maybeReexecToRealBinary() })
}

func TestMaybeReexecReadsRecordWhenInvokedAsShim(t *testing.T) {
	dir := t.TempDir()
	shimPath := filepath.Join(dir, genericShimName)
	require.NoError(t, os.WriteFile(shimPath, []byte("stale"), 0700))
	old := currentExecutable
	t.Cleanup(func() { currentExecutable = old })

	// Lookup error → fall through.
	currentExecutable = func() (string, error) { return "", errors.New("lookup failed") }
	require.NotPanics(t, func() { maybeReexecToRealBinary() })

	// Invoked as the shim but no record present → realBinaryTarget false → fall
	// through (never reaching syscall.Exec, which would replace this process).
	currentExecutable = func() (string, error) { return shimPath, nil }
	require.NotPanics(t, func() { maybeReexecToRealBinary() })
}
