package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInstallIsAdminCommand(t *testing.T) {
	require.True(t, isAdmin("install"))
}

func TestInstallWiresShimsCompletionsAndRc(t *testing.T) {
	systemEnvironment(t)
	home := os.Getenv("HOME")
	dataHome := os.Getenv("XDG_DATA_HOME")
	binDir := filepath.Join(home, ".local", "bin")

	runner := systemRunner{}
	var out bytes.Buffer
	streams := Streams{Stdout: &out, Stderr: &out}
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--shell", "bash"}, streams))

	for _, tool := range []string{"node", "npm", "npx", "pip", "cargo", "go"} {
		_, err := os.Lstat(filepath.Join(binDir, tool))
		require.NoError(t, err, tool)
	}
	_, err := os.Stat(filepath.Join(dataHome, "dproxy", "completions", "dproxy.bash"))
	require.NoError(t, err)
	_, err = os.Stat(filepath.Join(dataHome, "dproxy", "completions", "_dproxy"))
	require.NoError(t, err)

	rc, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	require.NoError(t, err)
	require.Contains(t, string(rc), dproxyBlockBegin)
	require.Contains(t, string(rc), dproxyBlockEnd)
	require.Contains(t, string(rc), ".local/bin")

	// Idempotent: a second run replaces rather than duplicates the block.
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--shell", "bash"}, streams))
	rc2, err := os.ReadFile(filepath.Join(home, ".bashrc"))
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(rc2), dproxyBlockBegin))
}

func TestInstallRcBlockReplacementPreservesOtherContent(t *testing.T) {
	systemEnvironment(t)
	home := os.Getenv("HOME")
	rcPath := filepath.Join(home, ".bashrc")
	require.NoError(t, os.WriteFile(rcPath, []byte("# my config\nexport EDITOR=vim\n"), 0600))

	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--shell", "bash"}, streams))
	merged, err := os.ReadFile(rcPath)
	require.NoError(t, err)
	require.Contains(t, string(merged), "export EDITOR=vim")
	require.Equal(t, 1, strings.Count(string(merged), dproxyBlockBegin))
}

func TestInstallShellSelectionErrors(t *testing.T) {
	systemEnvironment(t)
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.Error(t, runner.Command(context.Background(), "install", []string{"--shell", "csh"}, streams))
	require.Error(t, runner.Command(context.Background(), "install", []string{"bogus"}, streams))
}

func TestInstallDetectsShellFromEnv(t *testing.T) {
	t.Setenv("SHELL", "/bin/zsh")
	shells, err := targetShells(nil)
	require.NoError(t, err)
	require.Equal(t, []string{"zsh"}, shells)
	t.Setenv("SHELL", "/usr/local/bin/fish")
	require.Equal(t, []string{"fish"}, mustTargetShells(t, nil))
	t.Setenv("SHELL", "/bin/csh")
	_, err = targetShells(nil)
	require.Error(t, err)
}

func TestReplaceRcBlockAppendsNewlineToContentWithoutOne(t *testing.T) {
	rcPath := filepath.Join(t.TempDir(), ".bashrc")
	require.NoError(t, os.WriteFile(rcPath, []byte("# no trailing newline"), 0600))
	require.NoError(t, replaceRcBlock(rcPath, rcBlock("$HOME/.local/bin", `"$X/dproxy.bash"`)))
	data, err := os.ReadFile(rcPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "# no trailing newline\n")
	require.Equal(t, 1, strings.Count(string(data), dproxyBlockBegin))
}

func mustTargetShells(t *testing.T, args []string) []string {
	t.Helper()
	shells, err := targetShells(args)
	require.NoError(t, err)
	return shells
}

func TestInstallAllWiresBashZshAndFishCompletion(t *testing.T) {
	systemEnvironment(t)
	home := os.Getenv("HOME")
	dataHome := os.Getenv("XDG_DATA_HOME")
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--all"}, streams))

	for _, rc := range []string{".bashrc", ".zshrc"} {
		raw, err := os.ReadFile(filepath.Join(home, rc))
		require.NoError(t, err, rc)
		require.Contains(t, string(raw), dproxyBlockBegin)
	}
	_, err := os.Stat(filepath.Join(home, ".config", "fish", "completions", "dproxy.fish"))
	require.ErrorIs(t, err, os.ErrNotExist) // fish completion lives under XDG_DATA_HOME, not auto-dropped into ~/.config
	_, err = os.Stat(filepath.Join(dataHome, "dproxy", "completions", "dproxy.fish"))
	require.NoError(t, err)
}

func TestInstallRcBlockStripsPriorBlocks(t *testing.T) {
	systemEnvironment(t)
	home := os.Getenv("HOME")
	rcPath := filepath.Join(home, ".bashrc")
	// Pre-existing content including a stale dproxy block.
	require.NoError(t, os.WriteFile(rcPath, []byte("export EDITOR=vim\n"+dproxyBlockBegin+"\nOLD PATH JUNK\n"+dproxyBlockEnd+"\n"), 0600))
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--shell", "bash"}, streams))
	merged, err := os.ReadFile(rcPath)
	require.NoError(t, err)
	require.NotContains(t, string(merged), "OLD PATH JUNK")
	require.Equal(t, 1, strings.Count(string(merged), dproxyBlockBegin))
}
