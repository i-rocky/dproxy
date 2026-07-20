package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/i-rocky/dproxy/internal/plugin"
	"github.com/i-rocky/dproxy/internal/shim"
	"github.com/stretchr/testify/require"
)

func TestInstallIsAdminCommand(t *testing.T) {
	require.True(t, isAdmin("install"))
}

func TestInstallWiresShimsCompletionsAndRc(t *testing.T) {
	systemEnvironment(t)
	oldLoad := officialLoad
	t.Cleanup(func() { officialLoad = oldLoad })
	officialLoad = func() (map[string]plugin.Manifest, error) { return map[string]plugin.Manifest{"node": {}}, nil }
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

// TestInstallSkipsShimsWhenPluginsDoNotLoad locks the "shim only for loadable
// plugins" rule: when the bundled plugins cannot load (e.g. a build with no
// derivable provenance), install wires the shell but creates no tool shims, so
// it never installs a shim that would route to "plugin not found".
func TestInstallSkipsShimsWhenPluginsDoNotLoad(t *testing.T) {
	systemEnvironment(t)
	oldLoad := officialLoad
	t.Cleanup(func() { officialLoad = oldLoad })
	officialLoad = func() (map[string]plugin.Manifest, error) { return nil, errors.New("no provenance") }
	home := os.Getenv("HOME")
	binDir := filepath.Join(home, ".local", "bin")
	var out bytes.Buffer
	require.NoError(t, (systemRunner{}).Command(context.Background(), "install", []string{"--shell", "bash"}, Streams{Stdout: &out, Stderr: &out}))
	require.Contains(t, out.String(), "no loadable official plugins")
	for _, tool := range []string{"node", "npm", "python"} {
		_, err := os.Lstat(filepath.Join(binDir, tool))
		require.ErrorIs(t, err, os.ErrNotExist, tool)
	}
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

// TestManageableTargetsSkipsExistingCommands verifies install never overrides a
// command that already resolves on PATH (an nvm node, a system go, an unmanaged
// ~/.local/bin file), while still installing absent tools and re-syncing its own
// existing shims.
func TestManageableTargetsSkipsExistingCommands(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	shimDir := filepath.Join(root, "shims")
	require.NoError(t, os.MkdirAll(binDir, 0700))
	require.NoError(t, os.MkdirAll(shimDir, 0700))
	// The dproxy generic shim must exist so EvalSymlinks resolves managed links.
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "dproxy-shim"), []byte("#!/bin/sh\n"), 0700))
	// "node" already managed by dproxy (symlink to the generic shim) -> keep/re-sync.
	managedNode := filepath.Join(binDir, "node")
	require.NoError(t, os.Symlink(filepath.Join(shimDir, "dproxy-shim"), managedNode))

	// pathLookup: node -> managed shim; go -> system binary (unmanaged); rustc -> absent.
	prev := pathLookup
	t.Cleanup(func() { pathLookup = prev })
	pathLookup = func(name string) (string, error) {
		switch name {
		case "node":
			return managedNode, nil
		case "go":
			return "/usr/local/go/bin/go", nil
		default:
			return "", exec.ErrNotFound
		}
	}

	m := shim.Manager{BinDir: binDir, ShimDir: shimDir}
	targets := map[string]shim.Target{"node": {Binary: "node"}, "go": {Binary: "go"}, "rustc": {Binary: "rustc"}}
	keep, skipped := manageableTargets(m, targets)

	require.Contains(t, keep, "node", "already-managed shim is re-synced")
	require.Contains(t, keep, "rustc", "absent tool is installed")
	require.NotContains(t, keep, "go", "existing system command is not overridden")
	require.Equal(t, []string{"go"}, skipped)
}

// TestManageableTargetsSkipsUnmanagedFileInBinDir: an unmanaged file already in
// the target bin dir (e.g. a real ~/.local/bin/uv) is skipped, not overwritten.
func TestManageableTargetsSkipsUnmanagedFileInBinDir(t *testing.T) {
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	shimDir := filepath.Join(root, "shims")
	require.NoError(t, os.MkdirAll(binDir, 0700))
	require.NoError(t, os.MkdirAll(shimDir, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(shimDir, "dproxy-shim"), []byte("#!/bin/sh\n"), 0700))
	uvPath := filepath.Join(binDir, "uv")
	require.NoError(t, os.WriteFile(uvPath, []byte("real uv"), 0700))

	prev := pathLookup
	t.Cleanup(func() { pathLookup = prev })
	pathLookup = func(name string) (string, error) {
		if name == "uv" {
			return uvPath, nil
		}
		return "", exec.ErrNotFound
	}

	m := shim.Manager{BinDir: binDir, ShimDir: shimDir}
	keep, skipped := manageableTargets(m, map[string]shim.Target{"uv": {Binary: "uv"}})
	require.Empty(t, keep)
	require.Equal(t, []string{"uv"}, skipped)
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

// TestInstallZshCompletionUsesFpathNotSource locks in the fix for the
// "_tags can only be called from completion function" errors: zsh completions
// must be registered on fpath and autoloaded by compinit, never sourced.
func TestInstallZshCompletionUsesFpathNotSource(t *testing.T) {
	systemEnvironment(t)
	home := os.Getenv("HOME")
	runner := systemRunner{}
	streams := Streams{Stdout: new(bytes.Buffer), Stderr: new(bytes.Buffer)}
	require.NoError(t, runner.Command(context.Background(), "install", []string{"--shell", "zsh"}, streams))
	rc, err := os.ReadFile(filepath.Join(home, ".zshrc"))
	require.NoError(t, err)
	body := string(rc)
	require.Contains(t, body, "fpath=(")
	require.Contains(t, body, "compinit")
	require.NotContains(t, body, "source", "sourcing a #compdef file runs it outside completion")
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
