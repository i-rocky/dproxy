package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/i-rocky/dproxy/internal/shim"
	"github.com/i-rocky/dproxy/plugins/official"
)

const (
	dproxyBlockBegin = "# >>> dproxy begin >>>"
	dproxyBlockEnd   = "# <<< dproxy end <<<"
)

// installCommand wires the user's shell so managed tools dispatch transparently:
// it installs shims for every official tool, drops shell completion scripts, and
// writes idempotent PATH+completion blocks into the detected shell rc files. It
// requires no project and no lock.
func installCommand(args []string, streams Streams) error {
	shells, err := targetShells(args)
	if err != nil {
		return err
	}
	_, _, dataRoot, err := userRoots()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataRoot, 0700); err != nil {
		return err
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(home, ".local"), 0700); err != nil {
		return err
	}
	binDir := filepath.Join(home, ".local", "bin")
	shimDir := filepath.Join(dataRoot, "shims")

	targets, err := officialTargets()
	if err != nil {
		return err
	}
	manager := shim.Manager{BinDir: binDir, ShimDir: shimDir, Executable: executable}
	keep, skipped := manageableTargets(manager, targets)
	if err := manager.Sync(keep); err != nil {
		return err
	}
	completionsDir := filepath.Join(dataRoot, "completions")
	if err := writeCompletionFiles(completionsDir); err != nil {
		return err
	}
	wired, err := wireShells(home, binDir, completionsDir, shells)
	if err != nil {
		return err
	}
	fmt.Fprintf(streams.Stdout, "installed %d managed tool shims\n", len(keep))
	if len(skipped) > 0 {
		fmt.Fprintf(streams.Stdout, "skipped %d tools already on PATH (not overridden): %s\n", len(skipped), strings.Join(skipped, ", "))
	}
	if len(wired) > 0 {
		fmt.Fprintf(streams.Stdout, "wired shell rc: %s\n", strings.Join(wired, ", "))
		fmt.Fprintln(streams.Stdout, "restart your shell or open a new terminal for PATH and completion to take effect")
	}
	return nil
}

// pathLookup resolves a command name on PATH. It is a variable so tests can
// inject resolution without mutating the process environment.
var pathLookup = exec.LookPath

// manageableTargets filters the official tool set to those dproxy should manage.
// A tool is skipped when a command of the same name already resolves on PATH to
// anything other than a dproxy-managed shim — whether an unmanaged file in the
// target bin dir or a system/nvm/cargo install elsewhere — so dproxy never
// overrides an existing command. A name already pointing at a dproxy shim is
// kept (re-synced); a name not on PATH at all is installed.
func manageableTargets(m shim.Manager, targets map[string]shim.Target) (map[string]shim.Target, []string) {
	keep := make(map[string]shim.Target, len(targets))
	var skipped []string
	for name, target := range targets {
		resolved, err := pathLookup(name)
		if err == nil && !m.IsManagedShim(resolved) {
			skipped = append(skipped, name)
			continue
		}
		keep[name] = target
	}
	sort.Strings(skipped)
	return keep, skipped
}

// targetShells resolves which shell rc files to wire from --shell/--all flags or
// $SHELL. Unknown shell names are rejected.
func targetShells(args []string) ([]string, error) {
	if len(args) == 0 {
		if shell := shellFromEnv(os.Getenv("SHELL")); shell != "" {
			return []string{shell}, nil
		}
		return nil, errors.New("could not detect shell from $SHELL; pass --shell <bash|zsh|fish> or --all")
	}
	if len(args) == 2 && args[0] == "--shell" {
		if !knownShell(args[1]) {
			return nil, fmt.Errorf("unsupported shell %q (use bash, zsh, or fish)", args[1])
		}
		return []string{args[1]}, nil
	}
	if len(args) == 1 && args[0] == "--all" {
		return []string{"bash", "zsh", "fish"}, nil
	}
	return nil, errors.New("usage: dproxy install [--shell <bash|zsh|fish>|--all]")
}

func shellFromEnv(shell string) string {
	base := filepath.Base(shell)
	if knownShell(base) {
		return base
	}
	return ""
}

func knownShell(name string) bool {
	switch name {
	case "bash", "zsh", "fish":
		return true
	default:
		return false
	}
}

// officialTargets builds shim targets for every binary provided by the bundled
// official manifests. It does not require release provenance: shims only point
// at the dproxy binary; provenance is enforced when a tool is actually resolved.
func officialTargets() (map[string]shim.Target, error) {
	bins, err := official.Binaries()
	if err != nil {
		return nil, fmt.Errorf("enumerate official tools: %w", err)
	}
	targets := make(map[string]shim.Target, len(bins))
	for _, binary := range bins {
		targets[binary] = shim.Target{Binary: binary}
	}
	return targets, nil
}

func writeCompletionFiles(dir string) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create completions directory: %w", err)
	}
	scripts := map[string]string{
		"dproxy.bash": bashCompletion,
		"_dproxy":     zshCompletion,
		"dproxy.fish": fishCompletion,
	}
	for name, body := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); err != nil {
			return fmt.Errorf("write completion %q: %w", name, err)
		}
	}
	return nil
}

// wireShells writes the idempotent PATH+completion block into each requested
// shell's rc file and returns the shells actually wired.
func wireShells(home, binDir, completionsDir string, shells []string) ([]string, error) {
	var wired []string
	for _, shell := range shells {
		var rcPath, block string
		switch shell {
		case "bash":
			rcPath = filepath.Join(home, ".bashrc")
			block = rcBlock(binDir, bashCompletionSetup())
		case "zsh":
			rcPath = filepath.Join(home, ".zshrc")
			block = rcBlock(binDir, zshCompletionSetup())
		case "fish":
			// fish auto-loads completions from its config dir; no rc edit needed.
			continue
		default:
			return nil, fmt.Errorf("unsupported shell %q", shell)
		}
		if err := replaceRcBlock(rcPath, block); err != nil {
			return nil, fmt.Errorf("wire %s: %w", shell, err)
		}
		wired = append(wired, shell)
	}
	return wired, nil
}

// completionsDirExpr is the shell-time location of the completion scripts,
// resolved via XDG_DATA_HOME so it tracks the user's configuration.
const completionsDirExpr = `"${XDG_DATA_HOME:-$HOME/.local/share}/dproxy/completions"`

func bashCompletionSetup() string {
	return fmt.Sprintf("[ -f %s/dproxy.bash ] && source %s/dproxy.bash", completionsDirExpr, completionsDirExpr)
}

// zshCompletionSetup wires the _dproxy completion via fpath + compinit. zsh
// completions must NOT be sourced: a #compdef file runs its body when invoked,
// so sourcing it at shell startup calls _tags/_describe outside any completion
// context and errors with "_tags can only be called from completion function".
// Putting the directory on fpath and running compinit registers _dproxy whether
// the user's own compinit ran before or after this block.
func zshCompletionSetup() string {
	return fmt.Sprintf("fpath=(%s $fpath)\nautoload -Uz compinit && compinit", completionsDirExpr)
}

// rcBlock renders the idempotent marker-delimited block: prepends ~/.local/bin
// to PATH only when absent, then runs the shell-specific completion setup.
func rcBlock(binDir, completionSetup string) string {
	return strings.Join([]string{
		dproxyBlockBegin,
		`case ":$PATH:" in *":$HOME/.local/bin:"*) ;; *) export PATH="$HOME/.local/bin:$PATH";; esac`,
		completionSetup,
		dproxyBlockEnd,
	}, "\n") + "\n"
}

// replaceRcBlock atomically rewrites rcPath with any prior dproxy block replaced
// by block. If the file does not exist it is created.
func replaceRcBlock(rcPath, block string) error {
	existing, readErr := os.ReadFile(rcPath)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	content := stripBlock(string(existing))
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += block
	perm := os.FileMode(0600)
	if info, statErr := os.Stat(rcPath); statErr == nil {
		perm = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(rcPath), ".dproxy-rc-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, rcPath)
}

// stripBlock removes a prior dproxy block (inclusive of markers) from content.
func stripBlock(content string) string {
	for {
		begin := strings.Index(content, dproxyBlockBegin)
		if begin < 0 {
			return content
		}
		end := strings.Index(content[begin:], dproxyBlockEnd)
		if end < 0 {
			return content
		}
		cut := begin + end + len(dproxyBlockEnd)
		if cut < len(content) && content[cut] == '\n' {
			cut++
		}
		content = content[:begin] + content[cut:]
	}
}

const (
	bashCompletion = `# dproxy shell completion (managed by dproxy install)
_dproxy_completions() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local cmds="init lock update tool plugin setup install doctor cache uninstall version --explain --dry-run"
    COMPREPLY=( $(compgen -W "$cmds" -- "$cur") )
}
complete -F _dproxy_completions dproxy
`
	zshCompletion = `#compdef dproxy
# dproxy shell completion (managed by dproxy install)
_dproxy() {
    local -a cmds
    cmds=(init lock update tool plugin setup install doctor cache uninstall version)
    _describe 'dproxy command' cmds
}
_dproxy "$@"
`
	fishCompletion = `# dproxy shell completion (managed by dproxy install)
complete -c dproxy -f -a "init lock update tool plugin setup install doctor cache uninstall version"
complete -c dproxy -f -n "test (count (commandline -opc)) -gt 1" -a "(__fish_use_subcommand)"
fish_add_path ~/.local/bin 2>/dev/null
`
)
