package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/i-rocky/dproxy/internal/diagnostic"
	"github.com/i-rocky/dproxy/internal/policy"
)

// supportedOSes lists the host operating systems dproxy currently runs on.
// Expanding this set requires the per-OS backends described in
// docs/platform-backends.md (gateway dataplane and hardened filesystem
// ownership) to land with passing security tests. It is a variable so tests
// can exercise the unsupported-OS path.
var supportedOSes = map[string]struct{}{"linux": {}}

// currentOS is the host OS used for the startup guard. It is a variable so
// tests can exercise the fail-closed path without changing build settings.
var currentOS = runtime.GOOS

func assertSupportedRuntime(goos string) error {
	if _, ok := supportedOSes[goos]; ok {
		return nil
	}
	return fmt.Errorf("dproxy does not yet run on %q; only linux is supported today (see docs/platform-backends.md)", goos)
}

var ErrSandboxCreation = errors.New("sandbox creation failed")

type Streams struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

type Runner interface {
	Resolve(context.Context, string, []string) (policy.Plan, error)
	Run(context.Context, policy.Plan, Streams) (int, error)
	Command(context.Context, string, []string, Streams) error
}

type readOnlyResolver interface {
	ResolveReadOnly(context.Context, string, []string) (policy.Plan, error)
}

type administrativePlanner interface {
	PlanCommand(context.Context, string, []string) (string, error)
}

type Dependencies struct {
	Runner         Runner
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

func Execute(ctx context.Context, argv0 string, args []string, stdout, stderr io.Writer) int {
	return ExecuteWithDeps(ctx, argv0, args, Dependencies{Runner: newSystemRunner(), Stdin: os.Stdin, Stdout: stdout, Stderr: stderr})
}

func ExecuteWithDeps(ctx context.Context, argv0 string, args []string, deps Dependencies) int {
	streams := normalizeStreams(deps)
	if err := assertSupportedRuntime(currentOS); err != nil {
		fmt.Fprintln(streams.Stderr, "dproxy:", err)
		return 2
	}
	if deps.Runner == nil {
		fmt.Fprintln(streams.Stderr, "dproxy: execution dependencies are unavailable")
		return 2
	}
	name := filepath.Base(argv0)
	if name == "dproxy" || name == "dproxy.exe" {
		return executeDirect(ctx, args, deps.Runner, streams)
	}
	return executeTool(ctx, name, args, false, false, deps.Runner, streams)
}

func executeDirect(ctx context.Context, args []string, runner Runner, streams Streams) int {
	dryRun, explain := false, false
	for len(args) > 0 {
		switch args[0] {
		case "--dry-run":
			dryRun, args = true, args[1:]
		case "--explain":
			explain, args = true, args[1:]
		default:
			goto parsed
		}
	}
parsed:
	if len(args) == 0 {
		fmt.Fprintln(streams.Stderr, "usage: dproxy [--dry-run|--explain] <command|tool> [arguments...]")
		return 2
	}
	if isHelpRequest(args[0]) {
		fmt.Fprint(streams.Stdout, helpText)
		return 0
	}
	if args[0] == "version" {
		if len(args) != 1 || dryRun || explain {
			return usage(streams, "version takes no arguments")
		}
		fmt.Fprintf(streams.Stdout, "dproxy %s\n", buildVersion())
		return 0
	}
	if isAdmin(args[0]) {
		if explain {
			return usage(streams, "planning flags require a tool")
		}
		if dryRun {
			planner, ok := runner.(administrativePlanner)
			if !ok {
				return usage(streams, "administrative dry-run is unavailable")
			}
			planned, err := planner.PlanCommand(ctx, args[0], args[1:])
			if err != nil {
				return reportError(streams, err)
			}
			fmt.Fprintf(streams.Stdout, "dry-run: %s\n", planned)
			return 0
		}
		if err := runner.Command(ctx, args[0], args[1:], streams); err != nil {
			return reportError(streams, err)
		}
		return 0
	}
	return executeTool(ctx, args[0], args[1:], dryRun, explain, runner, streams)
}

func executeTool(ctx context.Context, binary string, args []string, dryRun, explain bool, runner Runner, streams Streams) int {
	if binary == "" || strings.ContainsAny(binary, `/\\`) {
		return usage(streams, "invalid tool name")
	}
	var plan policy.Plan
	var err error
	if dryRun || explain {
		if resolver, ok := runner.(readOnlyResolver); ok {
			plan, err = resolver.ResolveReadOnly(ctx, binary, args)
		} else {
			plan, err = runner.Resolve(ctx, binary, args)
		}
	} else {
		plan, err = runner.Resolve(ctx, binary, args)
	}
	if err != nil {
		return reportError(streams, err)
	}
	if dryRun || explain {
		fmt.Fprint(streams.Stdout, diagnostic.Explain(plan))
		fmt.Fprintf(streams.Stdout, "command=%s\n", strings.Join(plan.Command, " "))
		return 0
	}
	code, err := runner.Run(ctx, plan, streams)
	if err != nil {
		var post interface{ PostStartStatus() (int, bool) }
		if errors.As(err, &post) {
			status, known := post.PostStartStatus()
			fmt.Fprintf(streams.Stderr, "dproxy: warning: %v\n", err)
			if known {
				return status
			}
			return 125
		}
		return reportError(streams, err)
	}
	return code
}

func normalizeStreams(d Dependencies) Streams {
	in, out, errOut := d.Stdin, d.Stdout, d.Stderr
	if in == nil {
		in = strings.NewReader("")
	}
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	return Streams{Stdin: in, Stdout: out, Stderr: errOut}
}

func reportError(s Streams, err error) int {
	fmt.Fprintf(s.Stderr, "dproxy: %v\n", err)
	if errors.Is(err, ErrSandboxCreation) {
		return 125
	}
	return 2
}

func usage(s Streams, message string) int { fmt.Fprintln(s.Stderr, message); return 2 }

// buildVersion reports the dproxy version. A `go install ...@version` build
// carries the module version (pseudo-version or tag) in its build info; a local
// `go build` reports "(devel)", which falls back to "dev". No ldflags required.
func buildVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok {
		if v := info.Main.Version; v != "" && v != "(devel)" {
			return v
		}
	}
	return "dev"
}

func isAdmin(name string) bool {
	switch name {
	case "init", "lock", "update", "tool", "plugin", "setup", "install", "doctor", "cache", "uninstall":
		return true
	default:
		return false
	}
}

// isHelpRequest recognizes an explicit top-level help request. Help is routed
// to stdout and exits 0, matching the convention that asking for help is not
// an error (unlike unrecognized input, which prints usage to stderr, exit 2).
func isHelpRequest(arg string) bool {
	switch arg {
	case "help", "--help", "-h":
		return true
	default:
		return false
	}
}

const helpText = `Usage: dproxy [--dry-run|--explain] <command|tool> [arguments...]

dproxy runs untrusted developer tools in disposable, locked-down containers.

Commands:
  init        create a .dproxy.toml for this project
  install     install global shims and shell integration (no project required)
  lock        pin tool image digests to the project lockfile
  update      refresh pinned tool images
  tool        add or remove tools
  plugin      add, remove, sync, list, or inspect plugins
  setup       install this project's tool shims from its lockfile
  doctor      verify configuration and Docker engine; provision the gateway
  cache       list, clean, or prune the shared cache
  uninstall   remove global shims and shell integration
  version     print the dproxy version

Any other name runs that tool sandboxed, for example: dproxy npm install.
--dry-run and --explain print the resolved plan instead of running it.

Linux hosts only today; macOS and Windows backends are tracked same-release
work (see docs/platform-backends.md).
`
