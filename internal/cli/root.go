package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"dproxy/internal/diagnostic"
	"dproxy/internal/policy"
)

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
	if args[0] == "version" {
		if len(args) != 1 || dryRun || explain {
			return usage(streams, "version takes no arguments")
		}
		fmt.Fprintln(streams.Stdout, "dproxy dev")
		return 0
	}
	if isAdmin(args[0]) {
		if dryRun || explain {
			return usage(streams, "planning flags require a tool")
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
	plan, err := runner.Resolve(ctx, binary, args)
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

func isAdmin(name string) bool {
	switch name {
	case "init", "lock", "update", "tool", "plugin", "setup", "doctor", "cache", "uninstall":
		return true
	default:
		return false
	}
}
