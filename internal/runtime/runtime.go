package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dproxy/internal/engine"
	networkpolicy "dproxy/internal/network"
	"dproxy/internal/policy"
)

const defaultCleanupTimeout = 10 * time.Second

type PostStartError struct {
	Status      int
	StatusKnown bool
	Err         error
}

func (e *PostStartError) Error() string                { return e.Err.Error() }
func (e *PostStartError) Unwrap() error                { return e.Err }
func (e *PostStartError) PostStartStatus() (int, bool) { return e.Status, e.StatusKnown }

type Dependencies struct {
	Engine         engine.Engine
	Network        NetworkManager
	NetworkRequest networkpolicy.Request
	Signals        <-chan os.Signal
	CleanupTimeout time.Duration
}
type NetworkManager interface {
	Begin(context.Context, networkpolicy.Request) (networkpolicy.RuntimeSession, error)
}
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	TTY            bool
	MakeRaw        func() (func() error, error)
	TerminalSize   func() (height, width uint, err error)
}

func Run(ctx context.Context, deps Dependencies, plan policy.Plan, streams IO) (exitCode int, setupErr error) {
	if deps.Engine == nil {
		return 0, errors.New("runtime engine is required")
	}
	if deps.Network == nil {
		return 0, errors.New("network orchestrator is required")
	}
	timeout := deps.CleanupTimeout
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	var resources []engine.Resource
	var networkSession networkpolicy.RuntimeSession
	commandStarted, statusKnown := false, false
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		if err := cleanup(cleanupCtx, deps.Engine, resources); err != nil && setupErr == nil {
			setupErr = err
		}
		if networkSession != nil {
			if err := networkSession.Close(cleanupCtx); err != nil && setupErr == nil {
				setupErr = fmt.Errorf("cleanup network session: %w", err)
			}
		}
		if commandStarted && setupErr != nil {
			var post *PostStartError
			if !errors.As(setupErr, &post) {
				setupErr = &PostStartError{Status: exitCode, StatusKnown: statusKnown, Err: setupErr}
			}
		}
	}()
	if err := deps.Engine.Verify(ctx); err != nil {
		return 0, fmt.Errorf("verify container engine: %w", err)
	}
	if err := deps.Engine.PullByDigest(ctx, plan.Image); err != nil {
		return 0, fmt.Errorf("prepare locked image: %w", err)
	}
	req := deps.NetworkRequest
	req.Plan = plan
	networkSession, err := deps.Network.Begin(ctx, req)
	if err != nil {
		return 0, fmt.Errorf("start isolated network session: %w", err)
	}
	plan.InvocationID = networkSession.InvocationID()
	commandNetworkTarget := networkSession.GatewayID()
	command, err := deps.Engine.StartCommand(ctx, plan, commandNetworkTarget, streams.TTY)
	if err != nil {
		return 0, fmt.Errorf("create command: %w", err)
	}
	resources = append(resources, command)
	commandStarted = true
	if streams.TTY {
		if streams.MakeRaw == nil {
			return 0, errors.New("TTY raw-mode support is required")
		}
		restore, rawErr := streams.MakeRaw()
		if rawErr != nil {
			return 0, fmt.Errorf("enable terminal raw mode: %w", rawErr)
		}
		defer func() {
			if err := restore(); err != nil && setupErr == nil {
				setupErr = fmt.Errorf("restore terminal: %w", err)
			}
		}()
	}
	attachment, err := deps.Engine.Attach(ctx, command.ID, engine.IO{Stdin: streams.Stdin, Stdout: streams.Stdout, Stderr: streams.Stderr, TTY: streams.TTY})
	if err != nil {
		return 0, fmt.Errorf("attach command: %w", err)
	}
	defer func() {
		if err := attachment.Close(); err != nil && setupErr == nil {
			setupErr = fmt.Errorf("close command attachment: %w", err)
		}
	}()
	if streams.TTY {
		if streams.TerminalSize == nil {
			return 0, errors.New("TTY size source is required")
		}
		if err := resize(ctx, deps.Engine, command.ID, streams.TerminalSize); err != nil {
			return 0, err
		}
	}
	signals, stop := signalChannel(deps.Signals)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range signals {
			if sig == syscall.SIGWINCH {
				if streams.TTY {
					_ = resize(context.WithoutCancel(ctx), deps.Engine, command.ID, streams.TerminalSize)
				}
			} else if supportedSignal(sig) {
				_ = deps.Engine.Signal(context.WithoutCancel(ctx), command.ID, sig)
			}
		}
	}()
	exitCode, err = deps.Engine.Wait(ctx, command.ID)
	if err != nil {
		return exitCode, fmt.Errorf("wait for command: %w", err)
	}
	statusKnown = true
	if err = attachment.Wait(); err != nil {
		return exitCode, fmt.Errorf("relay command output: %w", err)
	}
	stop()
	<-done
	return exitCode, nil
}

func signalChannel(in <-chan os.Signal) (<-chan os.Signal, func()) {
	if in != nil {
		out := make(chan os.Signal, 4)
		quit := make(chan struct{})
		go func() {
			defer close(out)
			for {
				select {
				case sig, ok := <-in:
					if !ok {
						return
					}
					select {
					case out <- sig:
					case <-quit:
						return
					}
				case <-quit:
					return
				}
			}
		}()
		var stopped bool
		return out, func() {
			if !stopped {
				stopped = true
				close(quit)
			}
		}
	}
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGWINCH)
	var stopped bool
	return ch, func() {
		if !stopped {
			stopped = true
			signal.Stop(ch)
			close(ch)
		}
	}
}
func supportedSignal(sig os.Signal) bool {
	return sig == syscall.SIGINT || sig == syscall.SIGTERM
}
func resize(ctx context.Context, e engine.Engine, id string, size func() (uint, uint, error)) error {
	height, width, err := size()
	if err != nil {
		return fmt.Errorf("query terminal size: %w", err)
	}
	if err = e.Resize(ctx, engine.ContainerID(id), height, width); err != nil {
		return fmt.Errorf("resize command terminal: %w", err)
	}
	return nil
}
func cleanup(ctx context.Context, e engine.Engine, resources []engine.Resource) error {
	var errs []error
	for i := len(resources) - 1; i >= 0; i-- {
		r := resources[i]
		var err error
		if r.Role == "network" {
			err = e.RemoveNetwork(ctx, r)
		} else {
			err = e.RemoveContainer(ctx, r)
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("cleanup owned resources: %w", errors.Join(errs...))
	}
	return nil
}
