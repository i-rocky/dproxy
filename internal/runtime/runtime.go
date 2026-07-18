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
	"dproxy/internal/policy"
)

const defaultCleanupTimeout = 10 * time.Second

type Dependencies struct {
	Engine         engine.Engine
	Signals        <-chan os.Signal
	CleanupTimeout time.Duration
}
type IO struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
	TTY            bool
	MakeRaw        func() (func() error, error)
}

func Run(ctx context.Context, deps Dependencies, plan policy.Plan, streams IO) (exitCode int, setupErr error) {
	if deps.Engine == nil {
		return 0, errors.New("runtime engine is required")
	}
	timeout := deps.CleanupTimeout
	if timeout <= 0 {
		timeout = defaultCleanupTimeout
	}
	var resources []engine.Resource
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		if err := cleanup(cleanupCtx, deps.Engine, resources); err != nil && setupErr == nil {
			setupErr = err
		}
	}()
	if err := deps.Engine.Verify(ctx); err != nil {
		return 0, fmt.Errorf("verify container engine: %w", err)
	}
	if err := deps.Engine.PullByDigest(ctx, plan.Image); err != nil {
		return 0, fmt.Errorf("prepare locked image: %w", err)
	}
	var networkID string
	if plan.Network.Mode != "none" {
		network, err := deps.Engine.CreateNetwork(ctx, plan)
		if err != nil {
			return 0, fmt.Errorf("create isolated network: %w", err)
		}
		resources = append(resources, network)
		networkID = network.ID
		gateway, err := deps.Engine.StartGateway(ctx, plan, networkID)
		if err != nil {
			return 0, fmt.Errorf("start filtering gateway: %w", err)
		}
		resources = append(resources, gateway)
	}
	command, err := deps.Engine.StartCommand(ctx, plan, networkID, streams.TTY)
	if err != nil {
		return 0, fmt.Errorf("create command: %w", err)
	}
	resources = append(resources, command)
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
	defer attachment.Close()
	signals, stop := signalChannel(deps.Signals)
	defer stop()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for sig := range signals {
			if supportedSignal(sig) {
				_ = deps.Engine.Signal(context.WithoutCancel(ctx), command.ID, sig)
			}
		}
	}()
	exitCode, err = deps.Engine.Wait(ctx, command.ID)
	if err != nil {
		return exitCode, fmt.Errorf("wait for command: %w", err)
	}
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
	return sig == syscall.SIGINT || sig == syscall.SIGTERM || sig == syscall.SIGWINCH
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
