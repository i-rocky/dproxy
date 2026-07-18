package plugin

import (
	"context"
	"os/exec"
)

// Git receives an argument slice that is passed literally to the Git process.
type Git interface {
	Run(ctx context.Context, directory string, args []string) ([]byte, error)
}

type execGit struct {
	executable string
	home       string
}

func (g execGit) Run(ctx context.Context, directory string, args []string) ([]byte, error) {
	command := exec.CommandContext(ctx, g.executable, args...)
	command.Dir = directory
	command.Env = []string{
		"HOME=" + g.home,
		"PATH=/usr/bin:/bin",
		"LC_ALL=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=/bin/false",
		"SSH_ASKPASS=/bin/false",
	}
	return command.Output()
}
