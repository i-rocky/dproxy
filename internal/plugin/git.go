package plugin

import (
	"context"
	"os"
	"os/exec"
)

// Git receives an argument slice that is passed literally to the Git process.
type Git interface {
	Run(ctx context.Context, directory string, args []string) ([]byte, error)
}

type execGit struct{}

func (execGit) Run(ctx context.Context, directory string, args []string) ([]byte, error) {
	command := exec.CommandContext(ctx, "git", args...)
	command.Dir = directory
	command.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
	)
	return command.Output()
}
