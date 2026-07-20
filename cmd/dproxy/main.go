package main

import (
	"context"
	"os"

	"github.com/i-rocky/dproxy/internal/cli"
)

func main() {
	os.Exit(cli.Execute(context.Background(), os.Args[0], os.Args[1:], os.Stdout, os.Stderr))
}
