package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/i-rocky/dproxy/internal/gateway"
)

const readyPath = "/run/dproxy-ready"

func main() {
	if len(os.Args) < 2 {
		fatal(fmt.Errorf("gateway command is required"))
	}
	switch os.Args[1] {
	case "health":
		fatal(gateway.SystemHealth(readyPath, "/etc/dproxy/policy.json", os.Getenv("DPROXY_HEALTH_TOKEN"), os.Getenv("DPROXY_HEALTH_PROBE"), "127.0.0.1:1053"))
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		policy := fs.String("policy", "", "read-only policy path")
		if err := fs.Parse(os.Args[2:]); err != nil {
			fatal(err)
		}
		p, raw, err := gateway.LoadPolicyWithBytes(*policy)
		if err != nil {
			fatal(err)
		}
		ph := sha256.Sum256(raw)
		n := &gateway.NFT{Policy: p, DNSPort: 1053}
		controls := &gateway.RuntimeControls{Policy: p, Upstream: os.Getenv("DPROXY_DNS_UPSTREAM"), NFT: n}
		fatal(gateway.ServeWithToken(context.Background(), hex.EncodeToString(ph[:]), readyPath, os.Getenv("DPROXY_HEALTH_TOKEN"), controls))
	default:
		fatal(fmt.Errorf("unknown gateway command"))
	}
}
func fatal(err error) {
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
