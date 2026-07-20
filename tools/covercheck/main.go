// Command covercheck enforces a strict minimum coverage threshold on a Go
// coverage profile. It is a Go program, not a shell script, so the coverage
// gate runs identically on Linux, macOS, and Windows.
//
// Usage:
//
//	go test -coverprofile=coverage.out ./...
//	go run ./tools/covercheck [-min 80.0] coverage.out
//
// The check is strict: coverage must be greater than -min. The gate fails at or
// below the threshold, matching the design's "strictly greater than 80%" rule.
package main

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
)

func main() {
	min, path, err := parseArgs(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	pct, err := profileCoverage(path)
	if err != nil {
		fatal(err)
	}
	if pct <= min {
		fmt.Fprintf(os.Stderr, "coverage %.1f%% must be greater than %.1f%%\n", pct, min)
		os.Exit(1)
	}
	fmt.Printf("coverage %.1f%% is greater than %.1f%% threshold\n", pct, min)
}

func parseArgs(args []string) (float64, string, error) {
	min := 80.0
	var path string
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "-min" && i+1 < len(args):
			v, err := strconv.ParseFloat(args[i+1], 64)
			if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
				return 0, "", fmt.Errorf("invalid -min value %q", args[i+1])
			}
			min = v
			i++
		case strings.HasPrefix(args[i], "-"):
			return 0, "", fmt.Errorf("unknown argument %q", args[i])
		default:
			if path != "" {
				return 0, "", fmt.Errorf("only one coverage profile may be given")
			}
			path = args[i]
		}
	}
	if path == "" {
		return 0, "", fmt.Errorf("usage: go run ./tools/covercheck [-min N] coverage.out")
	}
	return min, path, nil
}

func profileCoverage(path string) (float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("open coverage profile: %w", err)
	}
	defer f.Close()
	return computeCoverage(f)
}

// computeCoverage parses a Go coverage profile ("go test -coverprofile" format)
// and returns the percentage of covered statements. Each data line is
// "file:start.line.col,end.line.col numStmts count"; a statement block is
// covered when count > 0.
//
// A block may appear more than once — notably with "go test -coverpkg=./...",
// every test binary reports every block, so a covered block still has many
// zero-count duplicate lines. Blocks are deduplicated by location; a block is
// covered when any of its duplicate lines reports count > 0.
func computeCoverage(r io.Reader) (float64, error) {
	type block struct {
		numStmts int64
		covered  bool
	}
	blocks := map[string]*block{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "mode:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 3 {
			continue
		}
		numStmts, err1 := strconv.ParseInt(parts[1], 10, 64)
		count, err2 := strconv.ParseInt(parts[2], 10, 64)
		if err1 != nil || err2 != nil || numStmts < 0 {
			continue
		}
		b, ok := blocks[parts[0]]
		if !ok {
			b = &block{numStmts: numStmts}
			blocks[parts[0]] = b
		}
		if count > 0 {
			b.covered = true
		}
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read coverage profile: %w", err)
	}
	if len(blocks) == 0 {
		return 0, fmt.Errorf("coverage profile has no statements")
	}
	var covered, total int64
	for _, b := range blocks {
		total += b.numStmts
		if b.covered {
			covered += b.numStmts
		}
	}
	return float64(covered) / float64(total) * 100, nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "covercheck:", err)
	os.Exit(2)
}
