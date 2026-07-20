package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestComputeCoverage(t *testing.T) {
	t.Run("counts covered statement blocks", func(t *testing.T) {
		profile := "mode: set\n" +
			"pkg/a.go:10.1,10.5 2 1\n" + // covered
			"pkg/a.go:20.1,20.5 3 0\n" + // uncovered
			"pkg/b.go:5.1,5.5 5 1\n" // covered
		pct, err := computeCoverage(strings.NewReader(profile))
		require.NoError(t, err)
		// covered = 2 + 5 = 7 of 10 total -> 70%
		require.InDelta(t, 70.0, pct, 0.001)
	})

	t.Run("fully covered profile", func(t *testing.T) {
		pct, err := computeCoverage(strings.NewReader("mode: set\npkg/x.go:1.1,1.5 4 1\n"))
		require.NoError(t, err)
		require.InDelta(t, 100.0, pct, 0.001)
	})

	t.Run("empty profile errors", func(t *testing.T) {
		_, err := computeCoverage(strings.NewReader("mode: set\n"))
		require.Error(t, err)
	})

	t.Run("malformed lines are skipped", func(t *testing.T) {
		pct, err := computeCoverage(strings.NewReader("mode: set\nnot a line\npkg/x.go:1.1,1.5 4 1\n"))
		require.NoError(t, err)
		require.InDelta(t, 100.0, pct, 0.001)
	})

	t.Run("deduplicates blocks reported by multiple test binaries", func(t *testing.T) {
		// Mirrors -coverpkg output: the same block appears once per test binary,
		// covered by only some of them. The block is covered iff any count > 0.
		profile := "mode: set\n" +
			"pkg/a.go:10.1,10.5 2 1\n" + // covered by binary A
			"pkg/a.go:10.1,10.5 2 0\n" + // not covered by binary B
			"pkg/a.go:20.1,20.5 3 0\n" + // never covered
			"pkg/a.go:20.1,20.5 3 0\n"
		pct, err := computeCoverage(strings.NewReader(profile))
		require.NoError(t, err)
		// 2 distinct blocks: one covered (2 stmts), one not (3 stmts) -> 2/5 = 40%
		require.InDelta(t, 40.0, pct, 0.001)
	})
}

func TestParseArgs(t *testing.T) {
	t.Run("defaults to 80 and reads path", func(t *testing.T) {
		min, path, err := parseArgs([]string{"coverage.out"})
		require.NoError(t, err)
		require.Equal(t, 80.0, min)
		require.Equal(t, "coverage.out", path)
	})
	t.Run("custom threshold", func(t *testing.T) {
		min, _, err := parseArgs([]string{"-min", "85", "coverage.out"})
		require.NoError(t, err)
		require.Equal(t, 85.0, min)
	})
	t.Run("missing path errors", func(t *testing.T) {
		_, _, err := parseArgs(nil)
		require.Error(t, err)
	})
	t.Run("bad threshold errors", func(t *testing.T) {
		_, _, err := parseArgs([]string{"-min", "notanum", "coverage.out"})
		require.Error(t, err)
	})
	t.Run("unknown flag errors", func(t *testing.T) {
		_, _, err := parseArgs([]string{"-bogus", "coverage.out"})
		require.Error(t, err)
	})
	t.Run("two profiles errors", func(t *testing.T) {
		_, _, err := parseArgs([]string{"a.out", "b.out"})
		require.Error(t, err)
	})
	t.Run("nan threshold errors", func(t *testing.T) {
		_, _, err := parseArgs([]string{"-min", "NaN", "coverage.out"})
		require.Error(t, err)
	})
}

func TestProfileCoverage(t *testing.T) {
	t.Run("reads and computes from a file", func(t *testing.T) {
		p := filepath.Join(t.TempDir(), "cov.out")
		require.NoError(t, os.WriteFile(p, []byte("mode: set\npkg/x.go:1.1,1.5 3 1\npkg/x.go:2.1,2.5 1 0\n"), 0600))
		pct, err := profileCoverage(p)
		require.NoError(t, err)
		require.InDelta(t, 75.0, pct, 0.001) // 3 of 4 statements
	})
	t.Run("missing file errors", func(t *testing.T) {
		_, err := profileCoverage(filepath.Join(t.TempDir(), "absent"))
		require.Error(t, err)
	})
}

// TestMainExitContract exercises the actual CLI the coverage gate runs: the
// exit code and message for passing, strictly-at-threshold, failing, and
// unreadable-profile inputs. CI relies on these exit codes.
func TestMainExitContract(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "covercheck")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build covercheck: %v\n%s", err, out)
	}
	writeProfile := func(content string) string {
		p := filepath.Join(t.TempDir(), "cov.out")
		require.NoError(t, os.WriteFile(p, []byte(content), 0600))
		return p
	}
	cases := []struct {
		name     string
		args     []string
		wantExit int
		wantOut  string
	}{
		{"above threshold exits 0", []string{writeProfile("mode: set\npkg/x.go:1.1,1.5 4 1\n")}, 0, "is greater than"},
		{"below threshold exits 1", []string{writeProfile("mode: set\npkg/x.go:1.1,1.5 4 0\n")}, 1, "must be greater than"},
		// Exactly 50% against -min 50: the gate is strict (must be greater).
		{"at threshold exits 1 (strict)", []string{"-min", "50", writeProfile("mode: set\npkg/x.go:1.1,1.5 4 1\npkg/y.go:1.1,1.5 4 0\n")}, 1, "must be greater than"},
		{"missing profile exits 2", []string{filepath.Join(t.TempDir(), "absent")}, 2, ""},
		{"no arguments exits 2", nil, 2, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := exec.Command(bin, c.args...).CombinedOutput()
			if c.wantExit == 0 {
				require.NoError(t, err, "output: %s", out)
			} else {
				exit := &exec.ExitError{}
				require.ErrorAs(t, err, &exit, "output: %s", out)
				require.Equal(t, c.wantExit, exit.ExitCode(), "output: %s", out)
			}
			if c.wantOut != "" {
				require.Contains(t, string(out), c.wantOut)
			}
		})
	}
}
