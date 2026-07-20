package main

import (
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
}
