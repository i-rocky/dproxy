package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), "dproxy", []string{"version"}, &out, &errOut)
	require.Equal(t, 0, code)
	require.Equal(t, "dproxy dev\n", out.String())
	require.Empty(t, errOut.String())
}

func TestCommandErrorUsesStderrAndStatusTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Execute(context.Background(), "dproxy", []string{"not-a-command"}, &out, &errOut)
	require.Equal(t, 2, code)
	require.Empty(t, out.String())
	require.Contains(t, errOut.String(), "unknown command")
}
