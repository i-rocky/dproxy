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
}
