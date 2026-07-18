//go:build integration

package integration

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSandboxDeniesHostAndAllowsProject(t *testing.T) {
	result, _ := runAttacker(t)
	require.True(t, result.ProjectWrite)
	require.False(t, result.HostCanaryRead)
	require.False(t, result.HostEnvRead)
	require.False(t, result.DockerSocketPresent)
}
