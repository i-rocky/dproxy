//go:build integration

package engine

import (
	"context"
	"testing"
	"time"

	"github.com/docker/docker/client"
	"github.com/stretchr/testify/require"
)

// This smoke test deliberately fails instead of skipping when Docker is absent.
// Release qualification can therefore never silently lose its engine coverage.
func TestDockerIntegrationEngineVerification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	api, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err, "Docker is required for integration qualification")
	defer api.Close()
	require.NoError(t, NewDocker(api).Verify(ctx), "a supported Linux Docker Engine is required for integration qualification")
}
