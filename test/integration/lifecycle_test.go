//go:build integration

package integration

import (
	"context"
	"fmt"
	"github.com/i-rocky/dproxy/internal/engine"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestCompletedAttackRemovesItsOwnedCommandBeforeReturning(t *testing.T) {
	api, _, _ := fixtures(t)
	_, ownership := runAttacker(t)
	owned, err := engine.NewDocker(api).ListOwned(context.Background(), ownership)
	require.NoError(t, err)
	require.Empty(t, owned)
}

func TestConcurrentProjectsRemainIndependent(t *testing.T) {
	api, image, _ := fixtures(t)
	type workerResult struct {
		attack attackResult
		err    error
	}
	results := make(chan workerResult, 2)
	for i := 0; i < 2; i++ {
		projectID := fmt.Sprintf("concurrent-%d", i)
		root := t.TempDir()
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			result, _, err := executeAttack(ctx, api, image, root, projectID)
			results <- workerResult{attack: result, err: err}
		}()
	}
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			require.NoError(t, result.err)
			require.True(t, result.attack.ProjectWrite)
		case <-time.After(35 * time.Second):
			t.Fatal("concurrent attacker worker timed out")
		}
	}
}
