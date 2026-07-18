package testimage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/stretchr/testify/require"
)

type fakeBuilder struct {
	built                bool
	id                   string
	buildErr, inspectErr error
}

func (f *fakeBuilder) ImageBuild(_ context.Context, archive io.Reader, options types.ImageBuildOptions) (types.ImageBuildResponse, error) {
	if f.buildErr != nil {
		return types.ImageBuildResponse{}, f.buildErr
	}
	raw, err := io.ReadAll(archive)
	if err != nil {
		return types.ImageBuildResponse{}, err
	}
	f.built = len(raw) > 0 && len(options.Tags) == 1
	return types.ImageBuildResponse{Body: io.NopCloser(strings.NewReader("{}\n"))}, nil
}
func (f *fakeBuilder) ImageInspectWithRaw(context.Context, string) (types.ImageInspect, []byte, error) {
	return types.ImageInspect{ID: f.id}, nil, f.inspectErr
}

func TestScratchBuildsOfflineStaticContentAddressedImage(t *testing.T) {
	fake := &fakeBuilder{id: "sha256:" + strings.Repeat("a", 64)}
	id, err := Scratch(context.Background(), fake, "test/fixtures/attacker", "attacker")
	require.NoError(t, err)
	require.True(t, fake.built)
	require.Equal(t, fake.id, id)
}

func TestScratchRejectsNonContentAddressedResult(t *testing.T) {
	_, err := Scratch(context.Background(), &fakeBuilder{id: "latest"}, "test/fixtures/attacker", "attacker")
	require.Error(t, err)
}

func TestScratchPropagatesDockerFailures(t *testing.T) {
	_, err := Scratch(context.Background(), &fakeBuilder{buildErr: errors.New("build")}, "test/fixtures/attacker", "attacker")
	require.Error(t, err)
	_, err = Scratch(context.Background(), &fakeBuilder{inspectErr: errors.New("inspect")}, "test/fixtures/attacker", "attacker")
	require.Error(t, err)
}
