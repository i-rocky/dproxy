package testimage

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/docker/docker/api/types"
)

type Builder interface {
	ImageBuild(context.Context, io.Reader, types.ImageBuildOptions) (types.ImageBuildResponse, error)
	ImageInspectWithRaw(context.Context, string) (types.ImageInspect, []byte, error)
}

func Scratch(ctx context.Context, api Builder, packagePath, name string) (string, error) {
	_, sourceFile, _, _ := runtime.Caller(0)
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
	directory, err := os.MkdirTemp("", "dproxy-integration-build-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(directory)
	binary := filepath.Join(directory, name)
	command := exec.CommandContext(ctx, "go", "build", "-trimpath", "-ldflags=-s -w", "-o", binary, filepath.Join(moduleRoot, packagePath))
	command.Dir = moduleRoot
	command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH, "GOCACHE="+filepath.Join(directory, "go-cache"))
	if output, err := command.CombinedOutput(); err != nil {
		return "", fmt.Errorf("build %s: %w: %s", name, err, output)
	}
	binaryData, err := os.ReadFile(binary)
	if err != nil {
		return "", err
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	files := map[string][]byte{"Dockerfile": []byte("FROM scratch\nCOPY " + name + " /" + name + "\nENTRYPOINT [\"/" + name + "\"]\n"), name: binaryData}
	for path, data := range files {
		mode := int64(0644)
		if path == name {
			mode = 0755
		}
		if err := writer.WriteHeader(&tar.Header{Name: path, Mode: mode, Size: int64(len(data))}); err != nil {
			return "", err
		}
		if _, err := writer.Write(data); err != nil {
			return "", err
		}
	}
	if err := writer.Close(); err != nil {
		return "", err
	}
	tag := "dproxy-integration/" + name + ":" + fmt.Sprint(time.Now().UnixNano())
	response, err := api.ImageBuild(ctx, bytes.NewReader(archive.Bytes()), types.ImageBuildOptions{Tags: []string{tag}, Remove: true})
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if _, err := io.Copy(io.Discard, response.Body); err != nil {
		return "", err
	}
	inspect, _, err := api.ImageInspectWithRaw(ctx, tag)
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(inspect.ID, "sha256:") || len(inspect.ID) != 71 {
		return "", fmt.Errorf("local fixture has non-content-addressed ID %q", inspect.ID)
	}
	return inspect.ID, nil
}
