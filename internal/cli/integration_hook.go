//go:build integration

package cli

import (
	"errors"
	"strings"
)

// SetIntegrationImageReferenceMapper installs a fail-closed mapping for one
// registry digest to one immutable image already provisioned in the daemon.
func SetIntegrationImageReferenceMapper(expected, localID string) (restore func(), err error) {
	if !strings.Contains(expected, "@sha256:") || !strings.HasPrefix(localID, "sha256:") || len(localID) != 71 {
		return nil, errors.New("invalid integration image mapping")
	}
	previous := systemImageReferenceMapper
	systemImageReferenceMapper = func(reference string) (string, error) {
		if reference != expected {
			return "", errors.New("unexpected locked image reference")
		}
		return localID, nil
	}
	return func() { systemImageReferenceMapper = previous }, nil
}
