package fault

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestErrorIsSanitizedAndUnwraps(t *testing.T) {
	cause := errors.New("secret-value")
	err := New("load configuration", "malformed TOML", cause)
	require.EqualError(t, err, "load configuration: malformed TOML")
	require.ErrorIs(t, err, cause)
}
