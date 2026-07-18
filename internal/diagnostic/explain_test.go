package diagnostic

import (
	"strings"
	"testing"

	"dproxy/internal/policy"
	"github.com/stretchr/testify/require"
)

func TestExplainRedactsEnvironmentAndHostSources(t *testing.T) {
	secret := "secret-value"
	host := "/home/person/private/project"
	plan := policy.Plan{Image: "repo/node@sha256:" + strings.Repeat("d", 64), Workdir: "/workspace/sub", Command: []string{"node", "--token=" + secret}, Environment: map[string]string{"TOKEN": secret, "SAFE": "also-secret"}, Mounts: []policy.Mount{{Source: host, Target: "/workspace"}, {Source: "/cache/private", Target: "/home/node/.npm"}}, Ports: []policy.Port{{Host: 3000, Container: 3000}}, Network: policy.Network{Mode: "allowlist", Allowlist: []string{"registry.example.test"}}, ReadOnlyRoot: true, NoNewPrivileges: true, CapDrop: []string{"ALL"}}
	got := Explain(plan)
	require.Contains(t, got, "TOKEN=<redacted>")
	require.Contains(t, got, "SAFE=<redacted>")
	require.NotContains(t, got, secret)
	require.NotContains(t, got, host)
	require.NotContains(t, got, "/cache/private")
	require.Contains(t, got, "destination=/workspace")
	require.Contains(t, got, "port=3000:3000")
	require.Contains(t, got, "network=allowlist")
	require.Contains(t, got, "allow=registry.example.test")
	require.Contains(t, got, "read_only_root=true")
}

func TestExplainIsDeterministic(t *testing.T) {
	plan := policy.Plan{Environment: map[string]string{"Z": "1", "A": "2"}, Mounts: []policy.Mount{{Target: "/z"}, {Target: "/a"}}}
	require.Equal(t, Explain(plan), Explain(plan))
	require.Less(t, strings.Index(Explain(plan), "A=<redacted>"), strings.Index(Explain(plan), "Z=<redacted>"))
}

func TestExplainCanonicalizesPermutedPlansAndEscapesControls(t *testing.T) {
	left := policy.Plan{Image: "image\nforged", Environment: map[string]string{"Z": "1", "A": "2"}, Mounts: []policy.Mount{{Target: "/z"}, {Target: "/a", ReadOnly: true}}, Ports: []policy.Port{{Host: 4000, Container: 40}, {Host: 3000, Container: 30}}, Network: policy.Network{Mode: "allow\nlist", Allowlist: []string{"z.example", "a.example"}}}
	right := left
	right.Mounts = []policy.Mount{left.Mounts[1], left.Mounts[0]}
	right.Ports = []policy.Port{left.Ports[1], left.Ports[0]}
	right.Network.Allowlist = []string{"a.example", "z.example"}
	require.Equal(t, Explain(left), Explain(right))
	require.NotContains(t, Explain(left), "image\nforged")
	require.Contains(t, Explain(left), `image=image\nforged`)
}
