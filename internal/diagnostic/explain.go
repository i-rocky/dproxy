package diagnostic

import (
	"fmt"
	"sort"
	"strings"

	"dproxy/internal/policy"
)

func Explain(plan policy.Plan) string {
	var out strings.Builder
	fmt.Fprintf(&out, "image=%s\nworkdir=%s\n", plan.Image, plan.Workdir)
	for _, mount := range plan.Mounts {
		fmt.Fprintf(&out, "destination=%s read_only=%t\n", mount.Target, mount.ReadOnly)
	}
	keys := make([]string, 0, len(plan.Environment))
	for key := range plan.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&out, "%s=<redacted>\n", key)
	}
	for _, port := range plan.Ports {
		fmt.Fprintf(&out, "port=%d:%d\n", port.Host, port.Container)
	}
	fmt.Fprintf(&out, "network=%s\n", plan.Network.Mode)
	allow := append([]string(nil), plan.Network.Allowlist...)
	sort.Strings(allow)
	for _, destination := range allow {
		fmt.Fprintf(&out, "allow=%s\n", destination)
	}
	fmt.Fprintf(&out, "read_only_root=%t\nno_new_privileges=%t\nauto_remove=%t\n", plan.ReadOnlyRoot, plan.NoNewPrivileges, plan.AutoRemove)
	return out.String()
}
