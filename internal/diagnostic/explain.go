package diagnostic

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/i-rocky/dproxy/internal/policy"
)

func Explain(plan policy.Plan) string {
	var out strings.Builder
	fmt.Fprintf(&out, "image=%s\nworkdir=%s\n", visible(plan.Image), visible(plan.Workdir))
	mounts := append([]policy.Mount(nil), plan.Mounts...)
	sort.Slice(mounts, func(i, j int) bool {
		if mounts[i].Target == mounts[j].Target {
			return !mounts[i].ReadOnly && mounts[j].ReadOnly
		}
		return mounts[i].Target < mounts[j].Target
	})
	for _, mount := range mounts {
		fmt.Fprintf(&out, "destination=%s read_only=%t\n", visible(mount.Target), mount.ReadOnly)
	}
	keys := make([]string, 0, len(plan.Environment))
	for key := range plan.Environment {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		fmt.Fprintf(&out, "%s=<redacted>\n", visible(key))
	}
	ports := append([]policy.Port(nil), plan.Ports...)
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Host == ports[j].Host {
			return ports[i].Container < ports[j].Container
		}
		return ports[i].Host < ports[j].Host
	})
	for _, port := range ports {
		fmt.Fprintf(&out, "port=%d:%d\n", port.Host, port.Container)
	}
	fmt.Fprintf(&out, "network=%s\n", visible(plan.Network.Mode))
	allow := append([]string(nil), plan.Network.Allowlist...)
	sort.Strings(allow)
	for _, destination := range allow {
		fmt.Fprintf(&out, "allow=%s\n", visible(destination))
	}
	fmt.Fprintf(&out, "read_only_root=%t\nno_new_privileges=%t\nauto_remove=%t\n", plan.ReadOnlyRoot, plan.NoNewPrivileges, plan.AutoRemove)
	return out.String()
}

func visible(value string) string { quoted := strconv.Quote(value); return quoted[1 : len(quoted)-1] }
