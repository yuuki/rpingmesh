package config

import (
	"fmt"
	"path"
	"strings"
)

// ServiceLabelMapping assigns a bounded service name to a cgroup v2 subtree.
// CgroupPath is relative to the cgroup mount, with a leading slash. The most
// specific matching path wins. Multiple paths may share one service name.
type ServiceLabelMapping struct {
	CgroupPath string `mapstructure:"cgroup_path" json:"cgroup_path"`
	Service    string `mapstructure:"service" json:"service"`
}

func validateServiceLabels(mappings []ServiceLabelMapping) error {
	seen := make(map[string]bool, len(mappings))
	for _, m := range mappings {
		if !path.IsAbs(m.CgroupPath) || path.Clean(m.CgroupPath) != m.CgroupPath || strings.ContainsRune(m.CgroupPath, '\x00') {
			return fmt.Errorf("service_tracing_service_labels: cgroup_path %q must be a clean absolute cgroup path", m.CgroupPath)
		}
		if seen[m.CgroupPath] {
			return fmt.Errorf("service_tracing_service_labels: duplicate cgroup_path %q", m.CgroupPath)
		}
		seen[m.CgroupPath] = true
		if m.Service == "" || strings.TrimSpace(m.Service) != m.Service || strings.HasPrefix(m.Service, "_") || len(m.Service) > 128 {
			return fmt.Errorf("service_tracing_service_labels: service must be 1-128 bytes, without surrounding whitespace or a reserved '_' prefix")
		}
	}
	return nil
}
