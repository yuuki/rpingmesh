package agent

import "github.com/yuuki/rpingmesh/internal/config"

func serviceMetricLabels(cfg *config.AgentConfig) []string {
	labels := make([]string, 0, len(cfg.ServiceTracingServiceLabels))
	for _, mapping := range cfg.ServiceTracingServiceLabels {
		labels = append(labels, mapping.Service)
	}
	return labels
}
