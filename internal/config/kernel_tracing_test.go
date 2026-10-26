package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKernelTracingConfig(t *testing.T) {
	cfg, err := LoadAgentConfig("", nil)
	if err != nil || cfg.ServiceTracingKernelULPEnabled {
		t.Fatalf("kernel tracing must be off by default: %+v, %v", cfg, err)
	}
	file := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(file, []byte("service_tracing_enabled: true\nservice_tracing_kernel_ulp_enabled: true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = LoadAgentConfig(file, nil)
	if err != nil || !cfg.ServiceTracingKernelULPEnabled {
		t.Fatalf("YAML setting not loaded: %+v, %v", cfg, err)
	}
	t.Setenv("RPINGMESH_SERVICE_TRACING_KERNEL_ULP_ENABLED", "false")
	cfg, err = LoadAgentConfig(file, nil)
	if err != nil || cfg.ServiceTracingKernelULPEnabled {
		t.Fatalf("environment override not loaded: %+v, %v", cfg, err)
	}
}
