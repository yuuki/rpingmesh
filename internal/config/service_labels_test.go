package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadServiceLabels(t *testing.T) {
	file := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(file, []byte(`service_tracing_service_labels:
  - cgroup_path: /system.slice/Training@A.service
    service: Training-A
  - cgroup_path: /kubepods.slice/pod123
    service: namespace/job
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAgentConfig(file, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []ServiceLabelMapping{{"/system.slice/Training@A.service", "Training-A"}, {"/kubepods.slice/pod123", "namespace/job"}}
	if !reflect.DeepEqual(cfg.ServiceTracingServiceLabels, want) {
		t.Fatalf("mappings = %v, want %v", cfg.ServiceTracingServiceLabels, want)
	}
}

func TestValidateServiceLabels(t *testing.T) {
	for name, mappings := range map[string][]ServiceLabelMapping{
		"relative":       {{"system.slice/a.service", "a"}},
		"parent":         {{"/system.slice/../a", "a"}},
		"trailing slash": {{"/system.slice/", "a"}},
		"empty":          {{"/system.slice", ""}},
		"reserved":       {{"/system.slice", "_unspecified"}},
		"whitespace":     {{"/system.slice", " a"}},
		"duplicate":      {{"/system.slice", "a"}, {"/system.slice", "b"}},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateServiceLabels(mappings); err == nil {
				t.Fatal("expected invalid mapping")
			}
		})
	}
	if err := validateServiceLabels([]ServiceLabelMapping{{"/", "host"}, {"/system.slice", "host"}}); err != nil {
		t.Fatal(err)
	}
}

func TestServiceLabelsEnvironmentOverride(t *testing.T) {
	file := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(file, []byte("service_tracing_service_labels:\n  - cgroup_path: /file.service\n    service: file\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, value string
		want        []ServiceLabelMapping
		wantError   bool
	}{
		{name: "mapping", value: `[{"cgroup_path":"/system.slice/Training@A.service","service":"Training-A"}]`, want: []ServiceLabelMapping{{"/system.slice/Training@A.service", "Training-A"}}},
		{name: "disabled", value: `[]`, want: []ServiceLabelMapping{}},
		{name: "invalid JSON", value: `[{`, wantError: true},
		{name: "invalid mapping", value: `[{"cgroup_path":"relative","service":"training"}]`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("RPINGMESH_SERVICE_TRACING_SERVICE_LABELS", tc.value)
			cfg, err := LoadAgentConfig(file, nil)
			if tc.wantError {
				if err == nil {
					t.Fatal("expected invalid environment configuration")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(cfg.ServiceTracingServiceLabels, tc.want) {
				t.Fatalf("mappings = %v, want %v", cfg.ServiceTracingServiceLabels, tc.want)
			}
		})
	}
}
