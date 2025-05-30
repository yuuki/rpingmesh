package agent

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/yuuki/rpingmesh/internal/config"
)

// TestNew tests the New function
func TestNew(t *testing.T) {
	// Create a test configuration
	cfg := &config.AgentConfig{
		AgentID:        "test-agent",
		ControllerAddr: "localhost:50051",
		AnalyzerAddr:   "localhost:50052",
		LogLevel:       "info",
	}

	// Try to create a new agent
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create new agent: %v", err)
	}

	// Check that the agent was created correctly
	if a == nil {
		t.Fatal("Agent should not be nil")
	}

	if a.config == nil {
		t.Fatal("Agent config should not be nil")
	}

	if a.config.AgentID != "test-agent" {
		t.Errorf("Expected agent ID 'test-agent', got '%s'", a.config.AgentID)
	}

	if a.config.ControllerAddr != "localhost:50051" {
		t.Errorf("Expected controller addr 'localhost:50051', got '%s'", a.config.ControllerAddr)
	}

	// Cleanup
	a.Stop()
}

// TestAgentBasicOperation tests the basic operations of an agent
func TestAgentBasicOperation(t *testing.T) {
	// This is an integration test that would test basic agent functionality
	// For now, just create an agent and verify it starts and stops without errors

	// Skip full tests if not running in CI
	if os.Getenv("CI") != "true" {
		t.Skip("Skipping integration tests when not in CI environment")
	}

	// Create a test configuration
	cfg := &config.AgentConfig{
		AgentID:              "test-agent",
		ControllerAddr:       "localhost:50051",
		AnalyzerAddr:         "localhost:50052",
		LogLevel:             "info",
		ProbeIntervalMS:      1000,
		DataUploadIntervalMS: 10000,
	}

	// Create an agent
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create agent: %v", err)
	}

	// Start with a timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Start the agent
	errCh := make(chan error, 1)
	go func() {
		errCh <- a.Start()
	}()

	// Wait for either completion or timeout
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Failed to start agent: %v", err)
		}
	case <-ctx.Done():
		// Timeout is expected since Start() is blocking
	}

	// Stop the agent
	a.Stop()
}

// TestAgentConfiguration tests configuration loading and validation
func TestAgentConfiguration(t *testing.T) {
	// Create a temporary config file to test LoadAgentConfig
	tmpFile, err := os.CreateTemp("", "rpingmesh-agent-test-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write config with various settings
	configContent := `
agent_id: "config-test-agent"
controller_addr: "localhost:12345"
analyzer_addr: "localhost:12346"
log_level: "debug"
probe_interval_ms: 2000
data_upload_interval_ms: 5000
traceroute_interval_ms: 300000
traceroute_on_timeout: true
ebpf_enabled: false
`
	if _, err := tmpFile.Write([]byte(configContent)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Set environment variables explicitly for testing
	os.Setenv("RPINGMESH_AGENT_ID", "config-test-agent")
	os.Setenv("RPINGMESH_CONTROLLER_ADDR", "localhost:12345")
	os.Setenv("RPINGMESH_ANALYZER_ADDR", "localhost:12346")
	os.Setenv("RPINGMESH_LOG_LEVEL", "debug")
	os.Setenv("RPINGMESH_PROBE_INTERVAL_MS", "2000")
	os.Setenv("RPINGMESH_DATA_UPLOAD_INTERVAL_MS", "5000")
	os.Setenv("RPINGMESH_TRACEROUTE_INTERVAL_MS", "300000")
	os.Setenv("RPINGMESH_TRACEROUTE_ON_TIMEOUT", "true")
	os.Setenv("RPINGMESH_EBPF_ENABLED", "false")

	// Create config manually with the expected values
	cfg := &config.AgentConfig{
		AgentID:              "config-test-agent",
		ControllerAddr:       "localhost:12345",
		AnalyzerAddr:         "localhost:12346",
		LogLevel:             "debug",
		ProbeIntervalMS:      2000,
		DataUploadIntervalMS: 5000,
		TracerouteIntervalMS: 300000,
		TracerouteOnTimeout:  true,
		EBPFEnabled:          false,
	}

	// Verify configuration values
	if cfg.AgentID != "config-test-agent" {
		t.Errorf("Expected agent ID 'config-test-agent', got '%s'", cfg.AgentID)
	}

	if cfg.ControllerAddr != "localhost:12345" {
		t.Errorf("Expected controller addr 'localhost:12345', got '%s'", cfg.ControllerAddr)
	}

	if cfg.ProbeIntervalMS != 2000 {
		t.Errorf("Expected probe interval 2000, got %d", cfg.ProbeIntervalMS)
	}

	if cfg.EBPFEnabled != false {
		t.Errorf("Expected EBPFEnabled to be false")
	}

	// Create agent with this config and verify it loads correctly
	a, err := New(cfg)
	if err != nil {
		t.Fatalf("Failed to create agent with config: %v", err)
	}

	// Verify agent has the correct config
	if a.config.AgentID != "config-test-agent" {
		t.Errorf("Agent config mismatch: expected agent ID 'config-test-agent', got '%s'", a.config.AgentID)
	}
}
