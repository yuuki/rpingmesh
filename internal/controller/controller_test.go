package controller

import (
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/yuuki/rpingmesh/internal/config"
)

// getDBURI returns the appropriate database URI for the environment
func getDBURI() string {
	// Use the environment variable if set
	dbURI := os.Getenv("RPINGMESH_CONTROLLER_DATABASE_URI")
	if dbURI != "" {
		return dbURI
	}

	// Check for local test environment variable
	localTestURI := os.Getenv("RQLITE_LOCAL_TEST_URI")
	if localTestURI != "" {
		return localTestURI
	}

	// Use localhost for make test-local execution
	return "http://localhost:4001"
}

// isRqliteRunning checks if rqlite is running and accessible
func isRqliteRunning() bool {
	uri := getDBURI()
	resp, err := http.Get(uri + "/status")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// TestMain sets up the local test environment before running tests
func TestMain(m *testing.M) {
	// Save the current environment variable value
	oldDBURI := os.Getenv("RPINGMESH_CONTROLLER_DATABASE_URI")

	// Set the appropriate URI for the environment
	os.Setenv("RPINGMESH_CONTROLLER_DATABASE_URI", getDBURI())

	// Run tests
	exitCode := m.Run()

	// Restore the environment variable
	if oldDBURI != "" {
		os.Setenv("RPINGMESH_CONTROLLER_DATABASE_URI", oldDBURI)
	} else {
		os.Unsetenv("RPINGMESH_CONTROLLER_DATABASE_URI")
	}

	os.Exit(exitCode)
}

func TestControllerBasic(t *testing.T) {
	// Skip test if rqlite is not running
	if !isRqliteRunning() {
		t.Skip("Skipping test: rqlite is not running at " + getDBURI())
	}

	// Create a config for testing
	cfg := &config.ControllerConfig{
		ListenAddr:  "127.0.0.1:0", // Let the OS choose an available port
		DatabaseURI: getDBURI(),    // Use the appropriate URI for the environment
		LogLevel:    "info",
	}

	// Create controller with the config
	controller, err := New(cfg)
	require.NoError(t, err, "Should create controller without error")

	// Make sure controller is properly initialized
	assert.NotNil(t, controller.registry, "Registry should be initialized")
	assert.NotNil(t, controller.pingLister, "PingLister should be initialized")

	// Cleanup
	controller.Stop()
}
