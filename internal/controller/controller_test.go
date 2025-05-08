package controller

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	// Set environment variable for database URI in tests
	os.Setenv("RPINGMESH_CONTROLLER_DATABASE_URI", "http://rqlite:4001")

	// Run tests
	exitCode := m.Run()

	// Exit with the same code
	os.Exit(exitCode)
}

func TestControllerBasic(t *testing.T) {
	// Create controller with empty config path (will use environment variables)
	controller, err := New("")
	require.NoError(t, err, "Should create controller without error")

	// Make sure controller is properly initialized
	assert.NotNil(t, controller.registry, "Registry should be initialized")
	assert.NotNil(t, controller.pingLister, "PingLister should be initialized")

	// Cleanup
	controller.Stop()
}
