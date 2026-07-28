package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// getSystemHostname returns the system hostname or a fallback string
func getSystemHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		// Fallback to a random identifier
		return fmt.Sprintf("agent-%d", os.Getpid())
	}
	return hostname
}

// createConfigDirectory ensures the directory for a config file exists
func createConfigDirectory(path string) error {
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("error creating config directory: %w", err)
		}
	}
	return nil
}

// writeConfigFile writes content to a config file
func writeConfigFile(path, content string) error {
	if err := createConfigDirectory(path); err != nil {
		return err
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		return fmt.Errorf("error writing config file: %w", err)
	}

	return nil
}
