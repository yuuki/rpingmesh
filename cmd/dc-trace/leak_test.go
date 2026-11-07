//go:build linux

package main

import (
	"testing"

	"go.uber.org/goleak"
)

// TestMain fails the package if a goroutine its tests started (the DC
// collector and its observation loop) is still running once they have
// finished.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
