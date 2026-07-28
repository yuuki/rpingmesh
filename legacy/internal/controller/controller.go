package controller

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/internal/controller/pinglist"
	"github.com/yuuki/rpingmesh/internal/controller/registry"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/grpc"
)

// Controller represents the RPingMesh controller
type Controller struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     *config.ControllerConfig
	server     *grpc.Server
	registry   *registry.RnicRegistry
	pingLister *pinglist.PingLister
	wg         sync.WaitGroup
}

// New creates a new controller instance
func New(cfg *config.ControllerConfig) (*Controller, error) {
	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize RNIC registry
	reg, err := registry.NewRnicRegistry(cfg.DatabaseURI)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize registry: %w", err)
	}

	// Initialize PingLister
	pl := pinglist.NewPingLister(reg)

	// Create new controller
	controller := &Controller{
		ctx:        ctx,
		cancel:     cancel,
		config:     cfg,
		registry:   reg,
		pingLister: pl,
	}

	return controller, nil
}

// Start starts the controller
func (c *Controller) Start() error {
	// Create gRPC server
	c.server = grpc.NewServer()

	// Register controller service
	service := NewControllerService(c.registry, c.pingLister)
	controller_agent.RegisterControllerServiceServer(c.server, service)

	// Start gRPC server
	lis, err := net.Listen("tcp", c.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Info().
		Str("addr", c.config.ListenAddr).
		Msg("Starting gRPC server")

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.server.Serve(lis); err != nil {
			log.Error().Err(err).Msg("Failed to serve gRPC")
		}
	}()

	// Note: Periodic cleanup is disabled to prevent agents from receiving empty pinglists
	// The CleanupStaleEntries method is still available for manual cleanup if needed

	return nil
}

// runPeriodicCleanup periodically cleans up stale entries
// NOTE: This function is currently disabled to prevent agents from receiving empty pinglists
// which would cause them to stop execution. The CleanupStaleEntries method is still available
// for manual cleanup operations if needed.
func (c *Controller) runPeriodicCleanup() {
	defer c.wg.Done()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			log.Info().Msg("Running periodic cleanup")
			if err := c.registry.CleanupStaleEntries(c.ctx); err != nil {
				log.Error().Err(err).Msg("Failed to cleanup stale entries")
			}
		}
	}
}

// Stop stops the controller
func (c *Controller) Stop() {
	c.cancel()

	// Gracefully stop gRPC server
	if c.server != nil {
		c.server.GracefulStop()
	}

	// Close registry
	if c.registry != nil {
		if err := c.registry.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close registry")
		}
	}

	// Wait for goroutines to complete
	c.wg.Wait()
	log.Info().Msg("Controller stopped")
}

// Run runs the controller with signal handling for graceful shutdown
func (c *Controller) Run() error {
	// Start the controller
	if err := c.Start(); err != nil {
		return err
	}

	// Set up signal handling for graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for a signal
	<-sigCh
	log.Info().Msg("Received signal, shutting down...")

	// Stop the controller
	c.Stop()
	return nil
}
