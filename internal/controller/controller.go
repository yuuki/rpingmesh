package controller

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

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
	config     *config.Config
	server     *grpc.Server
	registry   *registry.RnicRegistry
	pingLister *pinglist.PingLister
	wg         sync.WaitGroup
}

// New creates a new controller instance
func New(configPath string) (*Controller, error) {
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create registry
	rnicRegistry, err := registry.NewRnicRegistry(cfg.DatabaseURI)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create RNIC registry: %w", err)
	}

	// Create ping lister
	pingLister := pinglist.NewPingLister(rnicRegistry)

	// Create controller
	controller := &Controller{
		ctx:        ctx,
		cancel:     cancel,
		config:     cfg,
		registry:   rnicRegistry,
		pingLister: pingLister,
	}

	return controller, nil
}

// Start starts the controller server
func (c *Controller) Start() error {
	// Create new gRPC server
	c.server = grpc.NewServer()

	// Register service
	controller_agent.RegisterControllerServiceServer(c.server, NewService(c.registry, c.pingLister))

	// Start server
	listener, err := net.Listen("tcp", c.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Info().Str("addr", c.config.ListenAddr).Msg("Starting gRPC server")

	// Serve in a goroutine
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		if err := c.server.Serve(listener); err != nil {
			log.Error().Err(err).Msg("gRPC server error")
		}
	}()

	return nil
}

// Stop stops the controller
func (c *Controller) Stop() {
	// Stop gRPC server
	if c.server != nil {
		c.server.GracefulStop()
	}

	// Cancel context
	c.cancel()

	// Wait for all goroutines to finish
	c.wg.Wait()

	// Close registry
	if c.registry != nil {
		if err := c.registry.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close registry")
		}
	}

	log.Info().Msg("Controller stopped")
}

// Run runs the controller until signaled to stop
func (c *Controller) Run() error {
	// Start controller
	if err := c.Start(); err != nil {
		return err
	}

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("Received signal, shutting down")

	// Stop the controller
	c.Stop()

	return nil
}
