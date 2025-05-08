package analyzer

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/analyzer/analysis"
	"github.com/yuuki/rpingmesh/internal/analyzer/storage"
	"github.com/yuuki/rpingmesh/internal/config"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"google.golang.org/grpc"
)

// Analyzer represents the RPingMesh analyzer
type Analyzer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	config   *config.Config
	server   *grpc.Server
	storage  *storage.Storage
	analysis *analysis.Engine
	wg       sync.WaitGroup
}

// New creates a new analyzer instance
func New(configPath string) (*Analyzer, error) {
	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())

	// Create storage
	storage, err := storage.NewStorage(cfg.DatabaseURI)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create storage: %w", err)
	}

	// Create analysis engine
	analysisEngine := analysis.NewEngine(storage)

	// Create analyzer
	analyzer := &Analyzer{
		ctx:      ctx,
		cancel:   cancel,
		config:   cfg,
		storage:  storage,
		analysis: analysisEngine,
	}

	return analyzer, nil
}

// Start starts the analyzer server
func (a *Analyzer) Start() error {
	// Create new gRPC server
	a.server = grpc.NewServer()

	// Register service
	agent_analyzer.RegisterAnalyzerServiceServer(a.server, NewService(a.storage, a.analysis))

	// Start server
	listener, err := net.Listen("tcp", a.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	log.Info().Str("addr", a.config.ListenAddr).Msg("Starting gRPC server")

	// Serve in a goroutine
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		if err := a.server.Serve(listener); err != nil {
			log.Error().Err(err).Msg("gRPC server error")
		}
	}()

	// Start analysis tasks
	a.wg.Add(1)
	go a.runAnalysisTasks()

	return nil
}

// runAnalysisTasks runs periodic analysis tasks
func (a *Analyzer) runAnalysisTasks() {
	defer a.wg.Done()

	// Run periodic analysis tasks
	a.analysis.StartPeriodicTasks(a.ctx)
}

// Stop stops the analyzer
func (a *Analyzer) Stop() {
	// Stop gRPC server
	if a.server != nil {
		a.server.GracefulStop()
	}

	// Cancel context
	a.cancel()

	// Wait for all goroutines to finish
	a.wg.Wait()

	// Close storage
	if a.storage != nil {
		if err := a.storage.Close(); err != nil {
			log.Error().Err(err).Msg("Failed to close storage")
		}
	}

	log.Info().Msg("Analyzer stopped")
}

// Run runs the analyzer until signaled to stop
func (a *Analyzer) Run() error {
	// Start analyzer
	if err := a.Start(); err != nil {
		return err
	}

	// Set up signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for signal
	sig := <-sigCh
	log.Info().Str("signal", sig.String()).Msg("Received signal, shutting down")

	// Stop the analyzer
	a.Stop()

	return nil
}
