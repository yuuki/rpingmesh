package analysis

import (
	"context"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/analyzer/storage"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
)

// Engine represents the analysis engine
type Engine struct {
	storage *storage.Storage
}

// NewEngine creates a new analysis engine
func NewEngine(storage *storage.Storage) *Engine {
	return &Engine{
		storage: storage,
	}
}

// StartPeriodicTasks starts periodic analysis tasks
func (e *Engine) StartPeriodicTasks(ctx context.Context) {
	// Run anomaly detection every minute
	anomalyTicker := time.NewTicker(1 * time.Minute)
	defer anomalyTicker.Stop()

	// Run SLA reporting every hour
	slaTicker := time.NewTicker(1 * time.Hour)
	defer slaTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Msg("Stopping periodic analysis tasks")
			return
		case <-anomalyTicker.C:
			e.detectAnomalies()
		case <-slaTicker.C:
			e.generateSLAReport()
		}
	}
}

// AnalyzeNewData analyzes new data uploaded by an agent
func (e *Engine) AnalyzeNewData(agentID string, probeResults []*agent_analyzer.ProbeResult) {
	log.Info().
		Str("agentID", agentID).
		Int("resultCount", len(probeResults)).
		Msg("Analyzing new data")

	// Check for timeouts in new data
	timeoutCount := 0
	for _, result := range probeResults {
		if result.Status == agent_analyzer.ProbeResult_TIMEOUT {
			timeoutCount++
		}
	}

	// If timeout rate is high, log warning
	if float64(timeoutCount)/float64(len(probeResults)) > 0.1 {
		log.Warn().
			Str("agentID", agentID).
			Int("timeouts", timeoutCount).
			Int("total", len(probeResults)).
			Msg("High timeout rate detected")
	}
}

// detectAnomalies detects anomalies in the data
func (e *Engine) detectAnomalies() {
	log.Info().Msg("Running anomaly detection")

	// TODO: Implement anomaly detection
	// 1. Query data from storage
	// 2. Apply anomaly detection algorithms
	// 3. Generate alerts if needed
}

// generateSLAReport generates an SLA report
func (e *Engine) generateSLAReport() {
	log.Info().Msg("Generating SLA report")

	// TODO: Implement SLA reporting
	// 1. Query data from storage
	// 2. Calculate SLA metrics
	// 3. Generate report
}
