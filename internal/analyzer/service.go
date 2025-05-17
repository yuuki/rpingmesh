package analyzer

import (
	"context"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/analyzer/analysis"
	"github.com/yuuki/rpingmesh/internal/analyzer/storage"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
)

// Service implements the AnalyzerService gRPC service
type Service struct {
	agent_analyzer.UnimplementedAnalyzerServiceServer
	storage  *storage.Storage
	analysis *analysis.Engine
}

// NewService creates a new analyzer service
func NewService(storage *storage.Storage, analysis *analysis.Engine) *Service {
	return &Service{
		storage:  storage,
		analysis: analysis,
	}
}

// UploadData handles data uploads from agents
func (s *Service) UploadData(ctx context.Context, req *agent_analyzer.UploadDataRequest) (*agent_analyzer.UploadDataResponse, error) {
	log.Info().
		Str("agentID", req.AgentId).
		Int("probeResults", len(req.ProbeResults)).
		Int("pathInfo", len(req.PathInfos)).
		Msg("Received data upload")

	// Store probe results
	for _, result := range req.ProbeResults {
		if err := s.storage.StoreProbeResult(ctx, result); err != nil {
			log.Error().
				Err(err).
				Str("agentID", req.AgentId).
				Msg("Failed to store probe result")
		}
	}

	// Store path info
	for _, path := range req.PathInfos {
		if err := s.storage.StorePathInfo(ctx, path); err != nil {
			log.Error().
				Err(err).
				Str("agentID", req.AgentId).
				Msg("Failed to store path info")
		}
	}

	// Trigger analysis if needed
	if len(req.ProbeResults) > 0 {
		go s.analysis.AnalyzeNewData(req.AgentId, req.ProbeResults)
	}

	return &agent_analyzer.UploadDataResponse{
		Success: true,
		Message: "Data uploaded successfully",
	}, nil
}
