package registry

import (
	"context"
	"errors"
	"fmt"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// RnicRegistry manages RNIC information
type RnicRegistry struct {
	dbClient interface{} // This would be a rqlite client in production
}

// NewRnicRegistry creates a new RNIC registry
func NewRnicRegistry(dbURI string) (*RnicRegistry, error) {
	// In a real implementation, this would connect to rqlite
	// For now, we'll just create a stub

	log.Info().Str("dbURI", dbURI).Msg("Initializing RNIC registry")

	// TODO: Implement actual rqlite connection
	return &RnicRegistry{
		dbClient: nil,
	}, nil
}

// Close closes the registry
func (r *RnicRegistry) Close() error {
	// Close database connection
	return nil
}

// RegisterRNIC registers an RNIC with the registry
func (r *RnicRegistry) RegisterRNIC(
	ctx context.Context,
	agentID string,
	agentIP string,
	rnic *controller_agent.RnicInfo,
) error {
	log.Info().
		Str("agentID", agentID).
		Str("rnicGID", rnic.Gid).
		Msg("Registering RNIC")

	// TODO: Implement actual registration in the database
	return nil
}

// GetRNICsByToR gets all RNICs in a ToR
func (r *RnicRegistry) GetRNICsByToR(
	ctx context.Context,
	torID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Info().Str("torID", torID).Msg("Getting RNICs by ToR")

	// TODO: Implement actual database query
	// For now return empty list
	return []*controller_agent.RnicInfo{}, nil
}

// GetSampleRNICsFromOtherToRs gets sample RNICs from other ToRs
func (r *RnicRegistry) GetSampleRNICsFromOtherToRs(
	ctx context.Context,
	excludeTorID string,
) ([]*controller_agent.RnicInfo, error) {
	log.Info().Str("excludeTorID", excludeTorID).Msg("Getting sample RNICs from other ToRs")

	// TODO: Implement actual database query
	// For now return empty list
	return []*controller_agent.RnicInfo{}, nil
}

// GetRNICInfo gets RNIC info by IP or GID
func (r *RnicRegistry) GetRNICInfo(
	ctx context.Context,
	targetIP string,
	targetGID string,
) (*controller_agent.RnicInfo, error) {
	log.Info().
		Str("targetIP", targetIP).
		Str("targetGID", targetGID).
		Msg("Getting RNIC info")

	if targetIP == "" && targetGID == "" {
		return nil, errors.New("either targetIP or targetGID must be provided")
	}

	// TODO: Implement actual database query
	// For now return nil
	return nil, fmt.Errorf("RNIC not found")
}
