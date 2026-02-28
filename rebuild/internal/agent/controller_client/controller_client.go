// Package controller_client provides a gRPC client for communicating with the
// R-Pingmesh controller service. It implements the ControllerClient interface
// defined in the agent package, enabling agent registration and pinglist
// retrieval over gRPC.
package controller_client

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCControllerClient implements the agent.ControllerClient interface using
// gRPC to communicate with the controller service. It wraps a single gRPC
// connection and provides methods for agent registration and pinglist fetching.
//
// NOTE: This type satisfies the agent.ControllerClient interface (GetPinglist).
// A compile-time check is intentionally omitted to avoid a circular import
// between the agent and controller_client packages.
type GRPCControllerClient struct {
	conn   *grpc.ClientConn
	client controller_agent.ControllerServiceClient
	logger zerolog.Logger
}

// NewGRPCControllerClient creates a new gRPC client connected to the controller
// at the given address. The address should be in "host:port" format. The
// connection uses insecure credentials, which is acceptable for internal
// network communication.
func NewGRPCControllerClient(controllerAddr string) (*GRPCControllerClient, error) {
	conn, err := grpc.NewClient(
		controllerAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC client for controller at %s: %w", controllerAddr, err)
	}

	logger := log.With().
		Str("component", "controller_client").
		Str("controller_addr", controllerAddr).
		Logger()

	logger.Info().Msg("Created gRPC controller client")

	return &GRPCControllerClient{
		conn:   conn,
		client: controller_agent.NewControllerServiceClient(conn),
		logger: logger,
	}, nil
}

// Close closes the underlying gRPC connection. It should be called when the
// client is no longer needed to release resources.
func (c *GRPCControllerClient) Close() error {
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			return fmt.Errorf("failed to close gRPC connection: %w", err)
		}
		c.logger.Info().Msg("Closed gRPC controller client connection")
	}
	return nil
}

// RegisterAgent sends an agent registration request to the controller.
// It returns the registration response on success, or an error if the RPC
// fails or the controller rejects the registration.
func (c *GRPCControllerClient) RegisterAgent(
	ctx context.Context,
	req *controller_agent.AgentRegistrationRequest,
) (*controller_agent.AgentRegistrationResponse, error) {
	c.logger.Debug().
		Str("agent_id", req.GetAgentId()).
		Str("agent_ip", req.GetAgentIp()).
		Str("hostname", req.GetHostname()).
		Str("tor_id", req.GetTorId()).
		Int("rnic_count", len(req.GetRnics())).
		Msg("Sending agent registration request")

	resp, err := c.client.RegisterAgent(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("RegisterAgent RPC failed: %w", err)
	}

	if !resp.GetSuccess() {
		c.logger.Warn().
			Str("agent_id", req.GetAgentId()).
			Str("message", resp.GetMessage()).
			Msg("Agent registration rejected by controller")
		return resp, fmt.Errorf("agent registration rejected: %s", resp.GetMessage())
	}

	c.logger.Info().
		Str("agent_id", req.GetAgentId()).
		Str("message", resp.GetMessage()).
		Msg("Agent registration succeeded")

	return resp, nil
}

// GetPinglist fetches a pinglist of the specified type from the controller.
// It builds a PinglistRequest from the provided parameters and returns the
// list of PingTarget entries. This method signature matches the
// agent.ControllerClient interface.
func (c *GRPCControllerClient) GetPinglist(
	ctx context.Context,
	agentID, torID, requesterGID string,
	ptype controller_agent.PinglistType,
) ([]*controller_agent.PingTarget, error) {
	req := &controller_agent.PinglistRequest{
		AgentId:      agentID,
		TorId:        torID,
		RequesterGid: requesterGID,
		Type:         ptype,
	}

	c.logger.Debug().
		Str("agent_id", agentID).
		Str("tor_id", torID).
		Str("requester_gid", requesterGID).
		Str("pinglist_type", ptype.String()).
		Msg("Requesting pinglist from controller")

	resp, err := c.client.GetPinglist(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("GetPinglist RPC failed (type=%s): %w", ptype.String(), err)
	}

	c.logger.Info().
		Str("agent_id", agentID).
		Str("pinglist_type", ptype.String()).
		Int("target_count", len(resp.GetTargets())).
		Msg("Received pinglist from controller")

	return resp.GetTargets(), nil
}
