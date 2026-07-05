// Package controller_client provides a gRPC client for communicating with the
// R-Pingmesh controller service. It implements the ControllerClient interface
// defined in the agent package, enabling agent registration and pinglist
// retrieval over gRPC.
package controller_client

import (
	"context"
	"fmt"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/rebuild/internal/config"
	"github.com/yuuki/rpingmesh/rebuild/proto/controller_agent"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// rpcTimeout bounds every individual RPC to the controller. Without this,
// a hung or unreachable controller would block the caller indefinitely:
// for RegisterAgent that stalls agent startup/heartbeat, and for
// GetPinglist that stalls ClusterMonitor.Stop() (which waits for the
// in-flight fetch to return before the monitor goroutine can exit).
const rpcTimeout = 10 * time.Second

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

// NewGRPCControllerClient creates a new gRPC client connected to the
// controller at the given address. The address should be in "host:port"
// format. tlsCfg selects the transport credentials: a nil tlsCfg, or one
// with Mode == config.TLSModeDisabled (or the empty string), uses insecure
// credentials, preserving the original plaintext behavior for backward
// compatibility; a non-nil tlsCfg with Mode == tls or mtls builds TLS
// transport credentials instead.
func NewGRPCControllerClient(controllerAddr string, tlsCfg *config.TLSClientConfig) (*GRPCControllerClient, error) {
	mode := config.TLSModeDisabled
	if tlsCfg != nil && tlsCfg.Mode != "" {
		mode = tlsCfg.Mode
	}

	var transportCreds credentials.TransportCredentials
	if mode == config.TLSModeDisabled {
		log.Warn().Str("controller_addr", controllerAddr).
			Msg("gRPC controller client using tls_mode=disabled: controller-agent traffic is plaintext and unauthenticated; set tls_mode to tls or mtls for production deployments")
		transportCreds = insecure.NewCredentials()
	} else {
		tlsConfig, err := config.ClientTLSConfig(tlsCfg.Mode, tlsCfg.CertFile, tlsCfg.KeyFile, tlsCfg.CAFile, tlsCfg.ServerName)
		if err != nil {
			return nil, fmt.Errorf("failed to build client TLS configuration for controller at %s: %w", controllerAddr, err)
		}
		transportCreds = credentials.NewTLS(tlsConfig)
	}

	conn, err := grpc.NewClient(
		controllerAddr,
		grpc.WithTransportCredentials(transportCreds),
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

	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := c.client.RegisterAgent(rpcCtx, req)
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

	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := c.client.GetPinglist(rpcCtx, req)
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

// ReportProbeAnalysis sends a batch of window-aggregated per-path summaries to
// the controller's analyzer. It is best-effort: the caller (the agent's
// analysis reporter) drops the batch on any error rather than retrying, so a
// slow or unreachable controller never stalls active probing. The RPC is
// bounded by rpcTimeout like the other calls.
func (c *GRPCControllerClient) ReportProbeAnalysis(
	ctx context.Context,
	report *controller_agent.ProbeAnalysisReport,
) (*controller_agent.ProbeAnalysisAck, error) {
	c.logger.Debug().
		Str("agent_id", report.GetAgentId()).
		Int("summary_count", len(report.GetSummaries())).
		Msg("Reporting probe analysis to controller")

	rpcCtx, cancel := context.WithTimeout(ctx, rpcTimeout)
	defer cancel()

	resp, err := c.client.ReportProbeAnalysis(rpcCtx, report)
	if err != nil {
		return nil, fmt.Errorf("ReportProbeAnalysis RPC failed: %w", err)
	}

	c.logger.Debug().
		Str("agent_id", report.GetAgentId()).
		Bool("accepted", resp.GetAccepted()).
		Uint32("sla_violations", resp.GetSlaViolations()).
		Msg("Probe analysis reported")

	return resp, nil
}
