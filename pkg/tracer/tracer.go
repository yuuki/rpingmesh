package tracer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Tracer performs path tracing to diagnose network issues
type Tracer struct {
	traceResults chan *agent_analyzer.PathInfo
	mutex        sync.Mutex
}

// NewTracer creates a new tracer
func NewTracer() *Tracer {
	return &Tracer{
		traceResults: make(chan *agent_analyzer.PathInfo, 100),
	}
}

// GetTraceResults returns the channel where trace results are published
func (t *Tracer) GetTraceResults() <-chan *agent_analyzer.PathInfo {
	return t.traceResults
}

// Trace performs a traceroute to the target IP
func (t *Tracer) Trace(ctx context.Context, fiveTuple *agent_analyzer.ProbeFiveTuple) error {
	// Extract target IP from GID
	ip := net.ParseIP(fiveTuple.DstGid)
	if ip == nil || len(ip) == 0 {
		return fmt.Errorf("invalid destination GID format: %s", fiveTuple.DstGid)
	}

	// Use the IPv4 address if this is an IPv4-mapped IPv6 address
	targetIP := ip.String()
	if ip4 := ip.To4(); ip4 != nil {
		targetIP = ip4.String()
	}

	// Create path info result
	pathInfo := &agent_analyzer.PathInfo{
		FiveTuple: fiveTuple,
		Timestamp: timestamppb.Now(),
		Hops:      make([]*agent_analyzer.PathInfo_Hop, 0),
	}

	// Run traceroute command
	cmdOutput, err := t.runTraceroute(ctx, targetIP)
	if err != nil {
		return err
	}

	// Parse traceroute output
	hops, err := t.parseTracerouteOutput(cmdOutput)
	if err != nil {
		return err
	}

	// Add hops to path info
	pathInfo.Hops = hops

	// Send result
	t.traceResults <- pathInfo

	log.Info().
		Str("targetIP", targetIP).
		Int("hops", len(hops)).
		Msg("Completed traceroute")

	return nil
}

// runTraceroute executes the traceroute command
func (t *Tracer) runTraceroute(ctx context.Context, targetIP string) (string, error) {
	// Create a command with context for cancellation
	cmd := exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", targetIP)

	// Run the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's just a non-zero exit code (common with traceroute)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// If we got output, continue with parsing
			if len(output) > 0 {
				return string(output), nil
			}
		}
		return "", fmt.Errorf("traceroute command failed: %w", err)
	}

	return string(output), nil
}

// parseTracerouteOutput parses the output of the traceroute command
func (t *Tracer) parseTracerouteOutput(output string) ([]*agent_analyzer.PathInfo_Hop, error) {
	lines := strings.Split(output, "\n")
	hops := make([]*agent_analyzer.PathInfo_Hop, 0)

	// Skip the first line (header)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Parse line
		hop, err := t.parseTracerouteLine(line)
		if err != nil {
			log.Warn().Err(err).Str("line", line).Msg("Error parsing traceroute line")
			continue
		}

		hops = append(hops, hop)
	}

	return hops, nil
}

// parseTracerouteLine parses a single line of traceroute output
// Format example: "1  192.168.1.1  0.445 ms"
func (t *Tracer) parseTracerouteLine(line string) (*agent_analyzer.PathInfo_Hop, error) {
	// Split by whitespace
	fields := strings.Fields(line)

	// Need at least 3 fields: hop number, IP, and RTT
	if len(fields) < 3 {
		return nil, fmt.Errorf("invalid traceroute line format: %s", line)
	}

	// Parse hop number (we don't actually use this)
	_, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, fmt.Errorf("invalid hop number: %s", fields[0])
	}

	// Parse IP address
	ipStr := fields[1]
	if ipStr == "*" {
		// For hops that don't respond
		return &agent_analyzer.PathInfo_Hop{
			IpAddress: "*",
			RttNs:     0,
		}, nil
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Parse RTT
	rttStr := fields[2]
	rttFloat, err := strconv.ParseFloat(rttStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid RTT: %s", rttStr)
	}

	// Convert ms to ns
	rttNs := int64(rttFloat * 1_000_000)

	return &agent_analyzer.PathInfo_Hop{
		IpAddress: ip.String(),
		RttNs:     rttNs,
	}, nil
}

// TracePeriodically runs traces periodically to the target
func (t *Tracer) TracePeriodically(ctx context.Context, fiveTuple *agent_analyzer.ProbeFiveTuple, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run initial trace
	err := t.Trace(ctx, fiveTuple)
	if err != nil {
		log.Error().Err(err).Msg("Initial trace failed")
	}

	// Run subsequent traces
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := t.Trace(ctx, fiveTuple)
			if err != nil {
				log.Error().Err(err).Msg("Periodic trace failed")
			}
		}
	}
}

// Close cleans up resources
func (t *Tracer) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	close(t.traceResults)
	return nil
}
