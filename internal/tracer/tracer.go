package tracer

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/proto/agent_analyzer"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Tracer performs path tracing to diagnose network issues
type Tracer struct {
	traceResults chan *agent_analyzer.PathInfo
	mutex        sync.Mutex
	ctx          context.Context
	periodicWg   sync.WaitGroup
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

// SetContext sets the context for the tracer
func (t *Tracer) SetContext(ctx context.Context) {
	t.ctx = ctx
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
	cmdOutput, isTracepath, err := t.runTraceroute(ctx, targetIP)
	if err != nil {
		return err
	}

	// Parse output based on which command was used
	var hops []*agent_analyzer.PathInfo_Hop
	if isTracepath {
		hops, err = t.parseTracepathOutput(cmdOutput)
	} else {
		hops, err = t.parseTracerouteOutput(cmdOutput)
	}

	if err != nil {
		return err
	}

	// Add hops to path info
	pathInfo.Hops = hops

	// Send result
	t.traceResults <- pathInfo

	// Log which command was used
	cmdName := "traceroute"
	if isTracepath {
		cmdName = "tracepath"
	}

	log.Info().
		Str("targetIP", targetIP).
		Str("command", cmdName).
		Int("hops", len(hops)).
		Msg("Completed path trace")

	return nil
}

// runTraceroute executes the traceroute command
func (t *Tracer) runTraceroute(ctx context.Context, targetIP string) (string, bool, error) {
	// First try traceroute
	cmd := exec.CommandContext(ctx, "traceroute", "-n", "-q", "1", targetIP)

	// Run the command and capture output
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if it's just a non-zero exit code (common with traceroute)
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// If we got output, continue with parsing
			if len(output) > 0 {
				return string(output), false, nil
			}
		}

		// If traceroute command fails (likely not installed), try tracepath instead
		log.Warn().Err(err).Msg("traceroute command failed, trying tracepath")
		cmd = exec.CommandContext(ctx, "tracepath", "-n", targetIP)
		output, err = cmd.CombinedOutput()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				// If we got output, continue with parsing
				if len(output) > 0 {
					return string(output), true, nil
				}
			}
			return "", false, fmt.Errorf("both traceroute and tracepath commands failed: %w", err)
		}
		return string(output), true, nil
	}

	return string(output), false, nil
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

// StartPeriodicTracing starts periodic traceroute to targets from the pinglist
// Returns the number of targets being traced
func (t *Tracer) StartPeriodicTracing(
	ctx context.Context,
	sourceGID string,
	targets []*controller_agent.PingTarget,
	intervalMS uint32,
	maxTargets int,
) int {
	if len(targets) == 0 {
		log.Warn().Msg("No pinglist targets available for traceroute")
		return 0
	}

	// Use up to maxTargets from the pinglist
	targetCount := min(maxTargets, len(targets))

	// Start traceroute for each target
	for i := 0; i < targetCount; i++ {
		target := targets[i]
		fiveTuple := &agent_analyzer.ProbeFiveTuple{
			SrcGid: sourceGID,
			DstGid: target.TargetRnic.Gid,
		}

		// Add a slight delay between starting each traceroute to avoid overloading
		tracerouteInterval := time.Duration(intervalMS) * time.Millisecond

		// Start traceroute goroutine
		t.periodicWg.Add(1)
		go func(ft *agent_analyzer.ProbeFiveTuple, interval time.Duration) {
			defer t.periodicWg.Done()
			// Add small delay to offset the traceroutes
			time.Sleep(time.Duration(rand.Intn(5000)) * time.Millisecond)
			t.TracePeriodically(ctx, ft, interval)
		}(fiveTuple, tracerouteInterval)

		log.Info().
			Uint32("interval_ms", intervalMS).
			Str("target", fiveTuple.DstGid).
			Msg("Started periodic traceroute")
	}

	log.Info().
		Int("target_count", targetCount).
		Uint32("interval_ms", intervalMS).
		Msg("Started periodic traceroute to multiple targets")

	return targetCount
}

// StartPeriodicTracingToLocalhost starts periodic traceroute to localhost as a fallback
func (t *Tracer) StartPeriodicTracingToLocalhost(
	ctx context.Context,
	sourceGID string,
	intervalMS uint32,
) {
	fiveTuple := &agent_analyzer.ProbeFiveTuple{
		SrcGid: sourceGID,
		DstGid: "127.0.0.1",
	}

	tracerouteInterval := time.Duration(intervalMS) * time.Millisecond
	t.periodicWg.Add(1)
	go func() {
		defer t.periodicWg.Done()
		t.TracePeriodically(ctx, fiveTuple, tracerouteInterval)
	}()

	log.Info().
		Uint32("interval_ms", intervalMS).
		Str("target", fiveTuple.DstGid).
		Msg("Started periodic traceroute to localhost (fallback)")
}

// Close cleans up resources
func (t *Tracer) Close() error {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	// Wait for all periodic traceroute goroutines to complete
	t.periodicWg.Wait()

	close(t.traceResults)
	return nil
}

// parseTracepathOutput parses the output of the tracepath command
func (t *Tracer) parseTracepathOutput(output string) ([]*agent_analyzer.PathInfo_Hop, error) {
	lines := strings.Split(output, "\n")
	hops := make([]*agent_analyzer.PathInfo_Hop, 0)

	// Skip the first line (header)
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// Parse line
		hop, err := t.parseTracepathLine(line)
		if err != nil {
			log.Warn().Err(err).Str("line", line).Msg("Error parsing tracepath line")
			continue
		}

		if hop != nil {
			hops = append(hops, hop)
		}
	}

	return hops, nil
}

// parseTracepathLine parses a single line of tracepath output
// Format examples:
// " 1?: [LOCALHOST]     pmtu 1500"
// " 1:  192.168.1.1                                           0.345ms"
// " 2:  10.0.0.1                                              0.554ms asymm  1"
// " 3:  no reply"
func (t *Tracer) parseTracepathLine(line string) (*agent_analyzer.PathInfo_Hop, error) {
	// Skip lines that don't contain IP addresses or RTT values
	if strings.Contains(line, "pmtu") || strings.Contains(line, "no reply") {
		return nil, nil
	}

	// Split by whitespace
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return nil, nil // Skip lines that don't have enough fields
	}

	// Parse hop number (we don't actually use this)
	hopNumStr := fields[0]
	hopNumStr = strings.TrimSuffix(hopNumStr, ":")
	hopNumStr = strings.TrimSuffix(hopNumStr, "?")
	_, err := strconv.Atoi(hopNumStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hop number: %s", fields[0])
	}

	// Parse IP address
	ipStr := fields[1]
	if ipStr == "[LOCALHOST]" {
		ipStr = "127.0.0.1"
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Look for RTT value (ends with ms)
	var rttNs int64 = 0
	for _, field := range fields {
		if strings.HasSuffix(field, "ms") {
			rttStr := strings.TrimSuffix(field, "ms")
			rttFloat, err := strconv.ParseFloat(rttStr, 64)
			if err != nil {
				continue // Just skip this field if we can't parse it
			}
			// Convert ms to ns
			rttNs = int64(rttFloat * 1_000_000)
			break
		}
	}

	return &agent_analyzer.PathInfo_Hop{
		IpAddress: ip.String(),
		RttNs:     rttNs,
	}, nil
}

// Helper function to find minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
