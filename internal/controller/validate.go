package controller

import (
	"fmt"
	"net"
	"time"

	"github.com/yuuki/rpingmesh/internal/probe"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Input bounds for the controller's RPCs. The controller may run without
// client authentication (tls_mode disabled or tls), so every value a request
// carries is stored or retained only after it passes these checks: they keep
// one request from writing unbounded rows or strings into the registry or the
// analyzer's in-memory window ring.
const (
	// MaxRecvMsgBytes caps one inbound gRPC message. The largest legitimate
	// requests (a GetTargetRnicInfo of MaxTargetRnicInfoGIDs GIDs, or a
	// ProbeAnalysisReport of an agent's 256-summary batch) stay well below it.
	MaxRecvMsgBytes = 1 << 20

	// MaxRnicsPerAgent caps the RNICs one RegisterAgent may register.
	MaxRnicsPerAgent = 256

	// MaxSummariesPerReport caps the summaries one ProbeAnalysisReport may
	// carry. Agents send at most 256 per report.
	MaxSummariesPerReport = 1024

	// maxFieldLen caps every free-form string field (agent_id, hostname,
	// tor_id, plane_id, device and netdev names).
	maxFieldLen = 255

	// maxGIDLen caps a GID string; the longest textual GID (an IPv6
	// address, optionally zero-padded) is 39 characters.
	maxGIDLen = 64

	// maxReportFutureSkew bounds how far in the future a reported window may
	// start. Summaries beyond it would sort as the newest windows and evict
	// the genuine ones from the retention ring.
	maxReportFutureSkew = 10 * time.Minute
)

func checkLen(field, v string, limit int) error {
	if len(v) > limit {
		return fmt.Errorf("%s is too long (%d bytes, max %d)", field, len(v), limit)
	}
	return nil
}

// validateGID checks that gid is a parseable GID of bounded length.
func validateGID(field, gid string) error {
	if err := checkLen(field, gid, maxGIDLen); err != nil {
		return err
	}
	if _, err := probe.ParseGID(gid); err != nil {
		return fmt.Errorf("%s %q is not a valid GID", field, gid)
	}
	return nil
}

// validateIP checks that ip is empty or a parseable IP address.
func validateIP(field, ip string) error {
	if ip == "" {
		return nil
	}
	if err := checkLen(field, ip, maxGIDLen); err != nil {
		return err
	}
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("%s %q is not a valid IP address", field, ip)
	}
	return nil
}

// validateRegistration checks the identity and bounds of a RegisterAgent
// request before anything is written to the registry.
func validateRegistration(req *controller_agent.AgentRegistrationRequest) error {
	if err := checkLen("agent_id", req.GetAgentId(), maxFieldLen); err != nil {
		return err
	}
	if err := checkLen("hostname", req.GetHostname(), maxFieldLen); err != nil {
		return err
	}
	if err := checkLen("tor_id", req.GetTorId(), maxFieldLen); err != nil {
		return err
	}
	if err := validateIP("agent_ip", req.GetAgentIp()); err != nil {
		return err
	}
	rnics := req.GetRnics()
	if len(rnics) > MaxRnicsPerAgent {
		return fmt.Errorf("too many rnics: %d (max %d)", len(rnics), MaxRnicsPerAgent)
	}
	for i, rnic := range rnics {
		if rnic == nil {
			return fmt.Errorf("rnic %d is empty", i)
		}
		if err := validateGID(fmt.Sprintf("rnic %d gid", i), rnic.GetGid()); err != nil {
			return err
		}
		if err := validateIP(fmt.Sprintf("rnic %d ip_address", i), rnic.GetIpAddress()); err != nil {
			return err
		}
		for _, f := range []struct{ name, v string }{
			{"tor_id", rnic.GetTorId()},
			{"plane_id", rnic.GetPlaneId()},
			{"device_name", rnic.GetDeviceName()},
			{"netdev", rnic.GetNetdev()},
		} {
			if err := checkLen(fmt.Sprintf("rnic %d %s", i, f.name), f.v, maxFieldLen); err != nil {
				return err
			}
		}
	}
	return nil
}

// summaryAcceptable reports whether one reported path summary may be
// ingested: bounded strings and a window that does not start in the future
// (beyond clock skew). Rejected summaries are dropped individually so one bad
// record does not cost the agent its whole batch.
func summaryAcceptable(s *controller_agent.PathSummary, now time.Time) bool {
	if s == nil {
		return false
	}
	if len(s.GetSourceGid()) > maxGIDLen || len(s.GetTargetGid()) > maxGIDLen {
		return false
	}
	if len(s.GetSourceTorId()) > maxFieldLen || len(s.GetTargetTorId()) > maxFieldLen {
		return false
	}
	limit := uint64(now.Add(maxReportFutureSkew).UnixNano())
	return s.GetWindowStartUnixNs() <= limit
}
