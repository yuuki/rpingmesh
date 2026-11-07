package registry

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rqlite/gorqlite"
	"github.com/yuuki/rpingmesh/proto/controller_agent"
)

// Fault injection: the registry against an rqlite HTTP API that misbehaves,
// through the real gorqlite client (the other tests use fakeConn). The
// controller serves every RPC from the registry, so a stuck or failing
// rqlite node must surface as an error within the RPC's deadline.

// fakeRqlite serves rqlite's HTTP API from handler and returns a gorqlite
// connection to it. Cluster discovery is disabled, so Open itself sends no
// request and every request comes from the registry call under test.
func fakeRqlite(t *testing.T, handler http.HandlerFunc) *RnicRegistry {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	conn, err := gorqlite.Open(srv.URL + "/?disableClusterDiscovery=true")
	if err != nil {
		t.Fatalf("gorqlite.Open: %v", err)
	}
	t.Cleanup(conn.Close)
	return newTestRegistry(conn)
}

// failingRqlite answers every request with 503, as a node without a leader
// does.
func failingRqlite(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "leadership lost while committing log", http.StatusServiceUnavailable)
}

// registryCalls exercises the write path and a read path.
var registryCalls = map[string]func(context.Context, *RnicRegistry) error{
	"RegisterRNICs": func(ctx context.Context, r *RnicRegistry) error {
		_, err := r.RegisterRNICs(ctx, "agent-1", "10.0.0.1", []*controller_agent.RnicInfo{testRnic("fe80::1")})
		return err
	},
	"GetRNICsByToR": func(ctx context.Context, r *RnicRegistry) error {
		_, err := r.GetRNICsByToR(ctx, "tor-1")
		return err
	},
}

// TestRegistry_HungRqliteHonoursDeadline: an rqlite node that is up but
// never answers (e.g. stuck waiting for a leader) must not hold a registry
// call past the caller's deadline.
func TestRegistry_HungRqliteHonoursDeadline(t *testing.T) {
	release := make(chan struct{})
	reg := fakeRqlite(t, func(w http.ResponseWriter, r *http.Request) {
		// Drain the body first: only then does the server notice the client
		// giving up and cancel r.Context().
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	// Cleanups run last-in first-out: release the handlers before the
	// server's Close waits for them.
	t.Cleanup(func() { close(release) })
	for name, call := range registryCalls {
		t.Run(name, func(t *testing.T) {
			const deadline = 200 * time.Millisecond
			ctx, cancel := context.WithTimeout(context.Background(), deadline)
			defer cancel()

			start := time.Now()
			err := call(ctx, reg)
			elapsed := time.Since(start)

			// gorqlite flattens the cause into its "tried all peers" text,
			// so only the failure itself and its timing are checked.
			if err == nil {
				t.Fatal("a hung rqlite call returned no error")
			}
			// gorqlite's own HTTP timeout is 10s; the caller's deadline
			// must win. The slack absorbs a loaded CI machine.
			if elapsed > deadline+3*time.Second {
				t.Fatalf("returned after %v, deadline was %v", elapsed, deadline)
			}
		})
	}
}

func TestRegistry_RqliteErrorStatusPropagates(t *testing.T) {
	reg := fakeRqlite(t, failingRqlite)
	for name, call := range registryCalls {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := call(ctx, reg); err == nil {
				t.Fatal("a 503 from rqlite was not reported as an error")
			}
		})
	}
}
