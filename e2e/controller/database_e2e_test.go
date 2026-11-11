package controller

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// databaseURI returns the URI of the database the Controller under test
// uses, in database_uri form: DATABASE_URI, else RQLITE_URL (its earlier
// name, rqlite only), else a local rqlite.
func databaseURI() string {
	if uri := os.Getenv("DATABASE_URI"); uri != "" {
		return uri
	}
	if uri := os.Getenv("RQLITE_URL"); uri != "" {
		return uri
	}
	return "http://localhost:4001"
}

// usesPostgres reports whether databaseURI is a PostgreSQL database.
func usesPostgres() bool {
	uri := strings.ToLower(databaseURI())
	return strings.HasPrefix(uri, "postgres://") || strings.HasPrefix(uri, "postgresql://")
}

// cleanDatabase deletes all rows from the rnics table. This ensures test
// isolation when tests share a single database.
func cleanDatabase(t *testing.T) {
	t.Helper()
	executeSQL(t, "DELETE FROM rnics")
}

// executeSQL runs statements directly against the Controller's database, in
// order; the first failing statement fails the test.
func executeSQL(t *testing.T, stmts ...string) {
	t.Helper()
	if usesPostgres() {
		executePostgres(t, stmts...)
		return
	}
	executeRqlite(t, stmts...)
}

// executePostgres runs statements in one PostgreSQL transaction.
func executePostgres(t *testing.T, stmts ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, databaseURI())
	if err != nil {
		t.Fatalf("connect to PostgreSQL: %v", err)
	}
	defer conn.Close(ctx)
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, stmt := range stmts {
		if _, err := tx.Exec(ctx, stmt); err != nil {
			t.Fatalf("statement %q failed: %v", stmt, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

// executeRqlite runs statements through the rqlite HTTP API as one request.
func executeRqlite(t *testing.T, stmts ...string) {
	t.Helper()
	payload := make([][]string, len(stmts))
	for i, s := range stmts {
		payload[i] = []string{s}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal statements: %v", err)
	}
	resp, err := http.Post(databaseURI()+"/db/execute", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("execute %v: %v", stmts, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("execute %v: HTTP %d", stmts, resp.StatusCode)
	}
	var out struct {
		Results []struct {
			Error string `json:"error"`
		} `json:"results"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode rqlite response: %v", err)
	}
	for i, r := range out.Results {
		if r.Error != "" {
			t.Fatalf("statement %q failed: %s", stmts[i], r.Error)
		}
	}
}
