package registry

import (
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/yuuki/rpingmesh/internal/config"
)

// FuzzRedactDatabaseURI checks config.RedactDatabaseURI against the parser
// that actually uses the URI: whatever password pgx finds in a PostgreSQL URI
// must not survive the redaction that the controller's startup log applies.
func FuzzRedactDatabaseURI(f *testing.F) {
	// The password must come from the URI alone. Setenv restores the
	// environment for the package's other tests.
	for _, env := range []string{"PGPASSWORD", "PGSERVICE", "PGSERVICEFILE"} {
		f.Setenv(env, "")
	}
	f.Setenv("PGPASSFILE", os.DevNull)
	for _, seed := range []string{
		"postgres://rpm:s3cret@db.example/rpingmesh",
		"postgres://rpm:2024#Spring@db.example/rpingmesh",
		"postgres://rpm:?s3cret@db.example/rpingmesh",
		"postgres://rpm:42?s3cret@db.example/rpingmesh",
		"postgres://rpm:s3%23cret@db.example/rpingmesh",
		"postgresql://db.example/rpingmesh?user=rpm&password=s3;cret",
		"postgres://db.example/rpingmesh?pass%77ord=s3cret&sslmode=disable",
		"postgres://rpm:s3cret@[2001:db8::1]:5432,[2001:db8::2]:5432/rpingmesh",
		"postgres://rpm:s3/cret@db.example/rpingmesh",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, uri string) {
		cfg, err := pgconn.ParseConfig(uri)
		if err != nil {
			return
		}
		pw := cfg.Password
		// A short password, or one that also spells other parts of the URI
		// (a host, a user), would match the redacted text by coincidence.
		if len(pw) < 4 || strings.Count(uri, pw) != 1 {
			return
		}
		if redacted := config.RedactDatabaseURI(uri); strings.Contains(redacted, pw) {
			t.Fatalf("RedactDatabaseURI(%q) = %q keeps the password %q", uri, redacted, pw)
		}
	})
}
