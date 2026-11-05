package telemetry

import (
	"context"
	"fmt"
	"os"

	"github.com/rs/zerolog/log"
	"github.com/yuuki/rpingmesh/internal/config"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// newOTLPExporter builds the OTLP/gRPC metric exporter for cfg. extra is
// appended after the options derived from cfg; tests use it to tune retries.
func newOTLPExporter(ctx context.Context, cfg config.OTLPExporterConfig, extra ...otlpmetricgrpc.Option) (*otlpmetricgrpc.Exporter, error) {
	opts, err := otlpExporterOptions(cfg)
	if err != nil {
		return nil, err
	}
	return otlpmetricgrpc.New(ctx, append(opts, extra...)...)
}

// otlpExporterOptions translates cfg into exporter options.
//
// The transport security is always set explicitly, either plaintext or TLS
// credentials, so the OTEL_EXPORTER_OTLP_* environment variables cannot change
// it: with TLS enabled, OTEL_EXPORTER_OTLP_INSECURE=true does not downgrade
// the connection, because the exporter prefers explicit credentials over the
// insecure flag. A failed TLS handshake fails the export; there is no
// fallback to plaintext.
//
// The CA bundle and the bearer token are read here, once. Changing either
// file takes effect when the process restarts.
func otlpExporterOptions(cfg config.OTLPExporterConfig) ([]otlpmetricgrpc.Option, error) {
	tlsCfg, token, err := cfg.Credentials()
	if err != nil {
		return nil, err
	}

	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(cfg.Endpoint)}
	if tlsCfg == nil {
		// Credentials never returns a token without TLS.
		return append(opts, otlpmetricgrpc.WithInsecure()), nil
	}
	opts = append(opts, otlpmetricgrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	if token != "" {
		warnIfTokenFileExposed(cfg.BearerTokenFile)
		opts = append(opts, otlpmetricgrpc.WithDialOption(
			grpc.WithPerRPCCredentials(bearerTokenCredentials{token: token})))
	}
	return opts, nil
}

// bearerTokenCredentials attaches "authorization: Bearer <token>" to every
// export RPC. It is per-RPC credentials rather than a static header so that
// gRPC enforces RequireTransportSecurity: a client with these credentials
// cannot be built over plaintext, and the token is not sent on a connection
// below privacy-and-integrity security. This is a second guard behind the
// configuration check that rejects a token without TLS.
type bearerTokenCredentials struct {
	token string
}

// GetRequestMetadata implements credentials.PerRPCCredentials.
func (c bearerTokenCredentials) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

// RequireTransportSecurity implements credentials.PerRPCCredentials.
func (bearerTokenCredentials) RequireTransportSecurity() bool {
	return true
}

// String redacts the token, so formatting the credentials with %v or %s
// cannot reveal it.
func (bearerTokenCredentials) String() string {
	return "bearerTokenCredentials{token: REDACTED}"
}

// GoString redacts the token for %#v.
func (c bearerTokenCredentials) GoString() string {
	return c.String()
}

// warnIfTokenFileExposed logs a warning when the bearer token file is
// accessible to users other than its owner and group. It does not refuse the
// file: a deployment may rely on other access controls, and the warning names
// the fix.
func warnIfTokenFileExposed(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		log.Warn().
			Str("otel_collector_bearer_token_file", path).
			Str("mode", fmt.Sprintf("%#o", perm)).
			Msg("OTLP bearer token file is accessible to other users; restrict it to the service account (for example mode 0400) or pass it as a systemd credential")
	}
}
