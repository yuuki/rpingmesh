package config

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
	"github.com/yuuki/rpingmesh/internal/testutil/tlscerts"
)

const testOTLPToken = "otlp-config-test-token"

// writeSecret writes content to a 0600 file inside t.TempDir() and returns
// its path.
func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	return path
}

// TestOTLPExporterConfig_PlaintextDefault pins the backward-compatible
// default: no TLS settings yield plaintext and no token.
func TestOTLPExporterConfig_PlaintextDefault(t *testing.T) {
	tlsCfg, token, err := OTLPExporterConfig{Endpoint: "localhost:4317"}.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if tlsCfg != nil || token != "" {
		t.Errorf("Credentials = (%v, %q), want plaintext without a token", tlsCfg, token)
	}
}

// TestOTLPExporterConfig_TLSOnlySettingsRequireTLS verifies that settings
// that only take effect with TLS are rejected without it, the bearer token
// above all, so the configuration cannot suggest a protection it lacks.
func TestOTLPExporterConfig_TLSOnlySettingsRequireTLS(t *testing.T) {
	tests := []struct {
		name    string
		cfg     OTLPExporterConfig
		wantErr string
	}{
		{"bearer token", OTLPExporterConfig{BearerTokenFile: writeSecret(t, testOTLPToken)}, "otel_collector_bearer_token_file requires otel_collector_tls_enabled"},
		{"CA file", OTLPExporterConfig{CAFile: "/etc/ssl/ca.pem"}, "otel_collector_tls_ca_file is set but otel_collector_tls_enabled is false"},
		{"server name", OTLPExporterConfig{ServerName: "collector.example"}, "otel_collector_tls_server_name is set but otel_collector_tls_enabled is false"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.cfg.Endpoint = "localhost:4317"
			checkErr(t, tt.cfg.Validate(), tt.wantErr)
		})
	}
}

// TestOTLPExporterConfig_TLSSystemRoots verifies that TLS without a CA file
// verifies against the system roots and the endpoint's host.
func TestOTLPExporterConfig_TLSSystemRoots(t *testing.T) {
	tlsCfg, token, err := OTLPExporterConfig{Endpoint: "collector.example:4317", TLSEnabled: true}.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if tlsCfg == nil {
		t.Fatal("Credentials returned no TLS config with TLS enabled")
	}
	if tlsCfg.RootCAs != nil {
		t.Error("RootCAs is set, want nil (system roots)")
	}
	if tlsCfg.ServerName != "" {
		t.Errorf("ServerName = %q, want empty (host of the endpoint)", tlsCfg.ServerName)
	}
	if tlsCfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify is set")
	}
	if tlsCfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion = %#x, want TLS 1.2", tlsCfg.MinVersion)
	}
	if token != "" {
		t.Errorf("token = %q, want none", token)
	}
}

// TestOTLPExporterConfig_TLSCustomCAAndToken verifies that a CA file, a
// server name and a token file are all loaded.
func TestOTLPExporterConfig_TLSCustomCAAndToken(t *testing.T) {
	certs := tlscerts.WriteFileSet(t)
	cfg := OTLPExporterConfig{
		Endpoint:        "192.0.2.10:4317",
		TLSEnabled:      true,
		CAFile:          certs.CAFile,
		ServerName:      "collector.example",
		BearerTokenFile: writeSecret(t, testOTLPToken+"\n"),
	}
	tlsCfg, token, err := cfg.Credentials()
	if err != nil {
		t.Fatalf("Credentials: %v", err)
	}
	if tlsCfg.RootCAs == nil {
		t.Error("RootCAs is nil, want the CA file's pool")
	}
	if tlsCfg.ServerName != "collector.example" {
		t.Errorf("ServerName = %q, want collector.example", tlsCfg.ServerName)
	}
	if token != testOTLPToken {
		t.Errorf("token = %q, want %q", token, testOTLPToken)
	}
}

// TestOTLPExporterConfig_InvalidCAFile verifies that a missing or unparsable
// CA bundle is rejected and named.
func TestOTLPExporterConfig_InvalidCAFile(t *testing.T) {
	notPEM := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing": filepath.Join(t.TempDir(), "missing.pem"),
		"not PEM": notPEM,
	} {
		t.Run(name, func(t *testing.T) {
			cfg := OTLPExporterConfig{Endpoint: "localhost:4317", TLSEnabled: true, CAFile: path}
			checkErr(t, cfg.Validate(), "otel_collector_tls_ca_file")
		})
	}
}

// TestReadBearerTokenFile verifies the accepted token format and that every
// failure names the key and file without echoing the file's contents.
func TestReadBearerTokenFile(t *testing.T) {
	t.Run("trims surrounding whitespace", func(t *testing.T) {
		got, err := readBearerTokenFile(writeSecret(t, "  "+testOTLPToken+"\r\n"))
		if err != nil {
			t.Fatalf("readBearerTokenFile: %v", err)
		}
		if got != testOTLPToken {
			t.Errorf("token = %q, want %q", got, testOTLPToken)
		}
	})

	secret := "s3cr3t-value"
	tests := []struct {
		name    string
		path    string
		wantErr string
	}{
		{"missing file", filepath.Join(t.TempDir(), "missing"), "no such file"},
		{"empty", writeSecret(t, ""), "file is empty"},
		{"whitespace only", writeSecret(t, " \n\t\n"), "file is empty"},
		{"Bearer scheme included", writeSecret(t, "Bearer "+secret), "without the \"Bearer\" scheme"},
		{"embedded newline", writeSecret(t, secret+"\n"+secret), "whitespace, control or non-ASCII"},
		{"control character", writeSecret(t, secret+"\x00"), "whitespace, control or non-ASCII"},
		{"non-ASCII", writeSecret(t, secret+"é"), "whitespace, control or non-ASCII"},
		{"oversized", writeSecret(t, strings.Repeat("a", maxBearerTokenFileBytes+1)), "larger than"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := readBearerTokenFile(tt.path)
			checkErr(t, err, tt.wantErr)
			if err == nil {
				return
			}
			if !strings.Contains(err.Error(), "otel_collector_bearer_token_file") || !strings.Contains(err.Error(), tt.path) {
				t.Errorf("error %q does not name the key and the file", err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Errorf("error %q reveals the file's contents", err)
			}
		})
	}

	// A relative value is most likely the token itself, typed into the path
	// key: it is rejected without being echoed.
	t.Run("relative path is not echoed", func(t *testing.T) {
		_, err := readBearerTokenFile(secret)
		checkErr(t, err, "otel_collector_bearer_token_file must be an absolute path")
		if err != nil && strings.Contains(err.Error(), secret) {
			t.Errorf("error %q reveals the value", err)
		}
	})

	t.Run("permission denied", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads files regardless of their mode")
		}
		path := writeSecret(t, secret)
		if err := os.Chmod(path, 0o000); err != nil {
			t.Fatal(err)
		}
		_, err := readBearerTokenFile(path)
		checkErr(t, err, "permission denied")
	})
}

// TestOTLPExporterConfig_EnvAuthorizationHeader verifies that an
// authorization header set through the OpenTelemetry environment variables,
// which the exporter attaches to every request, cannot bypass the rule that
// no token is sent over plaintext, nor duplicate the token file's token.
func TestOTLPExporterConfig_EnvAuthorizationHeader(t *testing.T) {
	const envSecret = "env-secret-value"
	tokenFile := writeSecret(t, testOTLPToken)
	tests := []struct {
		name    string
		env     string
		value   string
		cfg     OTLPExporterConfig
		wantErr string
	}{
		{"plaintext", "OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20" + envSecret,
			OTLPExporterConfig{}, "OTEL_EXPORTER_OTLP_HEADERS sets an authorization header, which would be sent over plaintext"},
		{"plaintext, metrics variable, padded key", "OTEL_EXPORTER_OTLP_METRICS_HEADERS", "x-tenant=a, authorization =" + envSecret,
			OTLPExporterConfig{}, "OTEL_EXPORTER_OTLP_METRICS_HEADERS sets an authorization header"},
		{"TLS with token file", "OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20" + envSecret,
			OTLPExporterConfig{TLSEnabled: true, BearerTokenFile: tokenFile}, "in addition to otel_collector_bearer_token_file"},
		{"TLS without token file", "OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer%20" + envSecret,
			OTLPExporterConfig{TLSEnabled: true}, ""},
		// Other headers keep working in plaintext, as before.
		{"plaintext, other headers", "OTEL_EXPORTER_OTLP_HEADERS", "x-scope-orgid=tenant-a,x-authorization-hint=1",
			OTLPExporterConfig{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(tt.env, tt.value)
			tt.cfg.Endpoint = "localhost:4317"
			err := tt.cfg.Validate()
			checkErr(t, err, tt.wantErr)
			if err != nil && strings.Contains(err.Error(), envSecret) {
				t.Errorf("error %q reveals the header value", err)
			}
		})
	}
}

// TestLoadConfig_OTLPTLSEnabledIsStrict verifies that the TLS switch accepts
// only boolean values: viper would read "yes" (a string in YAML 1.2) or "on"
// as false, silently exporting in plaintext.
func TestLoadConfig_OTLPTLSEnabledIsStrict(t *testing.T) {
	const wantErr = "otel_collector_tls_enabled must be true or false"
	type result struct {
		tls bool
		err error
	}
	// load loads both binaries' configuration from path (and the
	// environment), without flags.
	load := func(path string) map[string]result {
		out := map[string]result{}
		if agent, err := LoadAgentConfig(path, nil); err != nil {
			out["agent"] = result{err: err}
		} else {
			out["agent"] = result{tls: agent.OtelCollectorTLSEnabled}
		}
		if controller, err := LoadControllerConfig(path, nil); err != nil {
			out["controller"] = result{err: err}
		} else {
			out["controller"] = result{tls: controller.OtelCollectorTLSEnabled}
		}
		return out
	}

	for _, value := range []string{"yes", "on", `"enabled"`, "Yes"} {
		t.Run("YAML "+value, func(t *testing.T) {
			path := writeYAML(t, "config.yaml", "otel_collector_tls_enabled: "+value+"\n")
			for name, got := range load(path) {
				t.Run(name, func(t *testing.T) { checkErr(t, got.err, wantErr) })
			}
		})
	}
	t.Run("env on", func(t *testing.T) {
		t.Setenv("RPINGMESH_OTEL_COLLECTOR_TLS_ENABLED", "on")
		for name, got := range load("") {
			t.Run(name, func(t *testing.T) { checkErr(t, got.err, wantErr) })
		}
	})

	for _, tc := range []struct {
		name string
		yaml string
		env  string
		want bool
	}{
		{name: "YAML true", yaml: "otel_collector_tls_enabled: true\n", want: true},
		{name: "YAML false", yaml: "otel_collector_tls_enabled: false\n", want: false},
		{name: "env 1", env: "1", want: true},
		{name: "env FALSE", env: "FALSE", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := ""
			if tc.yaml != "" {
				path = writeYAML(t, "config.yaml", tc.yaml)
			}
			if tc.env != "" {
				t.Setenv("RPINGMESH_OTEL_COLLECTOR_TLS_ENABLED", tc.env)
			}
			for name, got := range load(path) {
				if got.err != nil || got.tls != tc.want {
					t.Errorf("%s: TLSEnabled = %v, err = %v; want %v, nil", name, got.tls, got.err, tc.want)
				}
			}
		})
	}

	t.Run("flag", func(t *testing.T) {
		agentFlags := pflag.NewFlagSet("agent", pflag.ContinueOnError)
		BindAgentFlags(agentFlags)
		controllerFlags := pflag.NewFlagSet("controller", pflag.ContinueOnError)
		BindControllerFlags(controllerFlags)
		for name, flags := range map[string]*pflag.FlagSet{"agent": agentFlags, "controller": controllerFlags} {
			if err := flags.Parse([]string{"--otel-collector-tls-enabled"}); err != nil {
				t.Fatalf("%s: parse flags: %v", name, err)
			}
		}
		agent, err := LoadAgentConfig("", agentFlags)
		if err != nil || !agent.OtelCollectorTLSEnabled {
			t.Errorf("agent: TLSEnabled = %v, err = %v; want true, nil", agent != nil && agent.OtelCollectorTLSEnabled, err)
		}
		controller, err := LoadControllerConfig("", controllerFlags)
		if err != nil || !controller.OtelCollectorTLSEnabled {
			t.Errorf("controller: TLSEnabled = %v, err = %v; want true, nil", controller != nil && controller.OtelCollectorTLSEnabled, err)
		}
	})
}

// TestLoadAgentConfig_OTLPExporter verifies the agent's keys from YAML and
// their environment overrides, and that OTLPExporter assembles them.
func TestLoadAgentConfig_OTLPExporter(t *testing.T) {
	certs := tlscerts.WriteFileSet(t)
	tokenFile := writeSecret(t, testOTLPToken)
	path := writeYAML(t, "agent.yaml", `otel_collector_addr: "192.0.2.10:4317"
otel_collector_tls_enabled: true
otel_collector_tls_ca_file: "`+certs.CAFile+`"
otel_collector_tls_server_name: "collector.example"
`)
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_BEARER_TOKEN_FILE", tokenFile)

	cfg, err := LoadAgentConfig(path, nil)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	want := OTLPExporterConfig{
		Endpoint:        "192.0.2.10:4317",
		TLSEnabled:      true,
		CAFile:          certs.CAFile,
		ServerName:      "collector.example",
		BearerTokenFile: tokenFile,
	}
	if got := cfg.OTLPExporter(); got != want {
		t.Errorf("OTLPExporter() = %+v, want %+v", got, want)
	}
}

// TestLoadControllerConfig_OTLPExporter does the same for the controller,
// whose analyzer exports through the same settings. The OTLP keys are
// independent of the controller's tls_mode, which stays disabled here.
func TestLoadControllerConfig_OTLPExporter(t *testing.T) {
	certs := tlscerts.WriteFileSet(t)
	tokenFile := writeSecret(t, testOTLPToken)
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_ADDR", "collector.example:4317")
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_TLS_ENABLED", "true")
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_TLS_CA_FILE", certs.CAFile)
	t.Setenv("RPINGMESH_OTEL_COLLECTOR_BEARER_TOKEN_FILE", tokenFile)

	cfg, err := LoadControllerConfig("", nil)
	if err != nil {
		t.Fatalf("LoadControllerConfig: %v", err)
	}
	if cfg.TLSMode != TLSModeDisabled {
		t.Errorf("tls_mode = %q, want %q", cfg.TLSMode, TLSModeDisabled)
	}
	want := OTLPExporterConfig{
		Endpoint:        "collector.example:4317",
		TLSEnabled:      true,
		CAFile:          certs.CAFile,
		BearerTokenFile: tokenFile,
	}
	if got := cfg.OTLPExporter(); got != want {
		t.Errorf("OTLPExporter() = %+v, want %+v", got, want)
	}
}

// TestLoadConfig_OTLPExporterDefaults pins the defaults of both binaries:
// plaintext, no CA, no server name, no token.
func TestLoadConfig_OTLPExporterDefaults(t *testing.T) {
	agent, err := LoadAgentConfig("", nil)
	if err != nil {
		t.Fatalf("LoadAgentConfig: %v", err)
	}
	controller, err := LoadControllerConfig("", nil)
	if err != nil {
		t.Fatalf("LoadControllerConfig: %v", err)
	}
	for name, got := range map[string]OTLPExporterConfig{
		"agent":      agent.OTLPExporter(),
		"controller": controller.OTLPExporter(),
	} {
		if want := (OTLPExporterConfig{Endpoint: "localhost:4317"}); got != want {
			t.Errorf("%s OTLPExporter() = %+v, want %+v", name, got, want)
		}
	}
}

// TestLoadConfig_RejectsInvalidOTLPSecurity verifies that both binaries
// refuse to start with a token but without TLS, or with an unreadable token
// file, and that the load error does not reveal the token.
func TestLoadConfig_RejectsInvalidOTLPSecurity(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "token without TLS",
			env:     map[string]string{"RPINGMESH_OTEL_COLLECTOR_BEARER_TOKEN_FILE": writeSecret(t, testOTLPToken)},
			wantErr: "otel_collector_bearer_token_file requires otel_collector_tls_enabled",
		},
		{
			name: "unreadable token file",
			env: map[string]string{
				"RPINGMESH_OTEL_COLLECTOR_TLS_ENABLED":       "true",
				"RPINGMESH_OTEL_COLLECTOR_BEARER_TOKEN_FILE": filepath.Join(t.TempDir(), "missing"),
			},
			wantErr: "otel_collector_bearer_token_file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			_, agentErr := LoadAgentConfig("", nil)
			_, controllerErr := LoadControllerConfig("", nil)
			for name, err := range map[string]error{"agent": agentErr, "controller": controllerErr} {
				t.Run(name, func(t *testing.T) {
					checkErr(t, err, tt.wantErr)
					if err != nil && strings.Contains(err.Error(), testOTLPToken) {
						t.Errorf("error %q reveals the token", err)
					}
				})
			}
		})
	}
}
