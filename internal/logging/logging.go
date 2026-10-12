// Package logging builds the process-wide zerolog logger shared by the agent
// and controller binaries, so both honor the same log_format setting.
package logging

import (
	"fmt"
	"io"
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Log formats accepted by log_format.
const (
	// FormatConsole is zerolog's human-readable ConsoleWriter output (the
	// default, and the only format before log_format existed).
	FormatConsole = "console"
	// FormatJSON is zerolog's native output: one JSON object per line, with
	// the standard "level", "time" and "message" fields plus the event's own
	// fields. It is meant for log shippers and for tools such as
	// scripts/topology/rtt_tor_check.py that parse `journalctl -o cat`.
	FormatJSON = "json"
	// DefaultFormat is used when log_format is unset.
	DefaultFormat = FormatConsole
)

// ValidateFormat returns an error unless format is a supported log_format
// value. The empty string (a zero-value config) means DefaultFormat.
func ValidateFormat(format string) error {
	switch format {
	case "", FormatConsole, FormatJSON:
		return nil
	default:
		return fmt.Errorf("log_format must be %q or %q, got: %q", FormatConsole, FormatJSON, format)
	}
}

// New returns a timestamped logger writing to w in the given format.
func New(format string, w io.Writer) (zerolog.Logger, error) {
	if err := ValidateFormat(format); err != nil {
		return zerolog.Nop(), err
	}
	if format == FormatJSON {
		return zerolog.New(w).With().Timestamp().Logger(), nil
	}
	return zerolog.New(zerolog.ConsoleWriter{Out: w}).With().Timestamp().Logger(), nil
}

// SetupBootstrap installs the default (console) logger on stderr as the
// global logger. Binaries call it before loading their configuration, so
// anything logged before log_format is known keeps the historical console
// format; Setup then replaces it once the configuration is resolved.
func SetupBootstrap() {
	log.Logger, _ = New(DefaultFormat, os.Stderr)
}

// Setup installs the global logger for the configured format on stderr and
// sets the global level. An unparsable level falls back to info and is
// reported (in the new format) via the returned warning flag, so the caller
// can log it with its own field naming.
func Setup(format, level string) (invalidLevel bool, err error) {
	logger, err := New(format, os.Stderr)
	if err != nil {
		return false, err
	}
	log.Logger = logger

	lvl, perr := zerolog.ParseLevel(level)
	if perr != nil {
		lvl = zerolog.InfoLevel
		invalidLevel = true
	}
	zerolog.SetGlobalLevel(lvl)
	return invalidLevel, nil
}
