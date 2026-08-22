package main

// `kapkan nginx-exporter` — the reference feeder for the source-block channel.
//
// Same binary, smallest job: tail an nginx access log (in the documented JSON
// log_format), measure per-source request rates per window, and POST verdicts
// to the brain's /api/v1/dataplane/sources. internal/exporter owns the loop;
// this file is flags and wiring, mirroring `kapkan scrub`'s conventions —
// including the refusal to silently inherit the daemon's global flags.

import (
	"context"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kapkan-io/kapkan/internal/exporter"
	"github.com/kapkan-io/kapkan/internal/logging"
)

func runExporterCommand(args []string, f *cliFlags, _, errOut io.Writer) int {
	// The daemon's global flags are not read here, loudly (see scrub.go for
	// why silence would be worse).
	for _, name := range []string{"config", "log-format", "log-level"} {
		if f.wasSet(name) {
			lineWriter{errOut}.printf(
				"kapkan nginx-exporter: the global -%s flag is not read by this role; pass it AFTER the command: kapkan nginx-exporter -%s ...\n",
				name, name)
			return exitUsage
		}
	}

	fs := subcommandFlags("nginx-exporter", errOut)
	logPath := fs.String("log", "", "nginx access log in the documented JSON log_format (required)")
	api := fs.String("api", "http://127.0.0.1:8080", "the brain's API base URL")
	tokenEnv := fs.String("token-env", "KAPKAN_API_TOKEN", "environment variable holding an operator API token")
	victim := fs.String("victim", "", "fixed victim address; overrides the log's dst field")
	window := fs.Duration("window", 10*time.Second, "measurement window")
	rps := fs.Float64("rps", 50, "per-source requests/second over the window that arms a block")
	minReq := fs.Int("min-requests", 100, "requests a source must reach in a window before rate arithmetic applies")
	errRatio := fs.Float64("error-ratio", 0, "additionally require this 4xx/5xx share (0 disables the axis)")
	ttl := fs.Duration("ttl", 5*time.Minute, "block TTL; a still-hot source is refreshed before it lapses")
	observe := fs.Bool("observe", false, "log verdicts without posting them (trial mode against a live brain)")
	logFormat := fs.String("log-format", "json", "log format: json|text")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		lineWriter{errOut}.printf("kapkan nginx-exporter: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	cfg := exporter.Config{
		LogPath:     *logPath,
		APIBase:     *api,
		Token:       os.Getenv(*tokenEnv),
		Window:      *window,
		RPS:         *rps,
		MinRequests: *minReq,
		ErrorRatio:  *errRatio,
		TTL:         *ttl,
		Observe:     *observe,
	}
	if *victim != "" {
		a, err := netip.ParseAddr(*victim)
		if err != nil {
			lineWriter{errOut}.printf("kapkan nginx-exporter: -victim %q: %v\n", *victim, err)
			return exitUsage
		}
		cfg.Victim = a
	}
	if !cfg.Observe && cfg.Token == "" {
		lineWriter{errOut}.printf("kapkan nginx-exporter: the API token is empty — set %s, or run with -observe\n", *tokenEnv)
		return 1
	}

	log := logging.New(*logFormat, *logLevel)
	cfg.Log = log

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := exporter.Run(ctx, cfg); err != nil && !errors.Is(err, context.Canceled) {
		log.Error("nginx-exporter exited", "err", err)
		return 1
	}
	return exitOK
}
