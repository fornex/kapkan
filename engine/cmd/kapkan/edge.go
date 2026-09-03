package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/kapkan-io/kapkan/internal/config"
	"github.com/kapkan-io/kapkan/internal/edge/acme"
	"github.com/kapkan-io/kapkan/internal/edge/node"
	"github.com/kapkan-io/kapkan/internal/logging"
)

// runEdgeCommand parses `kapkan edge` flags and runs the edge role until a
// signal. As with scrub, the global flags are deliberately not inherited: a
// node accidentally reading kapkan.yaml must be a loud usage error.
func runEdgeCommand(args []string, f *cliFlags, _, errOut io.Writer) int {
	for _, name := range []string{"config", "log-format", "log-level"} {
		if f.wasSet(name) {
			lineWriter{errOut}.printf(
				"kapkan edge: the global -%s flag is not read by this role; pass it AFTER the command: kapkan edge -%s ...\n",
				name, name)
			return exitUsage
		}
	}

	fs := subcommandFlags("edge", errOut)
	cfgPath := fs.String("config", "/etc/kapkan/edge.yaml", "path to the edge-node configuration")
	logFormat := fs.String("log-format", "json", "log format: json|text")
	logLevel := fs.String("log-level", "info", "log level: debug|info|warn|error")
	checkOnly := fs.Bool("check", false, "validate the configuration and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		return exitUsage
	}
	if fs.NArg() > 0 {
		lineWriter{errOut}.printf("kapkan edge: unexpected argument %q\n", fs.Arg(0))
		return exitUsage
	}

	ec, err := config.LoadEdgeNode(*cfgPath)
	if err != nil {
		lineWriter{errOut}.printf("kapkan edge: %v\n", err)
		return 1
	}
	if *checkOnly {
		lineWriter{errOut}.printf("kapkan edge: %s is valid (node %s, brain %s, dry_run %v)\n", *cfgPath, ec.Controller.Name, ec.Controller.URL, ec.DryRunResolved())
		return exitOK
	}
	token := os.Getenv(ec.Controller.TokenEnv)
	if token == "" {
		lineWriter{errOut}.printf("kapkan edge: the agent token is empty — set %s\n", ec.Controller.TokenEnv)
		return 1
	}

	log := logging.New(*logFormat, *logLevel)
	if err := runEdge(ec, token, log); err != nil {
		log.Error("kapkan edge failed", "err", err)
		return 1
	}
	return exitOK
}

// runEdge builds and runs the node; split out so the CLI layer stays thin.
func runEdge(ec *config.EdgeNodeConfig, token string, log *slog.Logger) error {
	// EAB HMAC keys are secrets and live in the environment, like the token.
	resolved, err := ec.ACME.ResolveEAB()
	if err != nil {
		return err
	}
	var eab map[string]acme.EAB
	if len(resolved) > 0 {
		eab = make(map[string]acme.EAB, len(resolved))
		for dir, c := range resolved {
			eab[dir] = acme.EAB{KID: c.KID, HMACKey: c.HMACKey}
		}
	}
	n, err := node.New(node.Options{
		Brain:          strings.TrimRight(ec.Controller.URL, "/"),
		Token:          token,
		Name:           ec.Controller.Name,
		DryRun:         ec.DryRunResolved(),
		StateDir:       ec.StateDir,
		SocketsDir:     ec.SocketsDir,
		SocketGroup:    ec.SocketGroup,
		Terminator:     node.Terminator{Binary: ec.Terminator.Binary, MainConf: ec.Terminator.MainConf, Reload: ec.Terminator.Reload, PIDFile: ec.Terminator.PIDFile, Command: ec.Terminator.Command},
		ACME:           node.ACME{Directory: ec.ACME.Directory, Fallback: ec.ACME.Fallback, Contact: ec.ACME.Contact, EAB: eab, Disabled: ec.ACME.Disabled},
		ReportInterval: time.Duration(ec.Controller.ReportIntervalSeconds) * time.Second,
		StatusListen:   ec.StatusListen,
		OmitCatchAll:   ec.OmitCatchAll,
		DisableIPv6:    ec.DisableIPv6,
		Logger:         log,
	})
	if err != nil {
		return err
	}
	log.Info("starting kapkan edge", "controller", ec.Controller.URL, "node", ec.Controller.Name, "dry_run", ec.DryRunResolved())
	if ec.DryRunResolved() {
		log.Warn("DRY-RUN mode (the remote-role default): decisions are counted and marked, nothing is refused")
	} else {
		log.Warn("LIVE mode: this node WILL refuse requests the decision service denies")
	}
	if strings.HasPrefix(ec.Controller.URL, "http://") {
		log.Warn("controller.url is plaintext http: the agent token crosses the network unencrypted — use https outside a lab")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = n.Run(ctx)
	log.Info("kapkan edge stopped")
	if err != nil {
		return fmt.Errorf("edge: %w", err)
	}
	return nil
}
