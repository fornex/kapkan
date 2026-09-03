package main

// These tests exist in this order on purpose. Adding positional dispatch to a
// pure-flag CLI is the kind of change that breaks an operator's systemd unit
// silently, so the FIRST thing pinned down is the grammar that already worked;
// only after that do the subcommand tests get to say anything.

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

// parse is the test-side entry point: the real declarations from cli.go, with
// ContinueOnError so a rejection is a returned error instead of os.Exit.
func parse(t *testing.T, argv ...string) (*cliFlags, error) {
	t.Helper()
	f, err := parseFlags("kapkan", argv, flag.ContinueOnError)
	f.fs.SetOutput(&bytes.Buffer{}) // keep flag's own usage dump out of the test log
	return f, err
}

// TestFlagInventoryIsFrozen is the drift gate on the command line itself. Every
// entry below is a flag operators have in scripts, systemd units and CI; adding
// one here is fine, changing or removing one is a breaking change that must be
// a deliberate act rather than the side effect of an edit.
func TestFlagInventoryIsFrozen(t *testing.T) {
	want := map[string]string{
		"config":      "configs/dev.yaml",
		"log-format":  "json",
		"log-level":   "info",
		"dump-schema": "false",
		// The edge zones file's schema (edge track, E3.6).
		"dump-zones-schema": "false",
		"check-config":      "",
		"version":           "false",
		"check-update":      "false",
		"pid-file":          "/run/kapkan/kapkan.pid",
		"s":                 "",
	}
	f, err := parse(t)
	if err != nil {
		t.Fatalf("parseFlags with no args: %v", err)
	}
	got := map[string]string{}
	f.fs.VisitAll(func(fl *flag.Flag) { got[fl.Name] = fl.DefValue })

	for name, def := range want {
		g, ok := got[name]
		if !ok {
			t.Errorf("flag -%s has disappeared from the command line", name)
			continue
		}
		if g != def {
			t.Errorf("flag -%s default = %q, want %q", name, g, def)
		}
	}
	for name := range got {
		if _, ok := want[name]; !ok {
			t.Errorf("new flag -%s is not in the frozen inventory; add it to this test on purpose", name)
		}
	}
}

// TestExistingInvocationsAreUntouched drives every invocation kapkan has ever
// documented and asserts two things: the values parse as they always did, and
// nothing is left in Args(). The second is the load-bearing one — an empty
// Args() is precisely why the new dispatch cannot be reached by any of them.
func TestExistingInvocationsAreUntouched(t *testing.T) {
	for _, tc := range []struct {
		name  string
		argv  []string
		check func(t *testing.T, f *cliFlags)
	}{
		{"bare", nil, func(t *testing.T, f *cliFlags) {
			if f.configPath != "configs/dev.yaml" || f.logFormat != "json" {
				t.Errorf("defaults changed: %+v", f)
			}
		}},
		{"version", []string{"-version"}, func(t *testing.T, f *cliFlags) {
			if !f.showVersion {
				t.Error("-version did not set showVersion")
			}
		}},
		{"double-dash version", []string{"--version"}, func(t *testing.T, f *cliFlags) {
			if !f.showVersion {
				t.Error("--version did not set showVersion")
			}
		}},
		{"check-config space", []string{"-check-config", "/etc/kapkan/config.yaml"}, func(t *testing.T, f *cliFlags) {
			if f.checkConfig != "/etc/kapkan/config.yaml" {
				t.Errorf("checkConfig = %q", f.checkConfig)
			}
		}},
		{"check-config equals", []string{"--check-config=/etc/kapkan/config.yaml"}, func(t *testing.T, f *cliFlags) {
			if f.checkConfig != "/etc/kapkan/config.yaml" {
				t.Errorf("checkConfig = %q", f.checkConfig)
			}
		}},
		{"signal reload", []string{"-s", "reload"}, func(t *testing.T, f *cliFlags) {
			if f.signalCmd != "reload" {
				t.Errorf("signalCmd = %q", f.signalCmd)
			}
		}},
		{"signal with pid file", []string{"-s", "stop", "-pid-file", "/tmp/k.pid"}, func(t *testing.T, f *cliFlags) {
			if f.signalCmd != "stop" || f.pidFile != "/tmp/k.pid" {
				t.Errorf("signalCmd=%q pidFile=%q", f.signalCmd, f.pidFile)
			}
		}},
		{"systemd unit order", []string{"-config", "/etc/kapkan/config.yaml", "-log-format", "json", "-log-level", "info"},
			func(t *testing.T, f *cliFlags) {
				if f.configPath != "/etc/kapkan/config.yaml" || f.logLevel != "info" {
					t.Errorf("%+v", f)
				}
			}},
		{"flags in any order", []string{"-log-level", "debug", "-config", "/x.yaml", "--log-format=text"},
			func(t *testing.T, f *cliFlags) {
				if f.configPath != "/x.yaml" || f.logLevel != "debug" || f.logFormat != "text" {
					t.Errorf("%+v", f)
				}
			}},
		{"dump-schema", []string{"-dump-schema"}, func(t *testing.T, f *cliFlags) {
			if !f.dumpSchema {
				t.Error("-dump-schema did not set dumpSchema")
			}
		}},
		{"dump-zones-schema", []string{"-dump-zones-schema"}, func(t *testing.T, f *cliFlags) {
			if !f.dumpZonesSchema || f.dumpSchema {
				t.Error("-dump-zones-schema did not set dumpZonesSchema alone")
			}
		}},
		{"check-update with config", []string{"-check-update", "-config", "/etc/kapkan/config.yaml"},
			func(t *testing.T, f *cliFlags) {
				if !f.checkUpdate || f.configPath != "/etc/kapkan/config.yaml" {
					t.Errorf("%+v", f)
				}
			}},
		{"run-dev", []string{"-config", "configs/dev.yaml", "-log-format", "text"}, func(t *testing.T, f *cliFlags) {
			if f.logFormat != "text" {
				t.Errorf("logFormat = %q", f.logFormat)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, err := parse(t, tc.argv...)
			if err != nil {
				t.Fatalf("parse %v: %v", tc.argv, err)
			}
			if got := f.args(); len(got) != 0 {
				t.Fatalf("parse %v left positional args %q — this invocation would now hit the "+
					"subcommand dispatch, which is exactly the regression this test exists to catch",
					tc.argv, got)
			}
			tc.check(t, f)
		})
	}
}

// TestSubcommandIsReachedOnlyByAPositionalArgument states the dispatch rule from
// the other side: an argument that is not a flag, and nothing else, gets there.
func TestSubcommandIsReachedOnlyByAPositionalArgument(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want []string
	}{
		{[]string{"dataplane", "status"}, []string{"dataplane", "status"}},
		{[]string{"-config", "/x.yaml", "dataplane", "status"}, []string{"dataplane", "status"}},
		// Everything after the first positional argument belongs to the
		// subcommand, including things that look like global flags. That is
		// flag's own rule and it is what lets `dataplane status -json` work.
		{[]string{"dataplane", "status", "-json"}, []string{"dataplane", "status", "-json"}},
		{[]string{"--log-level=debug", "dataplane", "status", "-json"}, []string{"dataplane", "status", "-json"}},
	} {
		f, err := parse(t, tc.argv...)
		if err != nil {
			t.Fatalf("parse %v: %v", tc.argv, err)
		}
		got := f.args()
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("parse %v args = %q, want %q", tc.argv, got, tc.want)
		}
	}
}

// TestGlobalFlagsBeforeASubcommandStillApply: -config is how `dataplane status`
// finds the pin path, so it has to survive the dispatch.
func TestGlobalFlagsBeforeASubcommandStillApply(t *testing.T) {
	f, err := parse(t, "-config", "/etc/kapkan/config.yaml", "dataplane", "status")
	if err != nil {
		t.Fatal(err)
	}
	if f.configPath != "/etc/kapkan/config.yaml" {
		t.Errorf("configPath = %q", f.configPath)
	}
	if !f.wasSet("config") {
		t.Error("wasSet(config) = false for an explicitly given flag")
	}
	if f.wasSet("version") {
		t.Error("wasSet(version) = true for a flag that was never given")
	}
}

// TestExitingFlagWithSubcommandIsRefused: -version and a subcommand both want to
// be the whole invocation. Honouring whichever is checked first would make the
// CLI's behaviour depend on the order of if-statements in main().
func TestExitingFlagWithSubcommandIsRefused(t *testing.T) {
	for _, argv := range [][]string{
		{"-version", "dataplane", "status"},
		{"-dump-schema", "dataplane", "status"},
		{"-dump-zones-schema", "dataplane", "status"},
		{"-s", "reload", "dataplane", "status"},
		{"-check-config", "/x.yaml", "dataplane", "status"},
		{"-check-update", "dataplane", "status"},
	} {
		f, err := parse(t, argv...)
		if err != nil {
			t.Fatalf("parse %v: %v", argv, err)
		}
		var out, errOut bytes.Buffer
		if code := runSubcommand(f, &out, &errOut); code != exitUsage {
			t.Errorf("runSubcommand(%v) = %d, want %d", argv, code, exitUsage)
		}
		if !strings.Contains(errOut.String(), "cannot be combined") {
			t.Errorf("runSubcommand(%v) stderr = %q, want an explanation", argv, errOut.String())
		}
	}
}

func TestUnknownCommandIsAUsageError(t *testing.T) {
	f, err := parse(t, "wat")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitUsage {
		t.Errorf("unknown command exit = %d, want %d", code, exitUsage)
	}
	s := errOut.String()
	if !strings.Contains(s, `unknown command "wat"`) || !strings.Contains(s, "dataplane status") {
		t.Errorf("stderr = %q, want the offending word and the command list", s)
	}
}

func TestHelpCommand(t *testing.T) {
	f, err := parse(t, "help")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitOK {
		t.Errorf("help exit = %d, want 0", code)
	}
	for _, want := range []string{"kapkan [flags]", "dataplane status", "-check-config", "-s "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help output missing %q:\n%s", want, out.String())
		}
	}
}

func TestDataplaneWithoutASubcommandIsAUsageError(t *testing.T) {
	f, err := parse(t, "dataplane")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitUsage {
		t.Errorf("bare `dataplane` exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "status") {
		t.Errorf("stderr = %q, want it to name the available subcommand", errOut.String())
	}
}

func TestDataplaneUnknownSubcommand(t *testing.T) {
	f, err := parse(t, "dataplane", "reset")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), `unknown subcommand "reset"`) {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// TestStatusRejectsAStrayArgument: a typo must not be silently discarded, for
// the same reason an unknown command is not.
func TestStatusRejectsAStrayArgument(t *testing.T) {
	f, err := parse(t, "dataplane", "status", "eth0")
	if err != nil {
		t.Fatal(err)
	}
	var out, errOut bytes.Buffer
	if code := runSubcommand(f, &out, &errOut); code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(errOut.String(), "unexpected argument") {
		t.Errorf("stderr = %q", errOut.String())
	}
}
