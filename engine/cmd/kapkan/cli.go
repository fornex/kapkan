package main

// The command line's grammar, and the subcommand dispatch bolted onto it.
//
// KAPKAN'S FLAGS ARE FROZEN. Operators have `kapkan -config ... -log-format json`
// in a systemd unit, `kapkan -check-config` in CI, `kapkan -s reload` in muscle
// memory, and every one of those must keep working byte for byte. So the rule
// this file follows is: parsing happens exactly where and how it always did, and
// positional arguments are only LOOKED AT afterwards.
//
// WHY THAT IS SAFE, stated precisely because getting it wrong is silent:
// Go's flag package stops parsing at the first argument that is not a flag, and
// leaves the rest in Args(). Every invocation kapkan has ever accepted consists
// only of flags, so for all of them Args() is empty and this file's dispatch is
// unreachable — the code below the dispatch is the same code, reached the same
// way, with the same values. Nothing about `-flag`, `--flag`, `-flag=value`,
// `-flag value`, flag order, or the `--` terminator changes, because none of
// that is re-implemented here: flag.FlagSet still does all of it.
//
// The one deliberate change is that an unrecognised positional argument is now
// an error instead of being ignored. `kapkan wat` used to start the daemon; it
// now prints the command list and exits 2. That is not an invocation anyone has,
// and silently starting a daemon for a typo'd command would be the worst
// possible reading of it.
//
// WHERE THE PARSING LIVES. The flags used to be declared inline in main(), which
// made the grammar untestable without exec'ing a binary — and "write tests that
// pin the existing grammar first" is not optional for a change like this. They
// moved into parseFlags with the error-handling mode as a parameter, so
// TestFlagInventoryIsFrozen and TestExistingInvocationsAreUntouched can drive the
// real declarations with ContinueOnError while main keeps the ExitOnError
// behaviour flag.CommandLine always had.

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// Process exit codes. 0 and 1 are what they have always been; the rest exist
// because a state that is neither success nor failure needs its own code, which
// is the precedent -check-update set with its 10 for "an update is available".
//
// Documented in docs/en/cli.mdx. Do not renumber: monitoring branches on these.
const (
	// exitOK: what was asked for is true.
	exitOK = 0
	// exitError: the command could not answer — bad config, permission denied,
	// an I/O failure. Something went wrong with the TOOL, not with the subject.
	exitError = 1
	// exitUsage: the command line itself was wrong. Also what flag's own
	// ExitOnError uses, so a bad flag and a bad subcommand agree.
	exitUsage = 2
	// exitNotEnforcing: `dataplane status` found a data plane that is not
	// filtering, with nothing broken about it — never started, stopped, or
	// detached. A state, not a fault.
	exitNotEnforcing = 10
	// exitNeedsAttention: `dataplane status` found something a human has to fix
	// before the data plane can work: no bpffs, a torn pin set, a schema skew.
	// The printed reason always names the fix.
	exitNeedsAttention = 11
)

// cliFlags is the parsed global command line: one field per flag kapkan has
// always had, plus the FlagSet so callers can ask what was explicitly set and
// what was left over as positional arguments.
type cliFlags struct {
	configPath  string
	logFormat   string
	logLevel    string
	dumpSchema  bool
	checkConfig string
	showVersion bool
	checkUpdate bool
	pidFile     string
	signalCmd   string

	fs *flag.FlagSet
}

// parseFlags declares and parses kapkan's global flags.
//
// Every name, default and help string below is verbatim what main() declared
// before subcommands existed, and TestFlagInventoryIsFrozen asserts that
// inventory so a future edit cannot quietly retire one.
//
// name is what appears in the usage header (main passes os.Args[0], exactly as
// flag.CommandLine does). onError is flag.ExitOnError in production — the
// behaviour operators already get for a bad flag — and ContinueOnError in tests,
// which is the only reason it is a parameter.
func parseFlags(name string, argv []string, onError flag.ErrorHandling) (*cliFlags, error) {
	c := &cliFlags{}
	fs := flag.NewFlagSet(name, onError)
	c.fs = fs

	fs.StringVar(&c.configPath, "config", "configs/dev.yaml", "path to YAML config file")
	fs.StringVar(&c.logFormat, "log-format", "json", "log format: json or text")
	fs.StringVar(&c.logLevel, "log-level", "info", "log level: debug, info, warn, error")
	fs.BoolVar(&c.dumpSchema, "dump-schema", false, "print the config JSON schema to stdout and exit")
	fs.StringVar(&c.checkConfig, "check-config", "", "validate the config file at this path and exit (0 = valid, 1 = invalid)")
	fs.BoolVar(&c.showVersion, "version", false, "print the version and exit")
	fs.BoolVar(&c.checkUpdate, "check-update", false, "check for a newer release and exit (0 = up to date, 10 = update available, 1 = error)")
	fs.StringVar(&c.pidFile, "pid-file", "/run/kapkan/kapkan.pid", "path to the pid file (written on start; read by -s)")
	fs.StringVar(&c.signalCmd, "s", "", "send a signal to the running kapkan and exit: "+signalNames)

	fs.Usage = func() { usage(fs.Output(), fs) }
	if err := fs.Parse(argv); err != nil {
		return c, err
	}
	return c, nil
}

// args returns the positional arguments left after the flags.
func (c *cliFlags) args() []string { return c.fs.Args() }

// wasSet reports whether a flag was given explicitly, as opposed to holding its
// default. Needed because "the operator asked for -version" and "-version is
// false" are the same value but not the same statement.
func (c *cliFlags) wasSet(name string) bool {
	found := false
	c.fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// exitingFlags are the flags that make kapkan do one thing and exit. Combining
// one with a subcommand is a contradiction, and silently honouring whichever
// happens to be checked first is how a CLI teaches people not to trust it.
var exitingFlags = []string{"version", "check-update", "dump-schema", "check-config", "s"}

// usage prints the synopsis, the command list and the flag defaults.
func usage(w io.Writer, fs *flag.FlagSet) {
	out := lineWriter{w}
	out.print(`kapkan — DDoS detection and mitigation daemon

Usage:
  kapkan [flags]                     run the daemon
  kapkan [flags] <command> [args]    run a command and exit

Commands:
  dataplane status    report the XDP data plane's state; read-only, works with the daemon
                      stopped. Run "kapkan dataplane status -h" for its own flags.
  scrub               run the scrub-node role: pull the brain's rule table and enforce it
                      in the local XDP data plane. Run "kapkan scrub -h" for its flags.
  edge                run the edge-node role: pull the brain's zone document, drive the
                      local nginx/Angie, decide requests, issue certificates. Run
                      "kapkan edge -h" for its flags.
  nginx-exporter      tail an nginx JSON access log and post per-source verdicts to the
                      brain's source-block API. Run "kapkan nginx-exporter -h" for its flags.
  help                print this message

Flags:
`)
	// PrintDefaults writes to the FlagSet's own output, not to an argument, so
	// the writer has to be swapped in and put back — otherwise `kapkan help`
	// would print the synopsis to stdout and the flags to stderr.
	prev := fs.Output()
	fs.SetOutput(w)
	fs.PrintDefaults()
	fs.SetOutput(prev)
}

// runSubcommand dispatches a positional command. It is only ever reached when
// flag parsing left something behind, which no flags-only invocation does.
func runSubcommand(f *cliFlags, out, errOut io.Writer) int {
	args := f.args()
	name := args[0]

	// Nothing may be silently ignored. A flag that would have exited on its own
	// cannot also be a subcommand's flag, so the combination is refused rather
	// than resolved by whichever check happens to run first.
	for _, flagName := range exitingFlags {
		if f.wasSet(flagName) {
			lineWriter{errOut}.printf(
				"kapkan: -%s exits on its own and cannot be combined with the %q command; run one or the other\n",
				flagName, name)
			return exitUsage
		}
	}

	switch name {
	case "dataplane":
		return runDataplaneCommand(args[1:], f, out, errOut)
	case "scrub":
		return runScrubCommand(args[1:], f, out, errOut)
	case "edge":
		return runEdgeCommand(args[1:], f, out, errOut)
	case "nginx-exporter":
		return runExporterCommand(args[1:], f, out, errOut)
	case "help":
		usage(out, f.fs)
		return exitOK
	}
	lineWriter{errOut}.printf("kapkan: unknown command %q\n\n", name)
	usage(errOut, f.fs)
	return exitUsage
}

// subcommandFlags builds the FlagSet for a leaf subcommand: ContinueOnError so
// the caller owns the exit code, output routed to the caller's stderr so tests
// can capture it, and a usage line that names the full command path.
func subcommandFlags(path string, errOut io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(path, flag.ContinueOnError)
	fs.SetOutput(errOut)
	fs.Usage = func() {
		lineWriter{errOut}.printf("Usage: kapkan [global flags] %s [flags]\n\nFlags:\n", path)
		fs.PrintDefaults()
	}
	return fs
}

// rejectExtraArgs turns a stray positional argument into a usage error instead
// of ignoring it — the same rule as the top-level dispatch, for the same reason.
func rejectExtraArgs(fs *flag.FlagSet, path string, errOut io.Writer) bool {
	if fs.NArg() == 0 {
		return true
	}
	lineWriter{errOut}.printf("kapkan %s: unexpected argument %q\n", path, strings.Join(fs.Args(), " "))
	fs.Usage()
	return false
}

// lineWriter is how everything in this package writes human output.
//
// It exists to make one decision once, in a place with room to explain it: a
// failed write to stdout or stderr is not actionable. There is no fallback
// channel to report it on, and a status command that returned a different exit
// code because its output was piped into `head` would be worse than one that
// ignored the error. Handling it at each of the ~40 call sites would be noise
// that hides the ones that matter.
type lineWriter struct{ w io.Writer }

func (l lineWriter) printf(format string, a ...any) { _, _ = fmt.Fprintf(l.w, format, a...) }
func (l lineWriter) print(s string)                 { _, _ = fmt.Fprint(l.w, s) }
func (l lineWriter) line(s string)                  { _, _ = fmt.Fprintln(l.w, s) }
